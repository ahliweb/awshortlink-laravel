<?php

declare(strict_types=1);

namespace App\Domain\Links;

use App\Domain\AccessControl\Gate\AuthorizationPipeline;
use App\Domain\Audit\AuditWriter;
use App\Domain\DestinationPolicy\DestinationRiskClassifier;
use App\Domain\Resolver\SlugCanonicalizer;
use App\Support\UuidV7;
use PDO;
use RuntimeException;

/**
 * ALG-004: Short Link Lifecycle, Versioned Destinations, SoD Approval & Atomic Pointer Swap (#15, #27).
 */
final class LinkLifecycleService
{
    /**
     * Creates a draft short link (`status = 'draft'`), reserves slug, and stores initial destination `v1` (#15, API-008).
     *
     * @return array<string, mixed>
     */
    public static function createDraft(
        string $actorId,
        string $unitId,
        string $rawSlug,
        string $title,
        string $destinationUrl,
        string $visibility = 'public',
        ?string $campaignId = null,
        ?string $expiresAt = null,
        string $reason = 'Initial draft creation',
        ?PDO $pdo = null,
    ): array {
        $slugCanon = SlugCanonicalizer::canonicalize($rawSlug);
        if (!$slugCanon['valid'] || $slugCanon['slug_normalized'] === null) {
            throw new RuntimeException('INVALID_SLUG:' . ($slugCanon['error_code'] ?? 'MALFORMED'));
        }

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'links.create_draft',
            resourceType: 'links',
            resourceAttributes: ['unit_id' => $unitId],
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        $slug = $slugCanon['slug_normalized'];
        $displaySlug = $slugCanon['display_slug'];

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $unitId,
            $slug,
            $displaySlug,
            $title,
            $destinationUrl,
            $visibility,
            $campaignId,
            $expiresAt,
            $reason
        ): array {
            // Check permanent reserved_slugs table first (TV-021, THR-007)
            $resCheck = $db->prepare(
                "SELECT reason, initial_link_id FROM shortlink.reserved_slugs WHERE namespace = 'buka' AND slug_normalized = :slug"
            );
            $resCheck->execute([':slug' => $slug]);
            /** @var array<string, mixed>|false $existingReservation */
            $existingReservation = $resCheck->fetch();
            if (is_array($existingReservation)) {
                throw new RuntimeException('SLUG_PERMANENTLY_RESERVED: Slug "' . $slug . '" is reserved (' . $existingReservation['reason'] . ').');
            }

            // Evaluate destination URL policy (ALG-002)
            $verdict = DestinationRiskClassifier::evaluate($destinationUrl, $db);
            if (!$verdict['allowed'] || $verdict['url_canonical'] === null || $verdict['host_canonical'] === null) {
                throw new RuntimeException('DESTINATION_FORBIDDEN:' . ($verdict['error_code'] ?? 'POLICY_REJECTED'));
            }

            $linkId = UuidV7::generate();
            $destId = UuidV7::generate();

            $insLink = $db->prepare(
                "INSERT INTO shortlink.links (
                    id, namespace, unit_id, creator_id, campaign_id, slug_normalized, display_slug,
                    title, status, visibility, expires_at, version
                ) VALUES (
                    :id, 'buka', :unit_id, :creator_id, :campaign_id, :slug, :display_slug,
                    :title, 'draft', :visibility, :expires_at, 1
                )
                RETURNING id, namespace, unit_id, creator_id, slug_normalized, display_slug, title, status, visibility, version"
            );
            $insLink->execute([
                ':id' => $linkId,
                ':unit_id' => $unitId,
                ':creator_id' => $actorId,
                ':campaign_id' => $campaignId,
                ':slug' => $slug,
                ':display_slug' => $displaySlug,
                ':title' => trim($title),
                ':visibility' => $visibility,
                ':expires_at' => $expiresAt,
            ]);
            /** @var array<string, mixed> $link */
            $link = $insLink->fetch();

            // Reserve slug in draft state
            $insRes = $db->prepare(
                "INSERT INTO shortlink.reserved_slugs (namespace, slug_normalized, initial_link_id, reason)
                 VALUES ('buka', :slug, :link_id, 'draft')"
            );
            $insRes->execute([':slug' => $slug, ':link_id' => $linkId]);

            // Insert destination version 1
            $insDest = $db->prepare(
                "INSERT INTO shortlink.link_destinations (
                    id, link_id, unit_id, url_canonical, host_canonical, risk_class,
                    policy_verdict, status, version, proposed_by
                ) VALUES (
                    :id, :link_id, :unit_id, :url, :host, :risk,
                    :verdict::jsonb, 'proposed', 1, :proposed_by
                )"
            );
            $insDest->execute([
                ':id' => $destId,
                ':link_id' => $linkId,
                ':unit_id' => $unitId,
                ':url' => $verdict['url_canonical'],
                ':host' => $verdict['host_canonical'],
                ':risk' => $verdict['risk_class'],
                ':verdict' => json_encode($verdict, JSON_THROW_ON_ERROR),
                ':proposed_by' => $actorId,
            ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'links.draft_created',
                subjectType: 'link',
                subjectId: $linkId,
                subjectVersion: 1,
                unitId: $unitId,
                linkId: $linkId,
                beforeState: null,
                afterState: array_merge($link, [
                    'destination_id' => $destId,
                    'url_canonical' => $verdict['url_canonical'],
                    'risk_class' => $verdict['risk_class'],
                ]),
                reason: $reason
            );

            return array_merge($link, [
                'destination_id' => $destId,
                'destination_version' => 1,
                'url_canonical' => $verdict['url_canonical'],
                'risk_class' => $verdict['risk_class'],
                'requires_approval' => $verdict['requires_approval'],
            ]);
        }, $pdo);
    }

    /**
     * Updates link metadata (`title`, `visibility`, `expires_at`, `campaign_id`) with optimistic `If-Match` version check (#15, TV-023).
     *
     * @param array<string, mixed> $changes
     * @return array<string, mixed>
     */
    public static function updateLinkMetadata(
        string $actorId,
        string $linkId,
        int $expectedVersion,
        array $changes,
        string $reason,
        ?PDO $pdo = null,
    ): array {
        // Load current link state first
        $link = self::fetchLinkForAuth($actorId, $linkId, $pdo);

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'links.update_draft',
            resourceType: 'links',
            resourceAttributes: $link,
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $linkId,
            $expectedVersion,
            $changes,
            $reason
        ): array {
            $stmt = $db->prepare(
                'SELECT id, unit_id, title, status, visibility, campaign_id, expires_at::text, version
                 FROM shortlink.links
                 WHERE id = :id
                 FOR UPDATE'
            );
            $stmt->execute([':id' => $linkId]);
            /** @var array<string, mixed>|false $current */
            $current = $stmt->fetch();
            if (!is_array($current)) {
                throw new RuntimeException('LINK_NOT_FOUND');
            }
            if ($current['status'] === 'archived') {
                throw new RuntimeException('ARCHIVED_LINK_IMMUTABLE');
            }
            if ((int) $current['version'] !== $expectedVersion) {
                throw new RuntimeException('STALE_VERSION: Expected version ' . $expectedVersion . ', actual ' . $current['version']);
            }

            $newTitle = isset($changes['title']) ? trim((string) $changes['title']) : (string) $current['title'];
            $newVisibility = isset($changes['visibility']) ? (string) $changes['visibility'] : (string) $current['visibility'];
            $newCampaign = array_key_exists('campaign_id', $changes) ? $changes['campaign_id'] : $current['campaign_id'];
            $newExpires = array_key_exists('expires_at', $changes) ? $changes['expires_at'] : $current['expires_at'];
            $newVersion = ((int) $current['version']) + 1;

            $upd = $db->prepare(
                'UPDATE shortlink.links
                 SET title = :title,
                     visibility = :vis,
                     campaign_id = :camp,
                     expires_at = :exp,
                     version = :ver,
                     updated_at = now()
                 WHERE id = :id
                 RETURNING id, unit_id, slug_normalized, title, status, visibility, campaign_id, expires_at::text, version'
            );
            $upd->execute([
                ':title' => $newTitle,
                ':vis' => $newVisibility,
                ':camp' => $newCampaign,
                ':exp' => $newExpires,
                ':ver' => $newVersion,
                ':id' => $linkId,
            ]);
            /** @var array<string, mixed> $updated */
            $updated = $upd->fetch();

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'links.metadata_updated',
                subjectType: 'link',
                subjectId: $linkId,
                subjectVersion: $newVersion,
                unitId: (string) $current['unit_id'],
                linkId: $linkId,
                beforeState: $current,
                afterState: $updated,
                reason: $reason
            );

            return $updated;
        }, $pdo);
    }

    /**
     * Proposes a new destination revision (`version = n + 1`) without altering `current_destination_id` (#15, TV-022).
     *
     * @return array<string, mixed>
     */
    public static function proposeDestination(
        string $actorId,
        string $linkId,
        string $destinationUrl,
        string $reason,
        ?PDO $pdo = null,
    ): array {
        $link = self::fetchLinkForAuth($actorId, $linkId, $pdo);

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'destinations.propose',
            resourceType: 'links',
            resourceAttributes: $link,
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $linkId,
            $link,
            $destinationUrl,
            $reason
        ): array {
            $verdict = DestinationRiskClassifier::evaluate($destinationUrl, $db);
            if (!$verdict['allowed'] || $verdict['url_canonical'] === null || $verdict['host_canonical'] === null) {
                throw new RuntimeException('DESTINATION_FORBIDDEN:' . ($verdict['error_code'] ?? 'POLICY_REJECTED'));
            }

            $verStmt = $db->prepare('SELECT coalesce(max(version), 0) + 1 FROM shortlink.link_destinations WHERE link_id = :lid');
            $verStmt->execute([':lid' => $linkId]);
            $nextVer = (int) $verStmt->fetchColumn();

            $destId = UuidV7::generate();
            $unitId = (string) $link['unit_id'];

            $ins = $db->prepare(
                "INSERT INTO shortlink.link_destinations (
                    id, link_id, unit_id, url_canonical, host_canonical, risk_class,
                    policy_verdict, status, version, proposed_by
                ) VALUES (
                    :id, :link_id, :unit_id, :url, :host, :risk,
                    :verdict::jsonb, 'pending_review', :ver, :proposed_by
                )
                RETURNING id, link_id, unit_id, url_canonical, host_canonical, risk_class, status, version, proposed_by"
            );
            $ins->execute([
                ':id' => $destId,
                ':link_id' => $linkId,
                ':unit_id' => $unitId,
                ':url' => $verdict['url_canonical'],
                ':host' => $verdict['host_canonical'],
                ':risk' => $verdict['risk_class'],
                ':verdict' => json_encode($verdict, JSON_THROW_ON_ERROR),
                ':ver' => $nextVer,
                ':proposed_by' => $actorId,
            ]);
            /** @var array<string, mixed> $dest */
            $dest = $ins->fetch();

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'destinations.proposed',
                subjectType: 'link_destination',
                subjectId: $destId,
                subjectVersion: $nextVer,
                unitId: $unitId,
                linkId: $linkId,
                beforeState: null,
                afterState: $dest,
                reason: $reason
            );

            return $dest;
        }, $pdo);
    }

    /**
     * Submits a draft link or proposed destination revision for review (#15, #27, API-014).
     *
     * @return array<string, mixed>
     */
    public static function submitForApproval(
        string $actorId,
        string $linkId,
        ?string $destinationId = null,
        string $reason = 'Submitted for approval',
        ?PDO $pdo = null,
    ): array {
        $link = self::fetchLinkForAuth($actorId, $linkId, $pdo);

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'links.submit',
            resourceType: 'links',
            resourceAttributes: $link,
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $linkId,
            $destinationId,
            $reason
        ): array {
            $linkStmt = $db->prepare('SELECT id, unit_id, status, version FROM shortlink.links WHERE id = :id FOR UPDATE');
            $linkStmt->execute([':id' => $linkId]);
            /** @var array<string, mixed>|false $l */
            $l = $linkStmt->fetch();
            if (!is_array($l)) {
                throw new RuntimeException('LINK_NOT_FOUND');
            }

            if ($destinationId !== null) {
                $destStmt = $db->prepare('SELECT id, risk_class, status, version FROM shortlink.link_destinations WHERE id = :id AND link_id = :lid FOR UPDATE');
                $destStmt->execute([':id' => $destinationId, ':lid' => $linkId]);
            } else {
                $destStmt = $db->prepare('SELECT id, risk_class, status, version FROM shortlink.link_destinations WHERE link_id = :lid ORDER BY version DESC LIMIT 1 FOR UPDATE');
                $destStmt->execute([':lid' => $linkId]);
            }
            /** @var array<string, mixed>|false $dest */
            $dest = $destStmt->fetch();
            if (!is_array($dest)) {
                throw new RuntimeException('DESTINATION_NOT_FOUND');
            }

            $destId = (string) $dest['id'];
            $unitId = (string) $l['unit_id'];

            $db->prepare("UPDATE shortlink.link_destinations SET status = 'pending_review' WHERE id = :id")
                ->execute([':id' => $destId]);

            $newStatus = $l['status'] === 'draft' ? 'submitted' : (string) $l['status'];
            $newVersion = ((int) $l['version']) + 1;
            $db->prepare('UPDATE shortlink.links SET status = :s, version = :v, updated_at = now() WHERE id = :id')
                ->execute([':s' => $newStatus, ':v' => $newVersion, ':id' => $linkId]);

            $db->prepare(
                "INSERT INTO shortlink.link_approvals (id, link_id, unit_id, destination_id, actor_id, action, risk, reason)
                 VALUES (:id, :lid, :uid, :did, :actor, 'submit', :risk, :reason)"
            )->execute([
                ':id' => UuidV7::generate(),
                ':lid' => $linkId,
                ':uid' => $unitId,
                ':did' => $destId,
                ':actor' => $actorId,
                ':risk' => (string) $dest['risk_class'],
                ':reason' => $reason,
            ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'links.submitted',
                subjectType: 'link',
                subjectId: $linkId,
                subjectVersion: $newVersion,
                unitId: $unitId,
                linkId: $linkId,
                beforeState: ['status' => $l['status']],
                afterState: ['status' => $newStatus, 'destination_id' => $destId],
                reason: $reason
            );

            return [
                'link_id' => $linkId,
                'destination_id' => $destId,
                'status' => $newStatus,
                'destination_status' => 'pending_review',
                'risk_class' => (string) $dest['risk_class'],
                'version' => $newVersion,
            ];
        }, $pdo);
    }

    /**
     * Approves a pending destination and atomically swaps `links.current_destination_id` + permanent `reserved_slugs` tombstone (`ALG-004`, `POL-LINK-SOD`, #15, #27).
     *
     * @return array<string, mixed>
     */
    public static function approveAndPublish(
        string $approverId,
        string $linkId,
        ?string $destinationId = null,
        string $reason = 'Approved for public resolution',
        ?string $publishedAt = null,
        ?PDO $pdo = null,
    ): array {
        $linkAndDest = self::fetchLinkAndTargetDestForAuth($approverId, $linkId, $destinationId, $pdo);

        // Evaluate AuthorizationPipeline including POL-LINK-SOD (proposed_by vs actor.id on medium/high risk)
        $auth = AuthorizationPipeline::evaluate(
            actorId: $approverId,
            permissionKey: 'links.approve',
            resourceType: 'links',
            resourceAttributes: $linkAndDest,
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $approverId,
            $linkId,
            $destinationId,
            $reason,
            $publishedAt,
            $auth
        ): array {
            $linkStmt = $db->prepare(
                'SELECT id, namespace, unit_id, slug_normalized, current_destination_id, status, published_at::text, expires_at::text, version
                 FROM shortlink.links
                 WHERE id = :id
                 FOR UPDATE'
            );
            $linkStmt->execute([':id' => $linkId]);
            /** @var array<string, mixed>|false $l */
            $l = $linkStmt->fetch();
            if (!is_array($l)) {
                throw new RuntimeException('LINK_NOT_FOUND');
            }

            if ($destinationId !== null) {
                $destStmt = $db->prepare(
                    'SELECT id, url_canonical, risk_class, status, version, proposed_by
                     FROM shortlink.link_destinations
                     WHERE id = :id AND link_id = :lid
                     FOR UPDATE'
                );
                $destStmt->execute([':id' => $destinationId, ':lid' => $linkId]);
            } else {
                $destStmt = $db->prepare(
                    'SELECT id, url_canonical, risk_class, status, version, proposed_by
                     FROM shortlink.link_destinations
                     WHERE link_id = :lid
                     ORDER BY version DESC LIMIT 1
                     FOR UPDATE'
                );
                $destStmt->execute([':lid' => $linkId]);
            }
            /** @var array<string, mixed>|false $dest */
            $dest = $destStmt->fetch();
            if (!is_array($dest)) {
                throw new RuntimeException('DESTINATION_NOT_FOUND');
            }

            $risk = (string) $dest['risk_class'];
            // Defense-in-depth SoD check at application + DB CHECK boundary
            if (in_array($risk, ['medium', 'high'], true) && $dest['proposed_by'] === $approverId) {
                throw new RuntimeException('SOD_SELF_APPROVAL_FORBIDDEN: Medium/high risk destination cannot be approved by proposer.');
            }
            if ($risk === 'high' && empty($l['expires_at'])) {
                throw new RuntimeException('HIGH_RISK_REQUIRES_EXPIRY: High-risk external destinations require an expiration timestamp.');
            }

            $destId = (string) $dest['id'];
            $unitId = (string) $l['unit_id'];
            $newVersion = ((int) $l['version']) + 1;
            $pubAt = $publishedAt ?? ($l['published_at'] ?? gmdate('Y-m-d\TH:i:s\Z'));

            // Supersede previous current destination if any
            if (!empty($l['current_destination_id']) && $l['current_destination_id'] !== $destId) {
                $db->prepare("UPDATE shortlink.link_destinations SET status = 'superseded' WHERE id = :old_id")
                    ->execute([':old_id' => $l['current_destination_id']]);
            }

            // Mark approved destination as current
            $db->prepare(
                "UPDATE shortlink.link_destinations
                 SET status = 'current', approved_by = :approver, approved_at = now()
                 WHERE id = :id"
            )->execute([':approver' => $approverId, ':id' => $destId]);

            // Atomically swap current_destination_id and activate link
            $db->prepare(
                "UPDATE shortlink.links
                 SET current_destination_id = :dest_id,
                     status = 'active',
                     published_at = :pub_at,
                     version = :ver,
                     updated_at = now()
                 WHERE id = :id"
            )->execute([
                ':dest_id' => $destId,
                ':pub_at' => $pubAt,
                ':ver' => $newVersion,
                ':id' => $linkId,
            ]);

            // Upgrade reserved_slugs reason from 'draft' to permanent 'published' tombstone (ALG-004)
            $db->prepare(
                "UPDATE shortlink.reserved_slugs
                 SET reason = 'published'
                 WHERE namespace = :ns AND slug_normalized = :slug AND reason = 'draft'"
            )->execute([
                ':ns' => (string) $l['namespace'],
                ':slug' => (string) $l['slug_normalized'],
            ]);

            $db->prepare(
                "INSERT INTO shortlink.link_approvals (id, link_id, unit_id, destination_id, actor_id, action, risk, reason)
                 VALUES (:id, :lid, :uid, :did, :actor, 'approve', :risk, :reason)"
            )->execute([
                ':id' => UuidV7::generate(),
                ':lid' => $linkId,
                ':uid' => $unitId,
                ':did' => $destId,
                ':actor' => $approverId,
                ':risk' => $risk,
                ':reason' => $reason,
            ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $approverId,
                action: 'links.approved_and_published',
                subjectType: 'link',
                subjectId: $linkId,
                subjectVersion: $newVersion,
                unitId: $unitId,
                linkId: $linkId,
                policyVersionId: $auth['policy_version_id'],
                beforeState: ['status' => $l['status'], 'current_destination_id' => $l['current_destination_id']],
                afterState: [
                    'status' => 'active',
                    'current_destination_id' => $destId,
                    'url_canonical' => $dest['url_canonical'],
                    'published_at' => $pubAt,
                ],
                reason: $reason
            );

            return [
                'link_id' => $linkId,
                'slug' => (string) $l['slug_normalized'],
                'status' => 'active',
                'current_destination_id' => $destId,
                'destination_version' => (int) $dest['version'],
                'url_canonical' => (string) $dest['url_canonical'],
                'published_at' => $pubAt,
                'version' => $newVersion,
            ];
        }, $pdo);
    }

    /**
     * Immediately suspends an active link (`POL-EMERGENCY` allows single-actor emergency suspend with MFA) (#15, #27, DES-003).
     *
     * @return array<string, mixed>
     */
    public static function suspendLink(
        string $actorId,
        string $linkId,
        string $reason,
        bool $isEmergency = true,
        ?PDO $pdo = null,
    ): array {
        $link = self::fetchLinkForAuth($actorId, $linkId, $pdo);

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'links.suspend',
            resourceType: 'links',
            resourceAttributes: $link,
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $linkId,
            $reason,
            $isEmergency,
            $auth
        ): array {
            $stmt = $db->prepare(
                'SELECT id, unit_id, current_destination_id, status, version
                 FROM shortlink.links
                 WHERE id = :id
                 FOR UPDATE'
            );
            $stmt->execute([':id' => $linkId]);
            /** @var array<string, mixed>|false $l */
            $l = $stmt->fetch();
            if (!is_array($l)) {
                throw new RuntimeException('LINK_NOT_FOUND');
            }
            if ($l['status'] === 'archived') {
                throw new RuntimeException('ARCHIVED_LINK_IMMUTABLE');
            }

            $newVersion = ((int) $l['version']) + 1;
            $unitId = (string) $l['unit_id'];

            $db->prepare("UPDATE shortlink.links SET status = 'suspended', version = :v, updated_at = now() WHERE id = :id")
                ->execute([':v' => $newVersion, ':id' => $linkId]);

            if (!empty($l['current_destination_id'])) {
                $db->prepare(
                    'INSERT INTO shortlink.link_approvals (id, link_id, unit_id, destination_id, actor_id, action, risk, reason)
                     VALUES (:id, :lid, :uid, :did, :actor, :action, \'high\', :reason)'
                )->execute([
                    ':id' => UuidV7::generate(),
                    ':lid' => $linkId,
                    ':uid' => $unitId,
                    ':did' => $l['current_destination_id'],
                    ':actor' => $actorId,
                    ':action' => $isEmergency ? 'emergency_suspend' : 'suspend',
                    ':reason' => $reason,
                ]);
            }

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: $isEmergency ? 'links.emergency_suspended' : 'links.suspended',
                subjectType: 'link',
                subjectId: $linkId,
                subjectVersion: $newVersion,
                unitId: $unitId,
                linkId: $linkId,
                policyVersionId: $auth['policy_version_id'],
                beforeState: ['status' => $l['status']],
                afterState: ['status' => 'suspended'],
                reason: $reason
            );

            return [
                'link_id' => $linkId,
                'status' => 'suspended',
                'version' => $newVersion,
            ];
        }, $pdo);
    }

    /**
     * Reinstates a suspended link back to `active` (#15, #27, API-017).
     *
     * @return array<string, mixed>
     */
    public static function reinstateLink(
        string $actorId,
        string $linkId,
        string $reason,
        ?PDO $pdo = null,
    ): array {
        $link = self::fetchLinkForAuth($actorId, $linkId, $pdo);

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'links.reinstate',
            resourceType: 'links',
            resourceAttributes: $link,
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use ($actorId, $linkId, $reason): array {
            $stmt = $db->prepare(
                'SELECT id, unit_id, current_destination_id, status, version
                 FROM shortlink.links
                 WHERE id = :id
                 FOR UPDATE'
            );
            $stmt->execute([':id' => $linkId]);
            /** @var array<string, mixed>|false $l */
            $l = $stmt->fetch();
            if (!is_array($l) || $l['status'] !== 'suspended') {
                throw new RuntimeException('LINK_NOT_SUSPENDED');
            }

            $newVersion = ((int) $l['version']) + 1;
            $unitId = (string) $l['unit_id'];

            $db->prepare("UPDATE shortlink.links SET status = 'active', version = :v, updated_at = now() WHERE id = :id")
                ->execute([':v' => $newVersion, ':id' => $linkId]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'links.reinstated',
                subjectType: 'link',
                subjectId: $linkId,
                subjectVersion: $newVersion,
                unitId: $unitId,
                linkId: $linkId,
                beforeState: ['status' => 'suspended'],
                afterState: ['status' => 'active'],
                reason: $reason
            );

            return [
                'link_id' => $linkId,
                'status' => 'active',
                'version' => $newVersion,
            ];
        }, $pdo);
    }

    /**
     * Archives a short link with permanent slug tombstone (`retired_public_message` controls 410 vs 404 per DES-003) (#15, TV-019, TV-021).
     *
     * @return array<string, mixed>
     */
    public static function archiveLink(
        string $actorId,
        string $linkId,
        string $reason,
        bool $retiredPublicMessage = true,
        ?PDO $pdo = null,
    ): array {
        $link = self::fetchLinkForAuth($actorId, $linkId, $pdo);

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'links.archive',
            resourceType: 'links',
            resourceAttributes: $link,
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $linkId,
            $reason,
            $retiredPublicMessage
        ): array {
            $stmt = $db->prepare(
                'SELECT id, namespace, unit_id, slug_normalized, status, published_at, version
                 FROM shortlink.links
                 WHERE id = :id
                 FOR UPDATE'
            );
            $stmt->execute([':id' => $linkId]);
            /** @var array<string, mixed>|false $l */
            $l = $stmt->fetch();
            if (!is_array($l)) {
                throw new RuntimeException('LINK_NOT_FOUND');
            }
            if ($l['status'] === 'archived') {
                throw new RuntimeException('LINK_ALREADY_ARCHIVED');
            }

            $newVersion = ((int) $l['version']) + 1;
            $unitId = (string) $l['unit_id'];

            $db->prepare(
                "UPDATE shortlink.links
                 SET status = 'archived',
                     published_at = COALESCE(published_at, now()),
                     retired_public_message = :retired_msg,
                     version = :ver,
                     updated_at = now()
                 WHERE id = :id"
            )->execute([
                ':retired_msg' => $retiredPublicMessage ? 'true' : 'false',
                ':ver' => $newVersion,
                ':id' => $linkId,
            ]);

            // Permanent slug tombstone in reserved_slugs (TV-021)
            $db->prepare(
                "UPDATE shortlink.reserved_slugs
                 SET reason = 'published'
                 WHERE namespace = :ns AND slug_normalized = :slug"
            )->execute([
                ':ns' => (string) $l['namespace'],
                ':slug' => (string) $l['slug_normalized'],
            ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'links.archived',
                subjectType: 'link',
                subjectId: $linkId,
                subjectVersion: $newVersion,
                unitId: $unitId,
                linkId: $linkId,
                beforeState: ['status' => $l['status']],
                afterState: ['status' => 'archived', 'retired_public_message' => $retiredPublicMessage],
                reason: $reason
            );

            return [
                'link_id' => $linkId,
                'slug' => (string) $l['slug_normalized'],
                'status' => 'archived',
                'retired_public_message' => $retiredPublicMessage,
                'version' => $newVersion,
            ];
        }, $pdo);
    }

    /**
     * Rolls back `current_destination_id` to a previously approved destination version (#15, API-013).
     *
     * @return array<string, mixed>
     */
    public static function rollbackDestination(
        string $actorId,
        string $linkId,
        int $targetDestinationVersion,
        string $reason,
        ?PDO $pdo = null,
    ): array {
        $link = self::fetchLinkForAuth($actorId, $linkId, $pdo);

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'destinations.rollback',
            resourceType: 'links',
            resourceAttributes: $link,
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $linkId,
            $targetDestinationVersion,
            $reason
        ): array {
            $linkStmt = $db->prepare(
                'SELECT id, unit_id, current_destination_id, status, version
                 FROM shortlink.links
                 WHERE id = :id
                 FOR UPDATE'
            );
            $linkStmt->execute([':id' => $linkId]);
            /** @var array<string, mixed>|false $l */
            $l = $linkStmt->fetch();
            if (!is_array($l)) {
                throw new RuntimeException('LINK_NOT_FOUND');
            }

            $destStmt = $db->prepare(
                'SELECT id, url_canonical, version, approved_by
                 FROM shortlink.link_destinations
                 WHERE link_id = :lid AND version = :ver
                 FOR UPDATE'
            );
            $destStmt->execute([':lid' => $linkId, ':ver' => $targetDestinationVersion]);
            /** @var array<string, mixed>|false $targetDest */
            $targetDest = $destStmt->fetch();
            if (!is_array($targetDest) || empty($targetDest['approved_by'])) {
                throw new RuntimeException('DESTINATION_ROLLBACK_TARGET_NOT_APPROVED');
            }

            $targetDestId = (string) $targetDest['id'];
            $newVersion = ((int) $l['version']) + 1;

            if (!empty($l['current_destination_id']) && $l['current_destination_id'] !== $targetDestId) {
                $db->prepare("UPDATE shortlink.link_destinations SET status = 'superseded' WHERE id = :id")
                    ->execute([':id' => $l['current_destination_id']]);
            }

            $db->prepare("UPDATE shortlink.link_destinations SET status = 'current' WHERE id = :id")
                ->execute([':id' => $targetDestId]);

            $db->prepare('UPDATE shortlink.links SET current_destination_id = :did, version = :v, updated_at = now() WHERE id = :id')
                ->execute([':did' => $targetDestId, ':v' => $newVersion, ':id' => $linkId]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'destinations.rolled_back',
                subjectType: 'link',
                subjectId: $linkId,
                subjectVersion: $newVersion,
                unitId: (string) $l['unit_id'],
                linkId: $linkId,
                beforeState: ['current_destination_id' => $l['current_destination_id']],
                afterState: ['current_destination_id' => $targetDestId, 'destination_version' => $targetDestinationVersion],
                reason: $reason
            );

            return [
                'link_id' => $linkId,
                'current_destination_id' => $targetDestId,
                'destination_version' => $targetDestinationVersion,
                'url_canonical' => (string) $targetDest['url_canonical'],
                'version' => $newVersion,
            ];
        }, $pdo);
    }

    /**
     * @return array<string, mixed>
     */
    private static function fetchLinkForAuth(string $actorId, string $linkId, ?PDO $pdo = null): array
    {
        $ctx = \App\Domain\AccessControl\Database\RlsContext::systemGlobal($actorId);
        return $ctx->run(static function (PDO $db) use ($linkId): array {
            $stmt = $db->prepare(
                'SELECT id, unit_id, creator_id, status, visibility, version
                 FROM shortlink.links
                 WHERE id = :id'
            );
            $stmt->execute([':id' => $linkId]);
            /** @var array<string, mixed>|false $row */
            $row = $stmt->fetch();
            if (!is_array($row)) {
                throw new RuntimeException('LINK_NOT_FOUND');
            }
            return $row;
        }, $pdo);
    }

    /**
     * @return array<string, mixed>
     */
    private static function fetchLinkAndTargetDestForAuth(
        string $actorId,
        string $linkId,
        ?string $destinationId,
        ?PDO $pdo = null
    ): array {
        $ctx = \App\Domain\AccessControl\Database\RlsContext::systemGlobal($actorId);
        return $ctx->run(static function (PDO $db) use ($linkId, $destinationId): array {
            $stmt = $db->prepare(
                'SELECT id, unit_id, creator_id, status, visibility, version
                 FROM shortlink.links
                 WHERE id = :id'
            );
            $stmt->execute([':id' => $linkId]);
            /** @var array<string, mixed>|false $link */
            $link = $stmt->fetch();
            if (!is_array($link)) {
                throw new RuntimeException('LINK_NOT_FOUND');
            }

            if ($destinationId !== null) {
                $dStmt = $db->prepare('SELECT id, risk_class, proposed_by FROM shortlink.link_destinations WHERE id = :id AND link_id = :lid');
                $dStmt->execute([':id' => $destinationId, ':lid' => $linkId]);
            } else {
                $dStmt = $db->prepare('SELECT id, risk_class, proposed_by FROM shortlink.link_destinations WHERE link_id = :lid ORDER BY version DESC LIMIT 1');
                $dStmt->execute([':lid' => $linkId]);
            }
            /** @var array<string, mixed>|false $dest */
            $dest = $dStmt->fetch();
            if (is_array($dest)) {
                $link['risk_class'] = (string) $dest['risk_class'];
                $link['proposed_by'] = (string) $dest['proposed_by'];
            }
            return $link;
        }, $pdo);
    }
}

