<?php

declare(strict_types=1);

namespace App\Domain\Identity;

use App\Domain\AccessControl\Database\RlsContext;
use App\Domain\AccessControl\Gate\AuthorizationPipeline;
use App\Domain\Audit\AuditWriter;
use App\Support\Totp;
use App\Support\UuidV7;
use PDO;
use RuntimeException;

/**
 * Organization-Scoped Account Lifecycle, Session/MFA & Unit Closure Hierarchy Service (#11, #39, TST-015).
 */
final class IdentityService
{
    /**
     * @return array<string, mixed>
     */
    public static function inviteUser(
        string $actorId,
        string $name,
        string $email,
        string $unitId,
        string $reason,
        ?string $validUntil = null,
        ?PDO $pdo = null,
    ): array {
        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'users.invite',
            resourceType: 'users',
            resourceAttributes: ['unit_id' => $unitId],
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        $normalizedEmail = strtolower(trim($email));
        $newUserId = UuidV7::generate();
        $membershipId = UuidV7::generate();

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $newUserId,
            $membershipId,
            $name,
            $normalizedEmail,
            $unitId,
            $reason,
            $validUntil
        ): array {
            $stmt = $db->prepare(
                "INSERT INTO shortlink.users (id, name, email, status)
                 VALUES (:id, :name, :email, 'invited')
                 RETURNING id, name, email, status, version, created_at::text"
            );
            $stmt->execute([
                ':id' => $newUserId,
                ':name' => trim($name),
                ':email' => $normalizedEmail,
            ]);
            /** @var array<string, mixed> $user */
            $user = $stmt->fetch();

            $memStmt = $db->prepare(
                "INSERT INTO shortlink.user_unit_memberships (
                    id, user_id, unit_id, valid_until, status, created_by, reason
                ) VALUES (
                    :id, :user_id, :unit_id, :valid_until, 'active', :created_by, :reason
                )"
            );
            $memStmt->execute([
                ':id' => $membershipId,
                ':user_id' => $newUserId,
                ':unit_id' => $unitId,
                ':valid_until' => $validUntil,
                ':created_by' => $actorId,
                ':reason' => $reason,
            ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'users.invited',
                subjectType: 'user',
                subjectId: $newUserId,
                subjectVersion: 1,
                unitId: $unitId,
                beforeState: null,
                afterState: ['id' => $newUserId, 'email' => $normalizedEmail, 'status' => 'invited', 'unit_id' => $unitId],
                reason: $reason
            );

            $user['membership_id'] = $membershipId;
            $user['unit_id'] = $unitId;
            return $user;
        }, $pdo);
    }

    /**
     * Completes invitation onboarding, enrolls TOTP MFA (DES-006), and activates the user.
     *
     * @return array{user_id: string, status: string, mfa_secret: string, version: int}
     */
    public static function acceptInvitation(
        string $userId,
        string $plainPassword,
        ?string $mfaSecret = null,
        ?string $totpCode = null,
        ?PDO $pdo = null,
    ): array {
        if (strlen($plainPassword) < 12) {
            throw new RuntimeException('PASSWORD_TOO_SHORT: Password must be at least 12 characters.');
        }

        $secret = $mfaSecret ?? Totp::generateSecret();
        if ($totpCode !== null && !Totp::verify($secret, $totpCode)) {
            throw new RuntimeException('MFA_TOTP_INVALID: Provided TOTP verification code is invalid.');
        }

        $ctx = RlsContext::forActor($userId, [], true);
        return $ctx->run(static function (PDO $db) use ($userId, $plainPassword, $secret): array {
            $select = $db->prepare('SELECT id, status, version FROM shortlink.users WHERE id = :id FOR UPDATE');
            $select->execute([':id' => $userId]);
            /** @var array<string, mixed>|false $row */
            $row = $select->fetch();
            if (!is_array($row)) {
                throw new RuntimeException('USER_NOT_FOUND');
            }
            if ($row['status'] !== 'invited') {
                throw new RuntimeException('USER_NOT_IN_INVITED_STATE');
            }

            $newVersion = ((int) $row['version']) + 1;
            $upd = $db->prepare(
                "UPDATE shortlink.users
                 SET password_hash = :pw,
                     mfa_secret_encrypted = :secret,
                     mfa_enrolled_at = now(),
                     status = 'active',
                     version = :ver,
                     updated_at = now()
                 WHERE id = :id"
            );
            $upd->execute([
                ':pw' => password_hash($plainPassword, PASSWORD_BCRYPT),
                ':secret' => $secret,
                ':ver' => $newVersion,
                ':id' => $userId,
            ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $userId,
                action: 'users.activated_with_mfa',
                subjectType: 'user',
                subjectId: $userId,
                subjectVersion: $newVersion,
                beforeState: ['status' => 'invited'],
                afterState: ['status' => 'active', 'mfa_enrolled' => true],
                reason: 'Staff accepted invitation and enrolled TOTP MFA'
            );

            return [
                'user_id' => $userId,
                'status' => 'active',
                'mfa_secret' => $secret,
                'version' => $newVersion,
            ];
        }, $pdo);
    }

    /**
     * Authenticates a user and creates an active session with 30m idle / 8h absolute window (DES-012).
     *
     * @return array{session_id: string, user_id: string, mfa_verified: bool, expires_at: string}
     */
    public static function authenticate(
        string $email,
        string $plainPassword,
        ?string $totpCode = null,
        ?PDO $pdo = null,
    ): array {
        $normalizedEmail = strtolower(trim($email));
        $ctx = RlsContext::systemGlobal();

        return $ctx->run(static function (PDO $db) use ($normalizedEmail, $plainPassword, $totpCode): array {
            $stmt = $db->prepare(
                'SELECT id, email, password_hash, mfa_secret_encrypted, mfa_enrolled_at, status
                 FROM shortlink.users
                 WHERE email = :email'
            );
            $stmt->execute([':email' => $normalizedEmail]);
            /** @var array<string, mixed>|false $user */
            $user = $stmt->fetch();

            if (!is_array($user) || empty($user['password_hash'])) {
                throw new RuntimeException('AUTH_INVALID_CREDENTIALS');
            }
            if ($user['status'] !== 'active') {
                throw new RuntimeException('AUTH_ACCOUNT_NOT_ACTIVE:' . (string) $user['status']);
            }
            if (!password_verify($plainPassword, (string) $user['password_hash'])) {
                throw new RuntimeException('AUTH_INVALID_CREDENTIALS');
            }

            $mfaVerified = false;
            if (!empty($user['mfa_secret_encrypted'])) {
                $totp = ($totpCode !== null) ? trim($totpCode) : '';
                if ($totp === '' || !Totp::verify((string) $user['mfa_secret_encrypted'], $totp)) {
                    throw new RuntimeException('AUTH_MFA_REQUIRED_OR_INVALID');
                }
                $mfaVerified = true;
            } else {
                // User has MFA disabled; password verification is sufficient for complete session authentication
                $mfaVerified = true;
            }

            $userId = (string) $user['id'];
            $sessionId = bin2hex(random_bytes(24));
            $expiresAt = gmdate('Y-m-d\TH:i:s\Z', time() + (8 * 3600));

            $ins = $db->prepare(
                'INSERT INTO shortlink.sessions (id, user_id, mfa_verified, created_at, last_activity_at, expires_at)
                 VALUES (:id, :user_id, :mfa, now(), now(), :expires_at)'
            );
            $ins->execute([
                ':id' => $sessionId,
                ':user_id' => $userId,
                ':mfa' => $mfaVerified ? 'true' : 'false',
                ':expires_at' => $expiresAt,
            ]);

            $updLogin = $db->prepare('UPDATE shortlink.users SET last_login_at = now() WHERE id = :id');
            $updLogin->execute([':id' => $userId]);

            return [
                'session_id' => $sessionId,
                'user_id' => $userId,
                'mfa_verified' => $mfaVerified,
                'expires_at' => $expiresAt,
            ];
        }, $pdo);
    }

    /**
     * Validates session idle (30m) and absolute (8h) timeout and active user status (DES-012).
     *
     * @return array{valid: bool, user_id: ?string, mfa_verified: bool, reason_code: string}
     */
    public static function validateSession(string $sessionId, ?PDO $pdo = null): array
    {
        $ctx = RlsContext::systemGlobal();
        return $ctx->run(static function (PDO $db) use ($sessionId): array {
            $stmt = $db->prepare(
                "SELECT s.id, s.user_id, s.mfa_verified, s.revoked_at,
                        (s.expires_at <= now()) AS is_expired,
                        (s.last_activity_at + interval '30 minutes' <= now()) AS is_idle_expired,
                        u.status AS user_status
                 FROM shortlink.sessions s
                 JOIN shortlink.users u ON u.id = s.user_id
                 WHERE s.id = :id"
            );
            $stmt->execute([':id' => $sessionId]);
            /** @var array<string, mixed>|false $row */
            $row = $stmt->fetch();

            if (!is_array($row)) {
                return ['valid' => false, 'user_id' => null, 'mfa_verified' => false, 'reason_code' => 'SESSION_NOT_FOUND'];
            }
            if ($row['revoked_at'] !== null) {
                return ['valid' => false, 'user_id' => (string) $row['user_id'], 'mfa_verified' => false, 'reason_code' => 'SESSION_REVOKED'];
            }
            if ($row['user_status'] !== 'active') {
                return ['valid' => false, 'user_id' => (string) $row['user_id'], 'mfa_verified' => false, 'reason_code' => 'USER_NOT_ACTIVE'];
            }
            if ((bool) $row['is_expired']) {
                return ['valid' => false, 'user_id' => (string) $row['user_id'], 'mfa_verified' => false, 'reason_code' => 'SESSION_ABSOLUTE_TIMEOUT'];
            }
            if ((bool) $row['is_idle_expired']) {
                return ['valid' => false, 'user_id' => (string) $row['user_id'], 'mfa_verified' => false, 'reason_code' => 'SESSION_IDLE_TIMEOUT'];
            }

            $touch = $db->prepare('UPDATE shortlink.sessions SET last_activity_at = now() WHERE id = :id');
            $touch->execute([':id' => $sessionId]);

            return [
                'valid' => true,
                'user_id' => (string) $row['user_id'],
                'mfa_verified' => (bool) $row['mfa_verified'],
                'reason_code' => 'SESSION_ACTIVE',
            ];
        }, $pdo);
    }

    /**
     * Revokes a session (logout). Idempotent; unknown ids are ignored.
     */
    public static function revokeSession(string $sessionId, ?PDO $pdo = null): void
    {
        $ctx = RlsContext::systemGlobal();
        $ctx->run(static function (PDO $db) use ($sessionId): void {
            $stmt = $db->prepare('UPDATE shortlink.sessions SET revoked_at = now() WHERE id = :id AND revoked_at IS NULL');
            $stmt->execute([':id' => $sessionId]);
        }, $pdo);
    }

    /**
     * Suspends or terminally disables a user account while preventing last-platform-owner lockout (#39, TST-015).
     *
     * @return array{user_id: string, status: string, revoked_sessions: int, version: int}
     */
    public static function changeUserStatus(
        string $actorId,
        string $targetUserId,
        string $newStatus,
        string $reason,
        ?int $expectedVersion = null,
        ?PDO $pdo = null,
    ): array {
        if (!in_array($newStatus, ['suspended', 'disabled', 'active'], true)) {
            throw new RuntimeException('INVALID_TARGET_STATUS');
        }

        if ($actorId === $targetUserId && in_array($newStatus, ['suspended', 'disabled'], true)) {
            throw new RuntimeException('SELF_LOCKOUT_FORBIDDEN: Cannot suspend or disable own account.');
        }

        $permKey = match ($newStatus) {
            'suspended' => 'users.suspend',
            'disabled' => 'users.disable',
            'active' => 'users.update',
        };

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: $permKey,
            resourceType: 'users',
            resourceAttributes: ['id' => $targetUserId],
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $targetUserId,
            $newStatus,
            $reason,
            $expectedVersion
        ): array {
            $stmt = $db->prepare(
                'SELECT id, status, is_protected_owner, version
                 FROM shortlink.users
                 WHERE id = :id
                 FOR UPDATE'
            );
            $stmt->execute([':id' => $targetUserId]);
            /** @var array<string, mixed>|false $target */
            $target = $stmt->fetch();

            if (!is_array($target)) {
                throw new RuntimeException('USER_NOT_FOUND_OR_OUT_OF_SCOPE');
            }

            if ($target['status'] === 'disabled') {
                throw new RuntimeException('USER_TERMINALLY_DISABLED: Disabled accounts cannot be modified or reactivated.');
            }

            if ($expectedVersion !== null && (int) $target['version'] !== $expectedVersion) {
                throw new RuntimeException('STALE_VERSION: Expected version ' . $expectedVersion);
            }

            // Last active platform_owner lockout guard (TST-015)
            if (in_array($newStatus, ['suspended', 'disabled'], true)) {
                self::assertNotLastActivePlatformOwner($db, $targetUserId);
            }

            $newVersion = ((int) $target['version']) + 1;
            $upd = $db->prepare(
                "UPDATE shortlink.users
                 SET status = :status,
                     disabled_at = CASE WHEN :status_check = 'disabled' THEN now() ELSE disabled_at END,
                     version = :ver,
                     updated_at = now()
                 WHERE id = :id"
            );
            $upd->execute([
                ':status' => $newStatus,
                ':status_check' => $newStatus,
                ':ver' => $newVersion,
                ':id' => $targetUserId,
            ]);

            $revokedSessions = 0;
            if (in_array($newStatus, ['suspended', 'disabled'], true)) {
                $revStmt = $db->prepare(
                    'UPDATE shortlink.sessions
                     SET revoked_at = now()
                     WHERE user_id = :uid AND revoked_at IS NULL'
                );
                $revStmt->execute([':uid' => $targetUserId]);
                $revokedSessions = $revStmt->rowCount();
            }

            if ($newStatus === 'disabled') {
                $revRoles = $db->prepare(
                    'UPDATE shortlink.user_role_assignments
                     SET revoked_at = now(), revoked_by = :actor, revoke_reason = :reason
                     WHERE user_id = :uid AND revoked_at IS NULL'
                );
                $revRoles->execute([
                    ':actor' => $actorId,
                    ':reason' => 'Account terminally disabled: ' . $reason,
                    ':uid' => $targetUserId,
                ]);
            }

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'users.status_' . $newStatus,
                subjectType: 'user',
                subjectId: $targetUserId,
                subjectVersion: $newVersion,
                beforeState: ['status' => $target['status']],
                afterState: ['status' => $newStatus, 'revoked_sessions' => $revokedSessions],
                reason: $reason
            );

            return [
                'user_id' => $targetUserId,
                'status' => $newStatus,
                'revoked_sessions' => $revokedSessions,
                'version' => $newVersion,
            ];
        }, $pdo);
    }

    public static function assertNotLastActivePlatformOwner(PDO $db, string $targetUserId): void
    {
        $ownerCountStmt = $db->prepare(
            "SELECT count(DISTINCT u.id)
             FROM shortlink.users u
             JOIN shortlink.user_role_assignments ura ON ura.user_id = u.id
             JOIN shortlink.roles r ON r.id = ura.role_id
             WHERE r.key = 'platform_owner'
               AND u.status = 'active'
               AND ura.revoked_at IS NULL
               AND (ura.valid_until IS NULL OR ura.valid_until > now())
               AND u.id <> :target_id"
        );
        $ownerCountStmt->execute([':target_id' => $targetUserId]);
        $remainingOwners = (int) $ownerCountStmt->fetchColumn();

        if ($remainingOwners < 1) {
            throw new RuntimeException('LAST_OWNER_PROTECTED: Cannot suspend, disable, or revoke the last active platform_owner.');
        }
    }

    /**
     * Creates an organizational unit and populates `shortlink.unit_closure` (#39, DES-002).
     *
     * @return array<string, mixed>
     */
    public static function createUnit(
        string $actorId,
        string $code,
        string $name,
        ?string $parentId,
        string $reason,
        ?PDO $pdo = null,
    ): array {
        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'units.create',
            resourceType: 'units',
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        $unitId = UuidV7::generate();
        $cleanCode = strtoupper(trim($code));

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $unitId,
            $cleanCode,
            $name,
            $parentId,
            $reason
        ): array {
            $stmt = $db->prepare(
                "INSERT INTO shortlink.units (id, parent_id, code, name, status)
                 VALUES (:id, :parent_id, :code, :name, 'active')
                 RETURNING id, parent_id, code, name, status, version"
            );
            $stmt->execute([
                ':id' => $unitId,
                ':parent_id' => $parentId,
                ':code' => $cleanCode,
                ':name' => trim($name),
            ]);
            /** @var array<string, mixed> $unit */
            $unit = $stmt->fetch();

            // Self closure entry (depth = 0)
            $selfClosure = $db->prepare(
                'INSERT INTO shortlink.unit_closure (ancestor_id, descendant_id, depth)
                 VALUES (:id, :id, 0)'
            );
            $selfClosure->execute([':id' => $unitId]);

            // Inherit ancestors from parent
            if ($parentId !== null) {
                $ancClosure = $db->prepare(
                    'INSERT INTO shortlink.unit_closure (ancestor_id, descendant_id, depth)
                     SELECT ancestor_id, :child_id, depth + 1
                     FROM shortlink.unit_closure
                     WHERE descendant_id = :parent_id'
                );
                $ancClosure->execute([
                    ':child_id' => $unitId,
                    ':parent_id' => $parentId,
                ]);
            }

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'units.created',
                subjectType: 'unit',
                subjectId: $unitId,
                subjectVersion: 1,
                unitId: $unitId,
                beforeState: null,
                afterState: $unit,
                reason: $reason
            );

            return $unit;
        }, $pdo);
    }

    /**
     * Reparents an organizational unit with cycle detection and `unit_closure` subtree rebuild (#39, DES-002).
     *
     * @return array<string, mixed>
     */
    public static function moveUnit(
        string $actorId,
        string $unitId,
        string $newParentId,
        string $reason,
        ?PDO $pdo = null,
    ): array {
        if ($unitId === $newParentId) {
            throw new RuntimeException('CYCLE_DETECTED_IN_UNIT_TREE: Unit cannot be its own parent.');
        }

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'units.move',
            resourceType: 'units',
            resourceAttributes: ['id' => $unitId, 'unit_id' => $unitId],
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $unitId,
            $newParentId,
            $reason
        ): array {
            // Check if newParentId is already a descendant of unitId
            $cycleCheck = $db->prepare(
                'SELECT 1 FROM shortlink.unit_closure WHERE ancestor_id = :unit_id AND descendant_id = :new_parent'
            );
            $cycleCheck->execute([':unit_id' => $unitId, ':new_parent' => $newParentId]);
            if ($cycleCheck->fetchColumn() !== false) {
                throw new RuntimeException('CYCLE_DETECTED_IN_UNIT_TREE: Cannot move unit under its own descendant.');
            }

            $upd = $db->prepare(
                'UPDATE shortlink.units
                 SET parent_id = :parent_id, version = version + 1, updated_at = now()
                 WHERE id = :id
                 RETURNING id, parent_id, code, name, status, version'
            );
            $upd->execute([':parent_id' => $newParentId, ':id' => $unitId]);
            /** @var array<string, mixed>|false $updated */
            $updated = $upd->fetch();
            if (!is_array($updated)) {
                throw new RuntimeException('UNIT_NOT_FOUND');
            }

            // Delete old ancestor paths for subtree
            $delPaths = $db->prepare(
                'DELETE FROM shortlink.unit_closure
                 WHERE descendant_id IN (
                     SELECT descendant_id FROM shortlink.unit_closure WHERE ancestor_id = :u1
                 )
                 AND ancestor_id IN (
                     SELECT ancestor_id FROM shortlink.unit_closure WHERE descendant_id = :u2 AND ancestor_id <> descendant_id
                 )'
            );
            $delPaths->execute([':u1' => $unitId, ':u2' => $unitId]);

            // Insert new ancestor paths via newParentId
            $insPaths = $db->prepare(
                'INSERT INTO shortlink.unit_closure (ancestor_id, descendant_id, depth)
                 SELECT supertree.ancestor_id, subtree.descendant_id, supertree.depth + subtree.depth + 1
                 FROM shortlink.unit_closure AS supertree
                 CROSS JOIN shortlink.unit_closure AS subtree
                 WHERE supertree.descendant_id = :new_parent
                   AND subtree.ancestor_id = :unit_id'
            );
            $insPaths->execute([':new_parent' => $newParentId, ':unit_id' => $unitId]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'units.moved',
                subjectType: 'unit',
                subjectId: $unitId,
                subjectVersion: (int) $updated['version'],
                unitId: $unitId,
                beforeState: null,
                afterState: $updated,
                reason: $reason
            );

            return $updated;
        }, $pdo);
    }
}

