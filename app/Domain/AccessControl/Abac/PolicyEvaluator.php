<?php

declare(strict_types=1);

namespace App\Domain\AccessControl\Abac;

use Throwable;

/**
 * Constrained Declarative ABAC Policy Evaluator (ADR-0006, SPEC-06, #19, #41).
 *
 * Fail-closed: if any policy rule is malformed or throws during evaluation, the evaluator
 * returns `deny` (`ABAC_EVALUATION_ERROR`). Explicit `deny` always overrides `allow`.
 */
final class PolicyEvaluator
{
    /**
     * @param list<array{
     *   definition_key: string,
     *   version_id: string,
     *   resource: string,
     *   action: string,
     *   rule: array<string, mixed>
     * }> $activePolicies
     * @param array{
     *   actor: array<string, mixed>,
     *   resource: array<string, mixed>,
     *   context: array<string, mixed>
     * } $bag
     * @return array{
     *   verdict: 'allow'|'deny',
     *   reason_code: string,
     *   matched_policy_key: ?string,
     *   matched_version_id: ?string,
     *   trace: list<array<string, mixed>>
     * }
     */
    public static function evaluateAll(string $resourceType, string $action, array $activePolicies, array $bag): array
    {
        $trace = [];
        $matchedAllowPolicy = null;
        $matchedAllowVersion = null;

        foreach ($activePolicies as $pol) {
            $polResource = $pol['resource'];
            $polAction = $pol['action'];
            if ($polResource !== '*' && $polResource !== $resourceType) {
                continue;
            }
            if ($polAction !== '*' && $polAction !== $action) {
                continue;
            }

            $single = self::evaluateRule($pol['rule'], $bag);
            $trace[] = [
                'policy_key' => $pol['definition_key'],
                'version_id' => $pol['version_id'],
                'matched' => $single['matched'],
                'effect' => $single['effect'],
                'reason_code' => $single['reason_code'],
            ];

            if ($single['matched'] && $single['effect'] === 'deny') {
                return [
                    'verdict' => 'deny',
                    'reason_code' => $single['reason_code'],
                    'matched_policy_key' => $pol['definition_key'],
                    'matched_version_id' => $pol['version_id'],
                    'trace' => $trace,
                ];
            }

            if ($single['matched'] && $single['effect'] === 'allow' && $matchedAllowPolicy === null) {
                $matchedAllowPolicy = $pol['definition_key'];
                $matchedAllowVersion = $pol['version_id'];
            }
        }

        return [
            'verdict' => 'allow',
            'reason_code' => $matchedAllowPolicy !== null ? 'ABAC_EXPLICIT_ALLOW' : 'ABAC_NO_DENY_MATCHED',
            'matched_policy_key' => $matchedAllowPolicy,
            'matched_version_id' => $matchedAllowVersion,
            'trace' => $trace,
        ];
    }

    /**
     * @param array<string, mixed> $rule
     * @param array{actor: array<string, mixed>, resource: array<string, mixed>, context: array<string, mixed>} $bag
     * @return array{matched: bool, effect: 'allow'|'deny', reason_code: string}
     */
    public static function evaluateRule(array $rule, array $bag): array
    {
        try {
            $validation = RuleSchemaValidator::validate($rule);
            if (!$validation['valid']) {
                return [
                    'matched' => true,
                    'effect' => 'deny',
                    'reason_code' => 'ABAC_INVALID_RULE_FAIL_CLOSED',
                ];
            }

            $effect = $rule['effect'] === 'allow' ? 'allow' : 'deny';
            $reasonCode = (string) $rule['reason_code'];

            $matched = true;
            if (isset($rule['all']) && is_array($rule['all'])) {
                foreach ($rule['all'] as $pred) {
                    if (!self::evaluatePredicate((array) $pred, $bag)) {
                        $matched = false;
                        break;
                    }
                }
            } elseif (isset($rule['any']) && is_array($rule['any'])) {
                $matched = false;
                foreach ($rule['any'] as $pred) {
                    if (self::evaluatePredicate((array) $pred, $bag)) {
                        $matched = true;
                        break;
                    }
                }
            }

            return [
                'matched' => $matched,
                'effect' => $effect,
                'reason_code' => $reasonCode,
            ];
        } catch (Throwable) {
            return [
                'matched' => true,
                'effect' => 'deny',
                'reason_code' => 'ABAC_EVALUATION_ERROR_FAIL_CLOSED',
            ];
        }
    }

    /**
     * @param array<string, mixed> $pred
     * @param array<string, array<string, mixed>> $bag
     */
    private static function evaluatePredicate(array $pred, array $bag): bool
    {
        $field = (string) ($pred['field'] ?? '');
        $op = (string) ($pred['op'] ?? '');
        $left = self::resolveAttribute($field, $bag);
        $right = str_ends_with($op, '_ref')
            ? self::resolveAttribute((string) ($pred['ref'] ?? ''), $bag)
            : ($pred['value'] ?? null);

        return match ($op) {
            'eq', 'eq_ref' => $left !== null && $left === $right,
            'neq', 'neq_ref' => $left !== $right,
            'in', 'in_ref' => is_array($right) && in_array($left, $right, true),
            'not_in', 'not_in_ref' => is_array($right) && $left !== null && !in_array($left, $right, true),
            'lte' => is_numeric($left) && is_numeric($right) && $left <= $right,
            'gte' => is_numeric($left) && is_numeric($right) && $left >= $right,
            default => false,
        };
    }

    /**
     * @param array<string, array<string, mixed>> $bag
     */
    private static function resolveAttribute(string $field, array $bag): mixed
    {
        $parts = explode('.', $field, 2);
        if (count($parts) !== 2) {
            return null;
        }
        [$ns, $key] = $parts;
        return $bag[$ns][$key] ?? null;
    }
}

