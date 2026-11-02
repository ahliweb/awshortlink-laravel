<?php

declare(strict_types=1);

namespace App\Domain\AccessControl\Abac;

/**
 * Constrained Declarative ABAC JSON Rule Schema Validator (ADR-0006, SPEC-06, #41, TST-016).
 *
 * Strictly forbids executable scripts, expressions, SQL fragments, or arbitrary attribute paths.
 * Enforces max nesting depth <= 4 and max predicate count <= 12.
 */
final class RuleSchemaValidator
{
    public const MAX_DEPTH = 4;
    public const MAX_CONDITIONS = 12;

    private const ALLOWED_FIELDS = [
        'actor.id',
        'actor.status',
        'actor.mfa_verified',
        'actor.is_global_scope',
        'actor.expanded_unit_ids',
        'resource.id',
        'resource.unit_id',
        'resource.creator_id',
        'resource.proposed_by',
        'resource.status',
        'resource.risk_class',
        'resource.visibility',
        'context.permission_key',
        'context.permission_risk',
        'context.is_mutation',
        'context.scope_type',
    ];

    private const ALLOWED_OPS = [
        'eq',
        'neq',
        'in',
        'not_in',
        'eq_ref',
        'neq_ref',
        'in_ref',
        'not_in_ref',
        'lte',
        'gte',
    ];

    private const FORBIDDEN_KEYS = [
        'script', 'eval', 'php', 'sql', 'expression', 'raw', 'function', 'callback', 'exec', 'shell',
    ];

    /**
     * @param array<string, mixed> $rule
     * @return array{valid: bool, errors: list<string>, condition_count: int}
     */
    public static function validate(array $rule): array
    {
        $errors = [];

        // Check forbidden keys recursively & nesting depth
        $conditionCount = 0;
        self::inspectStructure($rule, 1, $errors, $conditionCount);

        if (($rule['schema_version'] ?? null) !== 1) {
            $errors[] = 'RULE_SCHEMA_VERSION_INVALID: schema_version must be integer 1.';
        }

        $effect = $rule['effect'] ?? null;
        if (!in_array($effect, ['allow', 'deny'], true)) {
            $errors[] = 'RULE_EFFECT_INVALID: effect must be "allow" or "deny".';
        }

        $reasonCode = $rule['reason_code'] ?? null;
        if (!is_string($reasonCode) || !preg_match('/^ABAC_[A-Z0-9_]{3,48}$/', $reasonCode)) {
            $errors[] = 'RULE_REASON_CODE_INVALID: reason_code must match ^ABAC_[A-Z0-9_]{3,48}$.';
        }

        $hasAll = isset($rule['all']) && is_array($rule['all']);
        $hasAny = isset($rule['any']) && is_array($rule['any']);
        if (!$hasAll && !$hasAny) {
            $errors[] = 'RULE_PREDICATES_MISSING: rule must contain non-empty "all" or "any" predicate array.';
        }

        $predicates = [];
        if ($hasAll) {
            $predicates = array_merge($predicates, (array) $rule['all']);
        }
        if ($hasAny) {
            $predicates = array_merge($predicates, (array) $rule['any']);
        }

        if ($predicates === []) {
            $errors[] = 'RULE_PREDICATES_EMPTY: predicate list must contain at least 1 condition.';
        }

        if (count($predicates) > self::MAX_CONDITIONS) {
            $errors[] = sprintf(
                'RULE_MAX_CONDITIONS_EXCEEDED: %d conditions exceed maximum %d.',
                count($predicates),
                self::MAX_CONDITIONS
            );
        }

        foreach ($predicates as $idx => $pred) {
            if (!is_array($pred)) {
                $errors[] = sprintf('RULE_PREDICATE_INVALID[%d]: must be an object.', $idx);
                continue;
            }
            $field = $pred['field'] ?? null;
            if (!is_string($field) || !in_array($field, self::ALLOWED_FIELDS, true)) {
                $errors[] = sprintf('RULE_FIELD_FORBIDDEN[%d]: "%s" is not in the typed attribute catalog.', $idx, (string) $field);
            }
            $op = $pred['op'] ?? null;
            if (!is_string($op) || !in_array($op, self::ALLOWED_OPS, true)) {
                $errors[] = sprintf('RULE_OP_FORBIDDEN[%d]: "%s" is not an allowed operator.', $idx, (string) $op);
                continue;
            }
            if (str_ends_with($op, '_ref')) {
                $ref = $pred['ref'] ?? null;
                if (!is_string($ref) || !in_array($ref, self::ALLOWED_FIELDS, true)) {
                    $errors[] = sprintf('RULE_REF_FORBIDDEN[%d]: "%s" is not in the typed attribute catalog.', $idx, (string) $ref);
                }
            } elseif (!array_key_exists('value', $pred)) {
                $errors[] = sprintf('RULE_VALUE_MISSING[%d]: operator "%s" requires a literal "value".', $idx, $op);
            }
        }

        return [
            'valid' => $errors === [],
            'errors' => $errors,
            'condition_count' => count($predicates),
        ];
    }

    /**
     * @param array<mixed> $node
     * @param list<string> $errors
     */
    private static function inspectStructure(array $node, int $depth, array &$errors, int &$conditionCount): void
    {
        if ($depth > self::MAX_DEPTH) {
            $errors[] = sprintf('RULE_MAX_DEPTH_EXCEEDED: nesting depth %d exceeds limit %d.', $depth, self::MAX_DEPTH);
            return;
        }

        foreach ($node as $key => $val) {
            if (is_string($key) && in_array(strtolower($key), self::FORBIDDEN_KEYS, true)) {
                $errors[] = sprintf('RULE_EXECUTABLE_KEY_FORBIDDEN: key "%s" is strictly prohibited.', $key);
            }
            if (is_array($val)) {
                if (isset($val['field'], $val['op'])) {
                    $conditionCount++;
                }
                self::inspectStructure($val, $depth + 1, $errors, $conditionCount);
            }
        }
    }
}

