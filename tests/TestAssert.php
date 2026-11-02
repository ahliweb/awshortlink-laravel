<?php

declare(strict_types=1);

namespace Tests;

use RuntimeException;
use Throwable;

final class TestAssert
{
    public static int $assertions = 0;

    public static function true(bool $condition, string $message): void
    {
        self::$assertions++;
        if (!$condition) {
            throw new RuntimeException('ASSERT_TRUE_FAILED: ' . $message);
        }
    }

    public static function same(mixed $expected, mixed $actual, string $message): void
    {
        self::$assertions++;
        if ($expected !== $actual) {
            throw new RuntimeException(sprintf(
                'ASSERT_SAME_FAILED (%s): expected %s, got %s',
                $message,
                var_export($expected, true),
                var_export($actual, true)
            ));
        }
    }

    public static function contains(string $needle, string $haystack, string $message): void
    {
        self::$assertions++;
        if (!str_contains($haystack, $needle)) {
            throw new RuntimeException(sprintf(
                'ASSERT_CONTAINS_FAILED (%s): "%s" not found in "%s"',
                $message,
                $needle,
                substr($haystack, 0, 240)
            ));
        }
    }

    public static function throws(callable $fn, string $expectedCodeSubstring, string $message): void
    {
        self::$assertions++;
        try {
            $fn();
        } catch (Throwable $e) {
            if ($expectedCodeSubstring !== '' && !str_contains($e->getMessage(), $expectedCodeSubstring)) {
                throw new RuntimeException(sprintf(
                    'ASSERT_THROWS_MISMATCH (%s): expected exception containing "%s", got "%s"',
                    $message,
                    $expectedCodeSubstring,
                    $e->getMessage()
                ));
            }
            return;
        }
        throw new RuntimeException('ASSERT_THROWS_FAILED (' . $message . '): no exception was thrown.');
    }
}

