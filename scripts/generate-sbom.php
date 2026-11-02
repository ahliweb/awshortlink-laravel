<?php

declare(strict_types=1);

/**
 * Generates a CycloneDX 1.5 SBOM from composer.lock (the real dependency set) — never hand-written.
 *
 *   php scripts/generate-sbom.php <composer.lock> <output.json> [app-version]
 */

[$script, $lockPath, $outPath] = array_pad($argv, 3, null);
$version = $argv[3] ?? trim((string) @file_get_contents(dirname(__DIR__) . '/VERSION'));
if ($lockPath === null || $outPath === null) {
    fwrite(STDERR, "Usage: php generate-sbom.php <composer.lock> <output.json> [app-version]\n");
    exit(2);
}

$lock = json_decode((string) file_get_contents($lockPath), true, 512, JSON_THROW_ON_ERROR);
$components = [];
foreach ((array) ($lock['packages'] ?? []) as $pkg) {
    $component = [
        'type' => 'library',
        'bom-ref' => 'pkg:composer/' . $pkg['name'] . '@' . $pkg['version'],
        'name' => $pkg['name'],
        'version' => $pkg['version'],
        'purl' => 'pkg:composer/' . $pkg['name'] . '@' . $pkg['version'],
    ];
    if (!empty($pkg['license'])) {
        $component['licenses'] = array_map(static fn (string $id): array => ['license' => ['id' => $id]], (array) $pkg['license']);
    }
    if (!empty($pkg['dist']['shasum'])) {
        $component['hashes'] = [['alg' => 'SHA-1', 'content' => $pkg['dist']['shasum']]];
    }
    $components[] = $component;
}
$components[] = [
    'type' => 'application',
    'name' => 'postgresql',
    'version' => '18.x',
    'description' => 'Runtime database engine (PostgreSQL only) with compulsory Row-Level Security',
];

$bom = [
    'bomFormat' => 'CycloneDX',
    'specVersion' => '1.5',
    'version' => 1,
    'metadata' => [
        'timestamp' => gmdate('c'),
        'component' => [
            'type' => 'application',
            'name' => 'ahliweb/awshortlink-laravel',
            'version' => $version !== '' ? $version : '0.0.0',
        ],
    ],
    'components' => $components,
];

file_put_contents($outPath, json_encode($bom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
echo "[OK] SBOM with " . count($components) . " components -> {$outPath}\n";
