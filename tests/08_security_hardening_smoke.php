<?php

declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap/autoload.php';

use App\Database\Migrator;
use App\Domain\Analytics\AccessLogRecorder;
use App\Domain\AccessControl\Database\RlsContext;
use App\Domain\Analytics\UserAgentParser;
use App\Domain\Links\LinkLifecycleService;
use App\Domain\Ops\OpsAndSecurityService;
use App\Domain\Resolver\ResolveSlug;
use App\Support\PostgreSql;
use App\Http\Kernel;
use App\Support\Branding;
use App\Support\GovCaptcha;
use App\Support\TemporaryPassword;
use Tests\TestAssert;

echo "==> [08] Running Security Hardening Regression Tests (path traversal, IP trust, privacy gate, secrets, branding)...\n";

$restore = static function (string $key, string|false $value): void {
    $value === false ? putenv($key) : putenv("{$key}={$value}");
};

// ---------------------------------------------------------------------------------------------------------
// 1. Static asset route must never serve files outside public/assets (source, .env, config, docs)
// ---------------------------------------------------------------------------------------------------------
$ok = Kernel::handle('GET', '/buka/assets/images/brand-logo.png');
TestAssert::same(200, $ok['status'], 'Legit asset is served');
TestAssert::contains('image/png', (string) $ok['headers']['Content-Type'], 'Legit asset has image/png');

// Names containing 'x' / '0' inside a sub-directory must still be served (guards against an over-broad filter).
$root = dirname(__DIR__);
$tmpDir = $root . '/public/assets/zz-test';
@mkdir($tmpDir, 0755, true);
file_put_contents($tmpDir . '/index-x0.css', 'body{}');
$legit = Kernel::handle('GET', '/buka/assets/zz-test/index-x0.css');
TestAssert::same(200, $legit['status'], 'Asset whose name contains x/0 inside a sub-directory is served');
unlink($tmpDir . '/index-x0.css');
rmdir($tmpDir);

foreach ([
    '/buka/assets/../.env',
    '/buka/assets/../.env.example',
    '/buka/assets/../config/database.php',
    '/buka/assets/../../etc/passwd',
    '/buka/assets/images/../../../artisan',
    '/buka/assets/%2e%2e/.env',
    '/buka/assets/..%2f.env',
    '/buka/assets/images\\..\\..\\.env',
    '/buka/assets/../composer.json',
    '/buka/assets/images/brand-logo.png%00.php',
    '/buka/assets/not-allowed.php',
    '/buka/assets/',
] as $evil) {
    $r = Kernel::handle('GET', $evil);
    TestAssert::true($r['status'] === 404, "Traversal/disallowed asset rejected: {$evil} (got {$r['status']})");
    TestAssert::true(!str_contains($r['body'], 'DB_PASSWORD') && !str_contains($r['body'], '<?php'), "No source/secret leaked: {$evil}");
}

// The old /buka/docs/* file server must not exist.
$docs = Kernel::handle('GET', '/buka/docs/README.md');
TestAssert::true(!str_contains($docs['body'], '# '), '/buka/docs/* does not serve repository docs');
TestAssert::true($docs['status'] !== 200 || !str_contains((string) ($docs['headers']['Content-Type'] ?? ''), 'markdown'), '/buka/docs/* is not a file server');

// ---------------------------------------------------------------------------------------------------------
// 2. Client IP: forwarding headers are ignored unless the immediate peer is a trusted proxy
// ---------------------------------------------------------------------------------------------------------
$prevProxies = getenv('TRUSTED_PROXIES');
$prevRemote = $_SERVER['REMOTE_ADDR'] ?? null;
$_SERVER['REMOTE_ADDR'] = '198.51.100.7';

putenv('TRUSTED_PROXIES');
$spoof = ['CF-Connecting-IP' => '203.0.113.9', 'X-Forwarded-For' => '203.0.113.10', 'X-Real-IP' => '203.0.113.11'];
TestAssert::same('198.51.100.7', UserAgentParser::clientIp($spoof), 'No trusted proxies: spoofed headers ignored');

putenv('TRUSTED_PROXIES=192.0.2.0/24');
TestAssert::same('198.51.100.7', UserAgentParser::clientIp($spoof), 'Peer outside trusted CIDR: spoofed headers ignored');

putenv('TRUSTED_PROXIES=198.51.100.0/24');
TestAssert::same('203.0.113.9', UserAgentParser::clientIp($spoof), 'Trusted peer: CF-Connecting-IP honoured');
TestAssert::same('203.0.113.10', UserAgentParser::clientIp(['X-Forwarded-For' => '203.0.113.10']), 'Trusted peer: XFF honoured');
TestAssert::same('203.0.113.10', UserAgentParser::clientIp(['X-Forwarded-For' => '6.6.6.6, 203.0.113.10, 198.51.100.200']), 'XFF walked right-to-left skipping our proxies (left entries are client-forgeable)');
TestAssert::same('198.51.100.7', UserAgentParser::clientIp(['X-Forwarded-For' => 'not-an-ip']), 'Garbage XFF falls back to peer');

TestAssert::true(UserAgentParser::ipInCidrs('10.1.2.3', ['10.0.0.0/8']), 'CIDR /8 match');
TestAssert::true(!UserAgentParser::ipInCidrs('11.1.2.3', ['10.0.0.0/8']), 'CIDR /8 non-match');
TestAssert::true(UserAgentParser::ipInCidrs('192.168.1.130', ['192.168.1.128/25']), 'CIDR /25 match (non byte boundary)');
TestAssert::true(!UserAgentParser::ipInCidrs('192.168.1.127', ['192.168.1.128/25']), 'CIDR /25 non-match');
TestAssert::true(UserAgentParser::ipInCidrs('2001:db8::1', ['2001:db8::/32']), 'IPv6 CIDR match');
TestAssert::true(!UserAgentParser::ipInCidrs('2001:db9::1', ['2001:db8::/32']), 'IPv6 CIDR non-match');
TestAssert::true(!UserAgentParser::ipInCidrs('10.0.0.1', ['2001:db8::/32']), 'Family mismatch never matches');

// The login throttle must key on the real peer: rotating a forged header must NOT evade the per-IP lockout.
putenv('TRUSTED_PROXIES');
$_SERVER['REMOTE_ADDR'] = '198.51.100.99';
putenv('THROTTLE_STORAGE_DIR=' . sys_get_temp_dir() . '/aw-throttle-' . bin2hex(random_bytes(4)));
Migrator::resetAllData();
$locked = false;
for ($i = 1; $i <= 7; $i++) {
    $res = Kernel::handle('POST', '/buka/admin/login', ['CF-Connecting-IP' => "203.0.113.{$i}"], [], ['email' => "victim{$i}@example.org", 'password' => 'x', 'totp' => '000000']);
    if ($res['status'] === 429) {
        $locked = true;
        break;
    }
}
TestAssert::true($locked, 'Per-IP lockout engages even when each attempt forges a different CF-Connecting-IP and uses a different e-mail');
putenv('THROTTLE_STORAGE_DIR');

$restore('TRUSTED_PROXIES', $prevProxies);
if ($prevRemote === null) {
    unset($_SERVER['REMOTE_ADDR']);
} else {
    $_SERVER['REMOTE_ADDR'] = $prevRemote;
}

// ---------------------------------------------------------------------------------------------------------
// 3. Privacy: per-visitor telemetry is opt-in; IP truncated; referer reduced to origin
// ---------------------------------------------------------------------------------------------------------
TestAssert::same('203.0.113.0', AccessLogRecorder::truncateIp('203.0.113.77'), 'IPv4 truncated to /24');
TestAssert::same('2001:db8:1::', AccessLogRecorder::truncateIp('2001:db8:1:2:3:4:5:6'), 'IPv6 truncated to /48');
TestAssert::same('', AccessLogRecorder::truncateIp('garbage'), 'Invalid IP stored as empty');
TestAssert::same('https://ref.example.net', AccessLogRecorder::refererOrigin('https://ref.example.net/path?token=SECRET#frag'), 'Referer path/query stripped');
TestAssert::same('http://ref.example.net:8080', AccessLogRecorder::refererOrigin('http://ref.example.net:8080/x'), 'Referer port retained');
TestAssert::same('', AccessLogRecorder::refererOrigin('javascript:alert(1)'), 'Non-http referer dropped');

$prevRaw = getenv('ANALYTICS_RAW_EVENTS_ENABLED');
putenv('ANALYTICS_RAW_EVENTS_ENABLED=false');
TestAssert::same(false, AccessLogRecorder::record('00000000-0000-7000-8000-0000000000aa', ['User-Agent' => 'Mozilla/5.0'], 0), 'Telemetry disabled: nothing recorded');
$restore('ANALYTICS_RAW_EVENTS_ENABLED', $prevRaw);

// ---------------------------------------------------------------------------------------------------------
// 4. Secrets: no fallback HMAC key, no demo seeding in production, destructive reset guarded
// ---------------------------------------------------------------------------------------------------------
$prevKey = getenv('APP_KEY');
putenv('APP_KEY');
TestAssert::throws(static fn () => GovCaptcha::generate(), 'APP_KEY', 'CAPTCHA refuses to sign without APP_KEY');
putenv('APP_KEY=short');
TestAssert::throws(static fn () => GovCaptcha::generate(), 'APP_KEY', 'CAPTCHA refuses a weak APP_KEY');
$restore('APP_KEY', $prevKey);
TestAssert::true(GovCaptcha::generate()['token'] !== '', 'CAPTCHA works with a strong APP_KEY');

$prevEnv = getenv('APP_ENV');
$prevDemo = getenv('SHORTLINK_DEMO_SEED');
putenv('APP_ENV=production');
putenv('SHORTLINK_DEMO_SEED=1');
TestAssert::throws(static fn () => Migrator::demoSeedEnabled(), 'production', 'Demo seed refused in production');
TestAssert::throws(static fn () => Migrator::resetAllData(), 'destructive', 'Data reset refused in production');
$restore('APP_ENV', $prevEnv);
$restore('SHORTLINK_DEMO_SEED', $prevDemo);

$pw1 = TemporaryPassword::generate();
$pw2 = TemporaryPassword::generate();
TestAssert::true(strlen($pw1) >= 24 && $pw1 !== $pw2, 'Temporary passwords are long and unique');

// ---------------------------------------------------------------------------------------------------------
// 5. Branding: placeholders resolved & escaped; production APP_URL must be https
// ---------------------------------------------------------------------------------------------------------
$prevName = getenv('BRAND_ORG_NAME');
putenv('BRAND_ORG_NAME=Acme <script>alert(1)</script> & Co');
$applied = Branding::apply('<p>@@ORG_NAME@@</p>');
TestAssert::true(!str_contains($applied, '<script>'), 'Brand values are HTML-escaped');
TestAssert::contains('&lt;script&gt;', $applied, 'Brand value escaped, not dropped');
$restore('BRAND_ORG_NAME', $prevName);

$prevUrl = getenv('APP_URL');
putenv('APP_ENV=production');
putenv('APP_URL=http://insecure.example.org/buka');
TestAssert::throws(static fn () => Branding::publicBaseUrl(), 'https', 'Production refuses a non-https APP_URL');
TestAssert::same('about:blank', Branding::safePublicBaseUrl(), 'Error paths degrade without throwing');
$restore('APP_ENV', $prevEnv);
$restore('APP_URL', $prevUrl);

$page = Kernel::handle('GET', '/buka/');
TestAssert::true(!str_contains($page['body'], '@@'), 'No unresolved @@placeholders in the public page');

// ---------------------------------------------------------------------------------------------------------
// 6. Telemetry ON: truncated IP, referer origin only, unit-scoped RLS SELECT, retention purge
// ---------------------------------------------------------------------------------------------------------
Migrator::resetAllData();
$prevRaw2 = getenv('ANALYTICS_RAW_EVENTS_ENABLED');
putenv('ANALYTICS_RAW_EVENTS_ENABLED=true');
$draftT = LinkLifecycleService::createDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_DIVISION_A,
    rawSlug: 'telemetry-check',
    title: 'Telemetry check',
    destinationUrl: 'https://www.example.org/telemetry'
);
LinkLifecycleService::approveAndPublish(Migrator::USER_SECURITY_APPROVER, (string) $draftT['id']);

$_SERVER['REMOTE_ADDR'] = '198.51.100.77';
$resT = ResolveSlug::resolve('GET', 'telemetry-check', [
    'User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
    'Referer' => 'https://ref.example.net/private/path?token=SECRET',
    'CF-Connecting-IP' => '203.0.113.9',
    'CF-IPCity' => 'Spoofville',
], PostgreSql::resolver());
TestAssert::same(302, $resT['http_status'], 'Telemetry link resolves');

$sys = RlsContext::systemGlobal();
$logRows = $sys->run(static fn (\PDO $db): array => $db->query('SELECT ip_address, referer, city, latitude FROM shortlink.link_access_logs')->fetchAll(\PDO::FETCH_ASSOC));
TestAssert::same(1, count($logRows), 'Exactly one telemetry row recorded when enabled');
TestAssert::true($logRows[0]['ip_address'] === '198.51.100.0', 'Stored IP is the truncated REAL peer, not the spoofed header');
TestAssert::same('https://ref.example.net', $logRows[0]['referer'], 'Referer stored as origin only (token/path dropped)');
TestAssert::same('Unknown', $logRows[0]['city'], 'Untrusted geo header ignored; no fabricated location');
TestAssert::same(null, $logRows[0]['latitude'], 'No fabricated coordinates');

// RLS: an actor scoped to another unit cannot read this unit's telemetry; a scoped actor for the owning unit can.
$other = RlsContext::forActor(Migrator::USER_PLATFORM_OWNER, [Migrator::UNIT_BRANCH_A], false);
TestAssert::same(0, (int) $other->run(static fn (\PDO $db): mixed => $db->query('SELECT count(*) FROM shortlink.link_access_logs')->fetchColumn()), 'Out-of-scope unit sees no telemetry (unit-scoped RLS)');
$own = RlsContext::forActor(Migrator::USER_PLATFORM_OWNER, [Migrator::UNIT_DIVISION_A], false);
TestAssert::same(1, (int) $own->run(static fn (\PDO $db): mixed => $db->query('SELECT count(*) FROM shortlink.link_access_logs')->fetchColumn()), 'In-scope unit sees its telemetry');

// Non-global actors cannot delete telemetry; the global scheduler purges only rows beyond retention.
$delOther = $own->run(static fn (\PDO $db): int => $db->exec('DELETE FROM shortlink.link_access_logs'));
TestAssert::same(0, $delOther, 'Scoped (non-global) actor cannot delete telemetry rows');
$sys->run(static function (\PDO $db) use ($draftT): void {
    $db->prepare("INSERT INTO shortlink.link_access_logs (id, link_id, occurred_at, ip_address) VALUES (:id, :l, now() - interval '400 days', '192.0.2.0')")
       ->execute([':id' => \App\Support\UuidV7::generate(), ':l' => $draftT['id']]);
});
$sched = OpsAndSecurityService::runBoundedSchedule();
TestAssert::same(1, $sched['access_logs_purged'], 'Scheduler purged exactly the row older than retention');
TestAssert::same(1, (int) $sys->run(static fn (\PDO $db): mixed => $db->query('SELECT count(*) FROM shortlink.link_access_logs')->fetchColumn()), 'Recent telemetry survives the purge');
$restore('ANALYTICS_RAW_EVENTS_ENABLED', $prevRaw2);
unset($_SERVER['REMOTE_ADDR']);

// No source file may hard-code a personal e-mail, password or instance identity.
$root = dirname(__DIR__);
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/app', FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    if ($f->isFile() && str_ends_with($f->getFilename(), '.php')) {
        $src = (string) file_get_contents($f->getPathname());
        TestAssert::true(preg_match('/[A-Za-z0-9._%+-]+@(gmail|yahoo|outlook|hotmail)\.com/i', $src) !== 1, 'No personal e-mail hard-coded in ' . $f->getFilename());
        TestAssert::true(!str_contains($src, '/home/'), 'No developer absolute path in ' . $f->getFilename());
    }
}

echo '    [PASS] Security hardening regression suite (' . TestAssert::$assertions . " assertions)\n";
