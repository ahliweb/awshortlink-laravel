<?php

declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap/autoload.php';

use App\Database\Migrator;
use App\Http\Kernel;
use App\Support\GovCaptcha;
use App\Support\Totp;
use Tests\TestAssert;

echo "==> [07] Running Admin Session Login, Cookie Hardening, Logout & Production Actor-Header Rejection...\n";

putenv('APP_ENV');
Migrator::resetAllData();

// The login form requires a solved math CAPTCHA; the token no longer contains the answer, so solve it from the question.
$captcha = static function (): array {
    $c = GovCaptcha::generate();
    TestAssert::true(!str_contains(base64_decode(strtr(explode('.', $c['token'])[0], '-_', '+/')), '"ans"'), 'CAPTCHA token does not expose the answer');
    preg_match('/(\d+)\s*([+-])\s*(\d+)/', $c['question'], $m);
    $answer = $m[2] === '+' ? (int) $m[1] + (int) $m[3] : (int) $m[1] - (int) $m[3];
    sleep(2); // anti-bot time-lock rejects instant submissions

    return ['captcha_token' => $c['token'], 'captcha_answer' => (string) $answer];
};

// Per-run random demo credentials are injected by scripts/smoke.sh; nothing is hard-coded in the repository.
$secret = (string) getenv('SHORTLINK_DEMO_TOTP_SECRET');
$email = Migrator::ownerEmail();
$pw = (string) getenv('SHORTLINK_DEMO_PASSWORD');
TestAssert::true($secret !== '' && strlen($pw) >= 16, 'Demo credentials must be supplied via environment (run through scripts/smoke.sh)');

// Login page renders a real POST form
$page = Kernel::handle('GET', '/buka/admin/login');
TestAssert::same(200, $page['status'], 'GET login page 200');
TestAssert::contains('method="POST" action="/buka/admin/login"', $page['body'], 'Login page has POST form');
TestAssert::contains('name="totp"', $page['body'], 'Login page requires TOTP');

// Bad credentials -> uniform 401, no cookie
$bad = Kernel::handle('POST', '/buka/admin/login', [], [], array_merge($captcha(), ['email' => $email, 'password' => 'wrong-password-123', 'totp' => '000000']));
TestAssert::same(401, $bad['status'], 'Wrong password rejected');
TestAssert::true(!isset($bad['headers']['Set-Cookie']), 'No cookie on failed login');

// Wrong TOTP
$badMfa = Kernel::handle('POST', '/buka/admin/login', [], [], array_merge($captcha(), ['email' => $email, 'password' => $pw, 'totp' => '000000']));
TestAssert::same(401, $badMfa['status'], 'Wrong TOTP rejected');

// Good login
$ok = Kernel::handle('POST', '/buka/admin/login', [], [], array_merge($captcha(), ['email' => $email, 'password' => $pw, 'totp' => Totp::codeAt($secret, time())]));
TestAssert::same(303, $ok['status'], 'Valid login redirects 303');
$cookie = $ok['headers']['Set-Cookie'] ?? '';
foreach (['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/buka'] as $attr) {
    TestAssert::contains($attr, $cookie, "Session cookie has {$attr}");
}
preg_match('/aw_session=([a-f0-9]{48})/', $cookie, $m);
TestAssert::true(isset($m[1]), 'Session id is 48 hex chars');
$cookieHdr = ['Cookie' => 'aw_session=' . $m[1]];

// Session grants dashboard with authorized menu
$dash = Kernel::handle('GET', '/buka/admin', $cookieHdr);
TestAssert::same(200, $dash['status'], 'Dashboard with session 200');
TestAssert::contains('/buka/admin/links', $dash['body'], 'Dashboard lists authorized navigation');
TestAssert::contains('/buka/admin/logout', $dash['body'], 'Dashboard has logout');

// Browser without session is redirected to login; API client gets 401 problem
$redir = Kernel::handle('GET', '/buka/admin', ['Accept' => 'text/html']);
TestAssert::same(302, $redir['status'], 'HTML client redirected to login');
$anon = Kernel::handle('GET', '/buka/admin');
TestAssert::same(401, $anon['status'], 'Anonymous gets 401');

// Forged cookie rejected
$forged = Kernel::handle('GET', '/buka/admin', ['Cookie' => 'aw_session=' . str_repeat('a', 48)]);
TestAssert::same(401, $forged['status'], 'Forged session rejected');

// Logout revokes server-side
$out = Kernel::handle('POST', '/buka/admin/logout', $cookieHdr);
TestAssert::same(303, $out['status'], 'Logout redirects');
$after = Kernel::handle('GET', '/buka/admin', $cookieHdr);
TestAssert::same(401, $after['status'], 'Revoked session rejected');

// Production must ignore X-Actor-Id
putenv('APP_ENV=production');
$spoof = Kernel::handle('GET', '/buka/admin', ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER]);
$apiSpoof = Kernel::handle('POST', '/buka/livewire/update', ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER]);
putenv('APP_ENV');
TestAssert::same(401, $spoof['status'], 'Production ignores X-Actor-Id on admin');
TestAssert::same(401, $apiSpoof['status'], 'Production ignores X-Actor-Id on livewire/API');

echo "    [PASS] 07_admin_session_login_smoke.php\n";
