<?php

declare(strict_types=1);

namespace App\Support;

/**
 * Self-Hosted, Privacy-Preserving, Accessible GovTech Anti-Spam & Math CAPTCHA Protection.
 * Fully offline/self-contained with no external dependencies (WCAG 2.2 AA compliant).
 */
final class GovCaptcha
{
    /**
     * Generates a new cryptographic math challenge and signed tamper-proof token.
     *
     * @return array{question: string, token: string}
     */
    public static function generate(): array
    {
        $a = random_int(4, 18);
        $b = random_int(2, 11);
        $isAdd = (random_int(0, 1) === 1);

        if ($isAdd) {
            $question = "Berapa hasil dari {$a} + {$b}?";
            $ans = $a + $b;
        } else {
            // Subtraction: ensure positive answer
            if ($a < $b) {
                [$a, $b] = [$b, $a];
            }
            if ($a === $b) {
                $a += 3;
            }
            $question = "Berapa hasil dari {$a} - {$b}?";
            $ans = $a - $b;
        }

        $now = time();
        $nonce = bin2hex(random_bytes(8));
        // The token is only signed, not encrypted, so it must never contain the answer: store a keyed digest
        // instead. Otherwise a bot could base64-decode the token and read the solution.
        $payload = [
            'ah' => hash_hmac('sha256', $nonce . '|' . $ans, self::secret()),
            'ts' => $now,
            'exp' => $now + 1800, // 30 minutes valid
            'nonce' => $nonce,
        ];

        $payloadJson = (string) json_encode($payload, JSON_UNESCAPED_SLASHES);
        $payloadB64 = rtrim(strtr(base64_encode($payloadJson), '+/', '-_'), '=');
        $sig = hash_hmac('sha256', $payloadB64, self::secret());
        $token = $payloadB64 . '.' . $sig;

        return [
            'question' => $question,
            'token' => $token,
        ];
    }

    /**
     * Verifies the submitted CAPTCHA token, user answer, and honeypot field.
     *
     * @param array<string, mixed> $body
     * @return array{valid: bool, error: ?string}
     */
    public static function verify(array $body): array
    {
        // 1. Honeypot check (invisible to humans, filled by spam bots)
        $honeypot = trim((string) ($body['website_url_confirm'] ?? ''));
        if ($honeypot !== '') {
            return ['valid' => false, 'error' => 'Aktivitas pengisian terdeteksi otomatis (bot spam). Permintaan akses ditolak.'];
        }

        $token = trim((string) ($body['captcha_token'] ?? ''));
        $userAnswer = trim((string) ($body['captcha_answer'] ?? ''));

        if ($token === '' || $userAnswer === '') {
            return ['valid' => false, 'error' => 'Pertanyaan verifikasi anti-spam (CAPTCHA) wajib diisi.'];
        }

        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) {
            return ['valid' => false, 'error' => 'Token verifikasi anti-spam tidak valid. Silakan muat soal baru.'];
        }

        [$payloadB64, $clientSig] = $parts;
        $expectedSig = hash_hmac('sha256', $payloadB64, self::secret());

        if (!hash_equals($expectedSig, $clientSig)) {
            return ['valid' => false, 'error' => 'Tanda tangan token keamanan anti-spam tidak cocok.'];
        }

        $jsonStr = base64_decode(strtr($payloadB64, '-_', '+/'), true);
        if ($jsonStr === false) {
            return ['valid' => false, 'error' => 'Payload verifikasi keamanan rusak.'];
        }

        $payload = json_decode($jsonStr, true);
        if (!is_array($payload) || !isset($payload['ah'], $payload['nonce'], $payload['ts'], $payload['exp'])) {
            return ['valid' => false, 'error' => 'Format token verifikasi tidak valid.'];
        }

        $now = time();
        $age = $now - (int) $payload['ts'];

        // 2. Time-lock check: rejecting instant automated script submissions (< 1.5s)
        if ($age < 2) {
            return ['valid' => false, 'error' => 'Pengisian formulir terlalu cepat (terindikasi bot otomatis). Mohon periksa kembali laporan Anda.'];
        }

        // 3. Expiration check (> 30 mins)
        if ($now > (int) $payload['exp']) {
            return ['valid' => false, 'error' => 'Kode verifikasi keamanan telah kedaluwarsa. Silakan klik tombol "Ganti Soal" untuk mendapatkan soal baru.'];
        }

        // 4. Mathematical answer check
        $expectedDigest = is_numeric($userAnswer)
            ? hash_hmac('sha256', (string) $payload['nonce'] . '|' . (int) $userAnswer, self::secret())
            : '';
        if ($expectedDigest === '' || !hash_equals($expectedDigest, (string) $payload['ah'])) {
            return ['valid' => false, 'error' => 'Jawaban verifikasi anti-spam salah. Silakan hitung kembali hasil soal matematika.'];
        }

        return ['valid' => true, 'error' => null];
    }

    /**
     * HMAC key derived from APP_KEY (domain-separated). There is no fallback secret: without a strong APP_KEY
     * tokens would be forgeable, so we fail closed.
     */
    private static function secret(): string
    {
        $key = (string) (getenv('APP_KEY') ?: '');
        if (str_starts_with($key, 'base64:')) {
            $decoded = base64_decode(substr($key, 7), true);
            $key = $decoded === false ? '' : $decoded;
        }
        if (strlen($key) < 32) {
            throw new \RuntimeException('APP_KEY is missing or too short (need >= 32 bytes); refusing to sign CAPTCHA tokens.');
        }

        return hash_hmac('sha256', 'awshortlink.captcha.v1', $key, true);
    }
}

