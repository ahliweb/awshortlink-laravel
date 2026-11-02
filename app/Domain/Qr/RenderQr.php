<?php

declare(strict_types=1);

namespace App\Domain\Qr;

use App\Support\Branding;
use App\Domain\AccessControl\Database\RlsContext;
use App\Domain\AccessControl\Gate\AuthorizationPipeline;
use App\Support\UuidV7;
use chillerlan\QRCode\Common\EccLevel;
use chillerlan\QRCode\Output\QRGdImagePNG;
use chillerlan\QRCode\Output\QRMarkupSVG;
use chillerlan\QRCode\QRCode;
use chillerlan\QRCode\QROptions;
use PDO;
use RuntimeException;

/**
 * Deterministic Dynamic ISO/IEC 18004 QR Code SVG & PNG Generator with Center Logo (#16, TST-005, API-019, API-020).
 *
 * Encodes ONLY the canonical public short link URL (`https://<host>/buka/<slug>`),
 * never the mutable destination URL, so destination updates do not invalidate printed QR codes.
 * Uses Error Correction Level H (30%) and stamps the official @@ORG_SHORT@@ logo cleanly in the center.
 * Scannable by standard mobile smartphone cameras, Google Lens, and QR scanner apps.
 * Unpublished/draft links require `qr.generate_draft` (`PERM-016`) and receive a `DRAFT` watermark.
 */
final class RenderQr
{
    /**
     * Local brand logo (env BRAND_LOGO_PATH or public/assets/images/brand-logo.png); null = QR without centre logo.
     */
    public static function resolveLogoPath(): ?string
    {
        return Branding::logoPath();
    }

    /**
     * @return array{
     *   asset_id: string,
     *   link_id: string,
     *   slug: string,
     *   encoded_url: string,
     *   format: 'svg'|'png',
     *   mime_type: string,
     *   is_draft_watermarked: bool,
     *   checksum: string,
     *   content: string
     * }
     */
    public static function generate(
        string $actorId,
        string $linkId,
        string $format = 'svg',
        int $sizePx = 320,
        ?PDO $pdo = null,
    ): array {
        $fmt = strtolower(trim($format));
        if (!in_array($fmt, ['svg', 'png'], true)) {
            throw new RuntimeException('UNSUPPORTED_QR_FORMAT: Only svg and png are allowed.');
        }

        $link = self::fetchLink($actorId, $linkId, $pdo);
        $isPublished = $link['status'] === 'active';
        $requiredPerm = $isPublished ? 'qr.generate_public' : 'qr.generate_draft';

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: $requiredPerm,
            resourceType: 'links',
            resourceAttributes: $link,
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        $slug = (string) $link['slug_normalized'];
        $encodedUrl = Branding::publicBaseUrl() . '/' . $slug;
        $isWatermarked = !$isPublished;

        $content = $fmt === 'svg'
            ? self::renderSvg($encodedUrl, $slug, $isWatermarked, $sizePx)
            : self::renderPng($encodedUrl, $isWatermarked, $sizePx);

        $checksum = hash('sha256', $content);
        $assetId = UuidV7::generate();

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $assetId,
            $linkId,
            $link,
            $slug,
            $encodedUrl,
            $fmt,
            $isWatermarked,
            $checksum,
            $content
        ): array {
            $stmt = $db->prepare(
                'INSERT INTO shortlink.link_qr_assets (
                    id, link_id, unit_id, style_version, output_format, encoded_url,
                    is_draft_watermarked, checksum, generated_by
                ) VALUES (
                    :id, :link_id, :unit_id, 1, :fmt, :encoded_url,
                    :watermarked, :checksum, :actor
                )'
            );
            $stmt->execute([
                ':id' => $assetId,
                ':link_id' => $linkId,
                ':unit_id' => (string) $link['unit_id'],
                ':fmt' => $fmt,
                ':encoded_url' => $encodedUrl,
                ':watermarked' => $isWatermarked ? 'true' : 'false',
                ':checksum' => $checksum,
                ':actor' => $actorId,
            ]);

            return [
                'asset_id' => $assetId,
                'link_id' => $linkId,
                'slug' => $slug,
                'encoded_url' => $encodedUrl,
                'format' => $fmt,
                'mime_type' => $fmt === 'svg' ? 'image/svg+xml' : 'image/png',
                'is_draft_watermarked' => $isWatermarked,
                'checksum' => $checksum,
                'content' => $content,
            ];
        }, $pdo);
    }

    /**
     * Backward-compatible helper for unit tests and deterministic matrix checks.
     *
     * @return list<list<int>>
     */
    public static function buildDeterministicMatrix(string $payload, int $gridSize = 25): array
    {
        $matrix = array_fill(0, $gridSize, array_fill(0, $gridSize, 0));
        $reserved = array_fill(0, $gridSize, array_fill(0, $gridSize, false));

        foreach ([[0, 0], [0, $gridSize - 7], [$gridSize - 7, 0]] as [$r0, $c0]) {
            for ($r = 0; $r < 7; $r++) {
                for ($c = 0; $c < 7; $c++) {
                    $isBorder = ($r === 0 || $r === 6 || $c === 0 || $c === 6);
                    $isCenter = ($r >= 2 && $r <= 4 && $c >= 2 && $c <= 4);
                    $matrix[$r0 + $r][$c0 + $c] = ($isBorder || $isCenter) ? 1 : 0;
                    $reserved[$r0 + $r][$c0 + $c] = true;
                }
            }
        }

        $digest = hash('sha256', 'QR-V1:' . $payload, true) . hash('sha256', 'QR-ECC:' . $payload, true);
        $bitIndex = 0;
        $totalBits = strlen($digest) * 8;

        for ($r = 0; $r < $gridSize; $r++) {
            for ($c = 0; $c < $gridSize; $c++) {
                if ($reserved[$r][$c]) {
                    continue;
                }
                $bytePos = intdiv($bitIndex % $totalBits, 8);
                $bitPos = 7 - ($bitIndex % 8);
                $matrix[$r][$c] = ((ord($digest[$bytePos]) >> $bitPos) & 1);
                $bitIndex++;
            }
        }

        return $matrix;
    }

    /**
     * Generates standard ISO/IEC 18004 Vector SVG with Error Correction Level H and centered @@ORG_SHORT@@ logo.
     */
    private static function renderSvg(
        string $encodedUrl,
        string $slug,
        bool $isWatermarked,
        int $sizePx
    ): string {
        $options = new QROptions();
        $options->eccLevel = EccLevel::H;
        $options->outputBase64 = false;
        $options->outputInterface = QRMarkupSVG::class;
        $options->addQuietzone = true;
        $options->quietzoneSize = 4;
        $options->svgUseFillAttributes = true;

        $qrcode = new QRCode($options);
        $baseSvg = $qrcode->render($encodedUrl);

        $dim = 41;
        if (preg_match('/viewBox="0 0 (\d+) (\d+)"/i', $baseSvg, $m)) {
            $dim = (int) $m[1];
        }

        // Center logo overlay
        $logoPath = self::resolveLogoPath();
        $logoSvg = '';
        if ($logoPath !== null && is_file($logoPath)) {
            $logoB64 = base64_encode((string) file_get_contents($logoPath));
            $logoW = round($dim * 0.20, 2);
            $logoH = round($logoW * 1.15, 2);
            $logoX = round(($dim - $logoW) / 2, 2);
            $logoY = round(($dim - $logoH) / 2, 2);

            $pad = round($logoW * 0.10, 2);
            $bgW = $logoW + ($pad * 2);
            $bgH = $logoH + ($pad * 2);
            $bgX = round(($dim - $bgW) / 2, 2);
            $bgY = round(($dim - $bgH) / 2, 2);

            $logoSvg = sprintf(
                "<g id=\"brand-logo-center\">\n" .
                "  <rect x=\"%s\" y=\"%s\" width=\"%s\" height=\"%s\" rx=\"1.5\" ry=\"1.5\" fill=\"#FFFFFF\" stroke=\"#CBD5E1\" stroke-width=\"0.35\"/>\n" .
                "  <image href=\"data:image/png;base64,%s\" x=\"%s\" y=\"%s\" width=\"%s\" height=\"%s\" preserveAspectRatio=\"xMidYMid meet\"/>\n" .
                "</g>\n",
                $bgX, $bgY, $bgW, $bgH,
                $logoB64,
                $logoX, $logoY, $logoW, $logoH
            );
        }

        $watermarkSvg = $isWatermarked
            ? sprintf(
                "<g id=\"draft-watermark\" opacity=\"0.92\">\n" .
                "  <rect x=\"%s\" y=\"%s\" width=\"%s\" height=\"%s\" rx=\"1\" fill=\"#DC2626\"/>\n" .
                "  <text x=\"%s\" y=\"%s\" text-anchor=\"middle\" fill=\"#FFFFFF\" font-family=\"sans-serif\" font-size=\"%s\" font-weight=\"bold\">DRAFT PREVIEW</text>\n" .
                "</g>\n",
                round($dim * 0.1, 2),
                round($dim * 0.74, 2),
                round($dim * 0.8, 2),
                round($dim * 0.15, 2),
                round($dim / 2, 2),
                round($dim * 0.85, 2),
                round($dim * 0.08, 2)
            )
            : '';

        $safeTitle = htmlspecialchars('QR Shortlink ' . Branding::orgShort() . ' /buka/' . $slug, ENT_XML1 | ENT_QUOTES, 'UTF-8');
        $safeDesc = htmlspecialchars($encodedUrl, ENT_XML1 | ENT_QUOTES, 'UTF-8');
        $headerTags = sprintf("<title>%s</title>\n<desc>%s</desc>\n", $safeTitle, $safeDesc);

        if (!preg_match('/<svg[^>]*\bwidth=/i', $baseSvg)) {
            $baseSvg = preg_replace('/<svg([^>]*)>/i', sprintf('<svg$1 width="%d" height="%d" style="display:block;margin:0 auto;max-width:100%%;height:auto">', $sizePx, $sizePx), $baseSvg, 1);
        } else {
            $baseSvg = preg_replace('/width="[^"]*"/', sprintf('width="%d"', $sizePx), $baseSvg, 1);
            $baseSvg = preg_replace('/height="[^"]*"/', sprintf('height="%d"', $sizePx), $baseSvg, 1);
        }
        $baseSvg = preg_replace('/<svg([^>]*)>/', "<svg$1>\n" . $headerTags, $baseSvg, 1);

        return str_replace('</svg>', $logoSvg . $watermarkSvg . '</svg>', $baseSvg);
    }

    /**
     * Generates standard ISO/IEC 18004 PNG bitmap with Error Correction Level H and centered @@ORG_SHORT@@ logo.
     */
    private static function renderPng(
        string $encodedUrl,
        bool $isWatermarked,
        int $sizePx
    ): string {
        $options = new QROptions();
        $options->eccLevel = EccLevel::H;
        $options->outputBase64 = false;
        $options->outputInterface = QRGdImagePNG::class;
        $options->addQuietzone = true;
        $options->quietzoneSize = 4;
        $options->scale = max(10, intdiv($sizePx, 35));

        $qrcode = new QRCode($options);
        $pngData = $qrcode->render($encodedUrl);

        $qrImg = imagecreatefromstring($pngData);
        if ($qrImg === false) {
            throw new RuntimeException('GD_CREATE_FAILED');
        }

        $w = imagesx($qrImg);
        $h = imagesy($qrImg);

        // Center Logo overlay
        $logoPath = self::resolveLogoPath();
        if ($logoPath !== null && is_file($logoPath)) {
            $logoImg = @imagecreatefrompng($logoPath);
            if ($logoImg !== false) {
                imagealphablending($logoImg, true);
                imagesavealpha($logoImg, true);
                $lw = imagesx($logoImg);
                $lh = imagesy($logoImg);

                $targetLogoW = (int) round($w * 0.20);
                $targetLogoH = (int) round($targetLogoW * ($lh / $lw));
                $logoX = (int) round(($w - $targetLogoW) / 2);
                $logoY = (int) round(($h - $targetLogoH) / 2);

                $pad = (int) round($targetLogoW * 0.10);
                $white = imagecolorallocate($qrImg, 255, 255, 255);
                imagefilledrectangle(
                    $qrImg,
                    $logoX - $pad,
                    $logoY - $pad,
                    $logoX + $targetLogoW + $pad,
                    $logoY + $targetLogoH + $pad,
                    (int) $white
                );

                imagecopyresampled(
                    $qrImg,
                    $logoImg,
                    $logoX,
                    $logoY,
                    0,
                    0,
                    $targetLogoW,
                    $targetLogoH,
                    $lw,
                    $lh
                );
            }
        }

        // Draft watermark if not published
        if ($isWatermarked) {
            $red = imagecolorallocate($qrImg, 220, 38, 38);
            $white = imagecolorallocate($qrImg, 255, 255, 255);
            $bandH = (int) round($h * 0.12);
            $bandY = (int) round($h * 0.75);
            imagefilledrectangle($qrImg, 10, $bandY, $w - 10, $bandY + $bandH, (int) $red);
            imagestring($qrImg, 5, intdiv($w, 2) - 55, $bandY + intdiv($bandH, 2) - 8, 'DRAFT PREVIEW', (int) $white);
        }

        // Resample to requested size if needed
        if ($sizePx > 0 && abs($w - $sizePx) > 10) {
            $scaledImg = imagecreatetruecolor($sizePx, $sizePx);
            if ($scaledImg !== false) {
                $bgWhite = imagecolorallocate($scaledImg, 255, 255, 255);
                imagefill($scaledImg, 0, 0, (int) $bgWhite);
                imagecopyresampled($scaledImg, $qrImg, 0, 0, 0, 0, $sizePx, $sizePx, $w, $h);
                $qrImg = $scaledImg;
            }
        }

        ob_start();
        imagepng($qrImg);
        $finalPng = (string) ob_get_clean();

        return $finalPng;
    }

    /**
     * @return array<string, mixed>
     */
    private static function fetchLink(string $actorId, string $linkId, ?PDO $pdo = null): array
    {
        $ctx = RlsContext::systemGlobal($actorId);
        return $ctx->run(static function (PDO $db) use ($linkId): array {
            $stmt = $db->prepare('SELECT id, unit_id, creator_id, slug_normalized, status, visibility FROM shortlink.links WHERE id = :id');
            $stmt->execute([':id' => $linkId]);
            /** @var array<string, mixed>|false $row */
            $row = $stmt->fetch();
            if (!is_array($row)) {
                throw new RuntimeException('LINK_NOT_FOUND');
            }
            return $row;
        }, $pdo);
    }
}

