<?php

declare(strict_types=1);

namespace App\Filament;

use App\Domain\AccessControl\Gate\AuthorizationPipeline;
use PDO;

/**
 * Filament 5 Panel Registry & WCAG 2.2 AA Accessible Screen Renderer (#10, #11, #15, #20, #22, #39, #40, #41, #42).
 *
 * Maps all 18 canonical screens (`UI-001..018`) to their required `PERM-*` permissions and OpenAPI operations,
 * ensuring fail-closed server-side authorization (never merely hiding menu items).
 * Adheres to ahliweb/personal-coding UI/UX design tokens and WCAG 2.2 Level AA accessibility.
 */
final class PanelRegistry
{
    public const APP_VERSION = '1.1.0';
    public const PANEL_PATH = '/buka/admin';
    public const LIVEWIRE_UPDATE_URI = '/buka/livewire/update';
    public const LIVEWIRE_SCRIPT_URI = '/buka/livewire/livewire.js';

    /**
     * @return array<string, array{
     *   id: string,
     *   route: string,
     *   title: string,
     *   permission: ?string,
     *   public: bool,
     *   nav_group: ?string
     * }>
     */
    public static function screens(): array
    {
        return [
            'UI-001' => ['id' => 'UI-001', 'route' => '/buka/admin/login', 'title' => 'Masuk Panel Admin & Verifikasi MFA TOTP', 'permission' => null, 'public' => true, 'nav_group' => null],
            'UI-002' => ['id' => 'UI-002', 'route' => '/buka/admin', 'title' => 'Dasbor Ikhtisar & Antrean Persetujuan', 'permission' => 'links.list_internal', 'public' => false, 'nav_group' => 'Utama'],
            'UI-003' => ['id' => 'UI-003', 'route' => '/buka/admin/links', 'title' => 'Daftar & Pencarian Tautan Pendek', 'permission' => 'links.list_internal', 'public' => false, 'nav_group' => 'Tautan'],
            'UI-004' => ['id' => 'UI-004', 'route' => '/buka/admin/links/create', 'title' => 'Buat Draf Tautan Pendek & Pemeriksa Kebijakan URL', 'permission' => 'links.create_draft', 'public' => false, 'nav_group' => 'Tautan'],
            'UI-005' => ['id' => 'UI-005', 'route' => '/buka/admin/links/{id}', 'title' => 'Detail Tautan, Riwayat Revisi Tujuan & Rollback', 'permission' => 'destinations.view_history', 'public' => false, 'nav_group' => null],
            'UI-006' => ['id' => 'UI-006', 'route' => '/buka/admin/approvals', 'title' => 'Tinjauan Persetujuan Independen (SoD) & Tangguhkan Darurat', 'permission' => 'links.list_internal', 'public' => false, 'nav_group' => 'Tautan'],
            'UI-007' => ['id' => 'UI-007', 'route' => '/buka/admin/links/{id}/qr', 'title' => 'Pratinjau & Unduh Kode QR Dinamis (SVG/PNG)', 'permission' => 'qr.generate_public', 'public' => false, 'nav_group' => null],
            'UI-008' => ['id' => 'UI-008', 'route' => '/buka/', 'title' => 'Beranda Publik & Direktori Tautan Resmi @@ORG_SHORT@@', 'permission' => null, 'public' => true, 'nav_group' => null],
            'UI-009' => ['id' => 'UI-009', 'route' => '/buka/{slug}', 'title' => 'Halaman Status Tautan Publik (404 / 410 / 503)', 'permission' => null, 'public' => true, 'nav_group' => null],
            'UI-010' => ['id' => 'UI-010', 'route' => '/buka/admin/analytics', 'title' => 'Analitik Klik Agregat Harian & Kampanye (k=10)', 'permission' => 'analytics.view', 'public' => false, 'nav_group' => 'Analitik'],
            'UI-011' => ['id' => 'UI-011', 'route' => '/buka/admin/audit', 'title' => 'Log Audit Rantai Hash SHA-256 & Verifikasi Integritas', 'permission' => 'audit.view', 'public' => false, 'nav_group' => 'Tata Kelola'],
            'UI-012' => ['id' => 'UI-012', 'route' => '/buka/admin/users', 'title' => 'Manajemen Pengguna & Siklus Hidup Akun Unit', 'permission' => 'users.read', 'public' => false, 'nav_group' => 'IAM & Keamanan'],
            'UI-013' => ['id' => 'UI-013', 'route' => '/buka/admin/units', 'title' => 'Hierarki Unit Organisasi & Keanggotaan (Closure Table)', 'permission' => 'units.read', 'public' => false, 'nav_group' => 'IAM & Keamanan'],
            'UI-014' => ['id' => 'UI-014', 'route' => '/buka/admin/roles', 'title' => 'Peran RBAC, Matriks Izin & Permintaan Dual-Control', 'permission' => 'roles.read', 'public' => false, 'nav_group' => 'IAM & Keamanan'],
            'UI-015' => ['id' => 'UI-015', 'route' => '/buka/admin/policies', 'title' => 'Kebijakan ABAC Deklaratif, Simulasi & Publikasi', 'permission' => 'policies.read', 'public' => false, 'nav_group' => 'IAM & Keamanan'],
            'UI-016' => ['id' => 'UI-016', 'route' => '/buka/admin/access-inspector', 'title' => 'Inspektur Akses Efektif Teredaksi (RBAC + ABAC + RLS)', 'permission' => 'access.inspect', 'public' => false, 'nav_group' => 'IAM & Keamanan'],
            'UI-017' => ['id' => 'UI-017', 'route' => '/buka/admin/settings', 'title' => 'Aturan Domain Tujuan, Impor/Ekspor CSV, Kunci API & Kesehatan Sistem', 'permission' => 'ops.health.view', 'public' => false, 'nav_group' => 'Operasional'],
            'UI-018' => ['id' => 'UI-018', 'route' => '/buka/laporan', 'title' => 'Pelaporan Penyalahgunaan Publik & Triase Insiden', 'permission' => null, 'public' => true, 'nav_group' => null],
        ];
    }

    /**
     * Authorizes access to a specific Filament screen (`UI-001..018`) fail-closed (#11, #19).
     *
     * @return array{allowed: bool, http_status: int, reason_code: string, screen: array<string, mixed>}
     */
    public static function authorizeScreen(string $screenId, ?string $actorId, ?PDO $pdo = null): array
    {
        $screens = self::screens();
        if (!isset($screens[$screenId])) {
            if ($screenId === 'UI-010-DETAIL') {
                $screen = ['id' => 'UI-010-DETAIL', 'route' => '/buka/admin/links/{id}/analytics', 'title' => 'Analitik Detail Pengunjung & Telemetri Akses Tautan', 'permission' => 'analytics.view', 'public' => false, 'nav_group' => null];
            } elseif ($screenId === 'UI-018-ADMIN') {
                $screen = ['id' => 'UI-018-ADMIN', 'route' => '/buka/admin/reports', 'title' => 'Laporan Tautan Masuk & Triase Insiden', 'permission' => 'links.list_internal', 'public' => false, 'nav_group' => null];
            } else {
                return [
                    'allowed' => false,
                    'http_status' => 404,
                    'reason_code' => 'SCREEN_NOT_FOUND',
                    'screen' => [],
                ];
            }
        } else {
            $screen = $screens[$screenId];
        }

        if ($screen['public']) {
            return [
                'allowed' => true,
                'http_status' => 200,
                'reason_code' => 'PUBLIC_SCREEN',
                'screen' => $screen,
            ];
        }

        if ($actorId === null || $actorId === '') {
            return [
                'allowed' => false,
                'http_status' => 401,
                'reason_code' => 'UNAUTHENTICATED_ADMIN_ACCESS',
                'screen' => $screen,
            ];
        }

        $perm = (string) $screen['permission'];
        $eval = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: $perm,
            resourceType: 'filament_screen',
            resourceAttributes: ['screen_id' => $screenId],
            pdo: $pdo
        );

        return [
            'allowed' => $eval['permitted'],
            'http_status' => $eval['permitted'] ? 200 : $eval['http_status'],
            'reason_code' => $eval['reason_code'],
            'screen' => $screen,
        ];
    }

    /**
     * Returns authorized navigation items for the given actor (`#11`, `#19`).
     *
     * @return list<array<string, mixed>>
     */
    public static function authorizedNavigation(string $actorId, ?PDO $pdo = null): array
    {
        $items = [];
        foreach (self::screens() as $id => $screen) {
            if ($screen['public'] || $screen['nav_group'] === null) {
                continue;
            }
            $check = self::authorizeScreen($id, $actorId, $pdo);
            if ($check['allowed']) {
                $items[] = $screen;
            }
        }
        return $items;
    }

    /**
     * Renders WCAG 2.2 AA accessible Indonesian HTML for public and admin screens (#11, #20, #23).
     * Follows ahliweb/personal-coding design tokens and GovTech UI guidelines.
     *
     * Includes skip-to-main link (`#main-content`), `lang="id"`, landmarks (`header`, `nav`, `main`, `footer`),
     * explicit `<label for="...">`, `aria-live="polite"`, and high-contrast @@ORG_SHORT@@ styling.
     *
     * @param array<string, mixed> $context
     */
    public static function renderHtml(string $screenId, array $context = []): string
    {
        $screens = self::screens();
        $screen = $screens[$screenId] ?? (
            $screenId === 'UI-010-DETAIL'
                ? ['id' => 'UI-010-DETAIL', 'title' => 'Analitik Detail Pengunjung & Telemetri Akses Tautan', 'route' => '/buka/admin/links/{id}/analytics']
                : ($screenId === 'UI-018-ADMIN'
                    ? ['id' => 'UI-018-ADMIN', 'title' => 'Laporan Tautan Masuk & Triase Insiden', 'route' => '/buka/admin/reports']
                    : [
                        'id' => $screenId,
                        'title' => 'Layanan Tautan Pendek Resmi @@ORG_SHORT@@',
                        'route' => '/buka/',
                    ])
        );

        $title = htmlspecialchars((string) ($context['title'] ?? $screen['title']), ENT_QUOTES, 'UTF-8');
        $heading = htmlspecialchars((string) ($context['heading'] ?? $screen['title']), ENT_QUOTES, 'UTF-8');
        $message = htmlspecialchars((string) ($context['message'] ?? 'Layanan penyingkat tautan resmi @@ORG_NAME@@.'), ENT_QUOTES, 'UTF-8');
        $statusBanner = isset($context['status_banner'])
            ? sprintf('<div role="status" aria-live="polite" class="status-banner"><span class="banner-icon">ℹ️</span> <div>%s</div></div>', htmlspecialchars((string) $context['status_banner'], ENT_QUOTES, 'UTF-8'))
            : '';

        $isLoggedIn = !empty($context['logged_in']);
        $isAdminScreen = ($screenId !== 'UI-001' && str_starts_with($screen['route'], '/buka/admin'));
        $actorEmail = htmlspecialchars((string) ($context['actor_email'] ?? 'Staf @@ORG_SHORT@@'), ENT_QUOTES, 'UTF-8');

        $cfg = is_file(dirname(__DIR__, 2) . '/config/shortlink.php')
            ? (array) (require dirname(__DIR__, 2) . '/config/shortlink.php')
            : [];
        $appVersion = htmlspecialchars((string) ($cfg['app_version'] ?? self::APP_VERSION), ENT_QUOTES, 'UTF-8');

        $logoutHtml = $isLoggedIn
            ? '<form method="POST" action="/buka/admin/logout" style="display:inline;margin-left:0.5rem"><button type="submit" class="btn btn-danger btn-sm">Keluar Sesi</button></form>'
            : '';

        $mainHtml = isset($context['main_html']) ? (string) $context['main_html'] : null;

        $directoryRows = '';
        if (isset($context['public_links']) && is_array($context['public_links'])) {
            foreach ($context['public_links'] as $pl) {
                $s = htmlspecialchars((string) ($pl['slug'] ?? ''), ENT_QUOTES, 'UTF-8');
                $t = htmlspecialchars((string) ($pl['title'] ?? ''), ENT_QUOTES, 'UTF-8');
                $target = htmlspecialchars((string) ($pl['target_url'] ?? ''), ENT_QUOTES, 'UTF-8');
                $directoryRows .= sprintf(
                    '<div class="public-link-card">
                        <div class="public-link-info">
                            <span class="badge badge-success">Aktif Terverifikasi</span>
                            <h3 class="public-link-title">%s</h3>
                            <div class="public-link-slug"><a href="/buka/%s" class="mono"><strong>/buka/%s</strong></a></div>
                            <div class="public-link-target">Tujuan aman: <code>%s</code></div>
                        </div>
                        <div class="public-link-action" style="display:flex;gap:0.4rem;align-items:center;flex-wrap:wrap">
                            <a href="/buka/%s" class="btn btn-primary btn-sm">Buka Tautan ↗</a>
                            <a href="/buka/laporan?slug=%s" class="btn btn-outline btn-sm" style="color:var(--danger-600);border-color:#fca5a5" title="Laporkan kendala tautan ini">⚠️ Laporkan</a>
                        </div>
                    </div>',
                    $t,
                    $s,
                    $s,
                    $target,
                    $s,
                    $s
                );
            }
        }

        if ($directoryRows === '') {
            $directoryRows = '<div style="text-align:center;padding:2.5rem;background:#ffffff;border:1px solid var(--gray-200);border-radius:var(--radius-md);color:var(--gray-500)"><p style="margin:0 0 0.5rem 0;font-size:1rem;font-weight:600">Tidak ada tautan resmi yang cocok dengan pencarian.</p><p style="margin:0;font-size:0.85rem">Silakan periksa kembali kata kunci atau <a href="/buka/" style="color:var(--brand-700);font-weight:600">tampilkan seluruh direktori</a>.</p></div>';
        }

        $bodyHtml = $mainHtml ?? <<<BODY
        <div class="search-section">
            <form method="GET" action="/buka/" role="search" aria-label="Pencarian Direktori Tautan">
                <div class="form-group">
                    <label for="search-slug">Cari Tautan Resmi atau Slug</label>
                    <div class="search-input-wrap">
                        <input id="search-slug" name="q" type="search" placeholder="Contoh: panduan, formulir, jadwal...">
                        <button type="submit" class="btn btn-primary">Cari Tautan</button>
                    </div>
                </div>
            </form>
        </div>
        <div class="directory-list">
            <h2>Daftar Tautan Publik Resmi</h2>
            {$directoryRows}
        </div>
BODY;

        // Group definitions for admin sidebar
        $sidebarGroups = [
            'Utama' => ['label' => 'UTAMA', 'icon' => '📊'],
            'Tautan' => ['label' => 'MANAJEMEN TAUTAN', 'icon' => '🔗'],
            'Analitik' => ['label' => 'ANALITIK & PELAPORAN', 'icon' => '📈'],
            'Tata Kelola' => ['label' => 'TATA KELOLA & AUDIT', 'icon' => '📜'],
            'IAM & Keamanan' => ['label' => 'IAM & KEAMANAN', 'icon' => '🔐'],
            'Operasional' => ['label' => 'OPERASIONAL & SISTEM', 'icon' => '⚙️'],
        ];

        $screenIcons = [
            'UI-002' => '📊',
            'UI-003' => '🔗',
            'UI-004' => '➕',
            'UI-006' => '🛡️',
            'UI-010' => '📈',
            'UI-011' => '📜',
            'UI-012' => '👥',
            'UI-013' => '🏢',
            'UI-014' => '🔑',
            'UI-015' => '⚖️',
            'UI-016' => '🔍',
            'UI-017' => '⚙️',
        ];

        $sidebarNavHtml = '';
        foreach ($sidebarGroups as $groupKey => $gMeta) {
            $groupItems = '';
            foreach ($screens as $sid => $sc) {
                if ($sc['public'] || $sc['nav_group'] !== $groupKey) {
                    continue;
                }
                $isActive = ($sc['route'] === $screen['route']) ? ' active' : '';
                $ico = $screenIcons[$sid] ?? '📄';
                $groupItems .= sprintf(
                    '<li><a href="%s" class="sidebar-link%s"><span class="sidebar-link-icon" aria-hidden="true">%s</span> <span class="sidebar-link-text">%s</span></a></li>',
                    htmlspecialchars((string) $sc['route'], ENT_QUOTES, 'UTF-8'),
                    $isActive,
                    $ico,
                    htmlspecialchars((string) $sc['title'], ENT_QUOTES, 'UTF-8')
                );
            }
            if ($groupKey === 'Tautan') {
                $isRepActive = ($screen['route'] === '/buka/admin/reports') ? ' active' : '';
                $groupItems .= sprintf(
                    '<li><a href="%s" class="sidebar-link%s"><span class="sidebar-link-icon" aria-hidden="true">%s</span> <span class="sidebar-link-text">%s</span></a></li>',
                    '/buka/admin/reports',
                    $isRepActive,
                    '⚠️',
                    'Laporan Masuk & Triase'
                );
            }
            if ($groupItems !== '') {
                $sidebarNavHtml .= sprintf(
                    '<div class="sidebar-group"><div class="sidebar-group-title">%s</div><ul class="sidebar-group-items">%s</ul></div>',
                    htmlspecialchars($gMeta['label'], ENT_QUOTES, 'UTF-8'),
                    $groupItems
                );
            }
        }

        if ($isAdminScreen) {
            $contentHtml = <<<ADMIN
    <div class="admin-shell">
        <div class="sidebar-backdrop" id="sidebar-backdrop"></div>
        <aside class="admin-sidebar" id="admin-sidebar" role="navigation" aria-label="Menu Navigasi Panel Admin">
            <div class="sidebar-header">
                <a href="/buka/admin" class="sidebar-brand">
                    <div class="sidebar-logo">
                        <img src="@@LOGO_URL@@" alt="Logo @@ORG_SHORT@@" style="height:32px;width:auto">
                    </div>
                    <div>
                        <div class="sidebar-brand-title">Portal Tautan Resmi</div>
                        <div class="sidebar-brand-sub">@@ORG_SHORT@@</div>
                    </div>
                </a>
                <button type="button" class="sidebar-close-btn" id="sidebar-close" aria-label="Tutup Menu">✕</button>
            </div>
            <nav class="sidebar-nav">
                {$sidebarNavHtml}
            </nav>
            <div class="sidebar-footer">
                <div class="sidebar-user">
                    <div>
                        <div style="font-weight:650;color:#ffffff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px">{$actorEmail}</div>
                        <div style="font-size:0.7rem;color:#34d399">● Sesi Terverifikasi (MFA)</div>
                    </div>
                    <span class="badge badge-success" style="font-size:0.68rem;padding:0.15rem 0.45rem">Aktif</span>
                </div>
                <form method="POST" action="/buka/admin/logout" style="margin-top:0.35rem">
                    <button type="submit" class="btn btn-outline btn-sm" style="width:100%;color:#fca5a5;border-color:rgba(239,68,68,0.3);background:transparent">Keluar Sesi</button>
                </form>
                <div style="font-size:0.7rem;color:#94a3b8;display:flex;align-items:center;justify-content:space-between;padding-top:0.45rem;border-top:1px solid rgba(255,255,255,0.06);margin-top:0.25rem">
                    <span>AW Shortlink</span>
                    <span style="font-weight:600;color:#5eead4">v{$appVersion}</span>
                </div>
            </div>
        </aside>
        <div class="admin-main">
            <header class="admin-topbar">
                <div style="display:flex;align-items:center;gap:0.75rem">
                    <button type="button" class="sidebar-toggle-btn" id="sidebar-toggle" aria-label="Tampilkan / Sembunyikan Menu" title="Tampilkan / Sembunyikan Menu Navigasi">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <line x1="3" y1="12" x2="21" y2="12"></line>
                            <line x1="3" y1="6" x2="21" y2="6"></line>
                            <line x1="3" y1="18" x2="21" y2="18"></line>
                        </svg>
                    </button>
                    <div class="breadcrumb-wrap">
                        <span class="breadcrumb-root">Panel Admin</span>
                        <span class="breadcrumb-sep">/</span>
                        <span class="breadcrumb-current">{$heading}</span>
                    </div>
                </div>
                <div class="topbar-actions" style="display:flex;align-items:center;gap:0.5rem">
                    <a href="/buka/" target="_blank" class="btn btn-outline btn-sm topbar-btn-public">Beranda Publik ↗</a>
                    <a href="/buka/admin/links/create" class="btn btn-primary btn-sm topbar-btn-create">➕ Buat Tautan</a>
                </div>
            </header>
            <main id="main-content" class="admin-content" role="main" tabindex="-1">
                {$statusBanner}
                <section class="card" aria-labelledby="page-heading">
                    <div class="card-header">
                        <div>
                            <h1 id="page-heading" data-screen-id="{$screenId}">{$heading}</h1>
                            <p>{$message}</p>
                        </div>
                    </div>
                    {$bodyHtml}
                </section>
            </main>
            <footer role="contentinfo" class="app-footer">
                <div class="footer-copy">
                    <small>&copy; @@ORG_NAME@@. Dilindungi Kebijakan HTTPS, Fail-Closed PostgreSQL RLS &amp; Privasi Tanpa Pelacakan Individu.</small>
                </div>
                <div class="footer-version">
                    <span class="badge badge-version" title="Versi Aplikasi Resmi AW Shortlink">v{$appVersion}</span>
                </div>
            </footer>
        </div>
    </div>
ADMIN;
        } elseif ($screenId === 'UI-008') {
            $searchVal = htmlspecialchars((string) ($context['search_query'] ?? ''), ENT_QUOTES, 'UTF-8');
            $resetSearchBtn = $searchVal !== ''
                ? '<a href="/buka/" class="btn btn-outline search-reset-btn" title="Hapus Filter">✕ Reset</a>'
                : '';
            $linkCount = isset($context['total_rows']) ? (int) $context['total_rows'] : (is_array($context['public_links'] ?? null) ? count($context['public_links']) : 0);
            $linkCountBadge = sprintf('<span class="badge badge-success">● %d Tautan Aktif</span>', $linkCount);
            $paginationHtml = (string) ($context['pagination_html'] ?? '');

            $directoryCardsHtml = '';
            if (isset($context['public_links']) && is_array($context['public_links']) && count($context['public_links']) > 0) {
                foreach ($context['public_links'] as $pl) {
                    $s = htmlspecialchars((string) ($pl['slug'] ?? ''), ENT_QUOTES, 'UTF-8');
                    $t = htmlspecialchars((string) ($pl['title'] ?? ''), ENT_QUOTES, 'UTF-8');
                    $target = htmlspecialchars((string) ($pl['target_url'] ?? ''), ENT_QUOTES, 'UTF-8');
                    $directoryCardsHtml .= sprintf(
                        '<div class="public-link-card">
                            <div class="public-link-info">
                                <div class="public-link-meta">
                                    <span class="badge badge-success">● Aktif Terverifikasi</span>
                                    <span class="public-link-unit">@@ORG_SHORT@@</span>
                                </div>
                                <h3 class="public-link-title">%s</h3>
                                <div class="public-link-slug">
                                    <span class="public-link-prefix">@@PUBLIC_HOST@@</span><a href="/buka/%s" class="mono public-slug-highlight">/buka/%s</a>
                                </div>
                                <div class="public-link-target">
                                    <span class="target-title">Tujuan Resmi Aman:</span>
                                    <code class="target-address">%s</code>
                                </div>
                            </div>
                            <div class="public-link-action" style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">
                                <a href="/buka/%s" class="btn btn-primary" target="_blank" rel="noopener noreferrer">Buka Tautan ↗</a>
                                <a href="/buka/laporan?slug=%s" class="btn btn-outline" style="color:var(--danger-600);border-color:#fca5a5;padding:0.4rem 0.75rem;font-size:0.82rem;font-weight:600" title="Laporkan kendala atau penyalahgunaan tautan ini">⚠️ Laporkan</a>
                            </div>
                        </div>',
                        $t,
                        $s,
                        $s,
                        $target,
                        $s,
                        $s
                    );
                }
            } else {
                $directoryCardsHtml = '<div class="public-empty-state"><p class="empty-title">Tidak ada tautan resmi yang cocok dengan kata kunci pencarian.</p><p class="empty-sub">Silakan periksa kembali kata kunci atau <a href="/buka/" class="btn-link">tampilkan seluruh direktori resmi</a>.</p></div>';
            }

            $contentHtml = <<<PUBLIC_HOME
    <header class="topbar" role="banner">
        <div class="topbar-inner">
            <div class="brand-meta">
                <a href="/buka/" class="brand-logo-link" style="display:flex;align-items:center;gap:0.75rem;text-decoration:none">
                    <div class="brand-logo" style="background:transparent;border:none">
                        <img src="@@LOGO_URL@@" alt="Logo @@ORG_SHORT@@" style="height:34px;width:auto">
                    </div>
                    <div>
                        <div class="brand-subtitle">@@ORG_NAME@@</div>
                        <div class="brand-title">Portal Tautan Pendek Resmi (<code>/buka</code>) <span class="badge" style="font-size:0.72rem;background:rgba(15,118,110,0.1);color:var(--brand-700);border:1px solid rgba(15,118,110,0.25);margin-left:0.35rem;padding:0.15rem 0.5rem;border-radius:4px;font-weight:600;vertical-align:middle">v{$appVersion}</span></div>
                    </div>
                </a>
            </div>
            <nav class="main-nav" aria-label="Navigasi Utama">
                <a href="/buka/" class="nav-link active">Beranda Direktori</a>
                <a href="/buka/admin/links/create" class="btn btn-primary btn-sm" style="color:#ffffff">➕ Buat Tautan</a>
                <a href="/buka/laporan" class="nav-link">Laporkan Penyalahgunaan</a>
                <a href="/buka/admin" class="nav-link">Panel Admin Staf</a>{$logoutHtml}
            </nav>
        </div>
    </header>
    <main id="main-content" class="container public-home-container" role="main" tabindex="-1">
        {$statusBanner}
        <section class="hero-banner" aria-labelledby="page-heading">
            <div class="hero-top-row">
                <span class="hero-tag">Layanan Publik Resmi @@ORG_SHORT@@</span>
                {$linkCountBadge}
            </div>
            <h1 id="page-heading" data-screen-id="UI-008">Portal Penyingkat Tautan Resmi</h1>
            <p>Akses cepat, transparan, dan terverifikasi aman ke seluruh informasi layanan publik, kampanye, dan direktori resmi @@ORG_NAME@@.</p>
            <div class="hero-trust-row">
                <span class="trust-pill">🔒 Wajib Protokol HTTPS Resmi</span>
                <span class="trust-pill">⚡ QR Dinamis &amp; Anti-Phishing</span>
                <span class="trust-pill">🛡️ Privasi Terlindungi (Tanpa Pelacak PII)</span>
            </div>
        </section>

        <section class="public-search-card" aria-label="Pencarian Direktori Tautan">
            <form method="GET" action="/buka/" role="search">
                <div class="form-group" style="margin-bottom:0">
                    <label for="search-slug">Cari Tautan Resmi atau Slug</label>
                    <div class="search-input-wrap">
                        <div class="search-input-box">
                            <span class="search-box-icon">🔍</span>
                            <input id="search-slug" name="q" type="search" value="{$searchVal}" placeholder="Ketik kata kunci, contoh: panduan, formulir, jadwal, skm...">
                        </div>
                        <button type="submit" class="btn btn-primary search-submit-btn">Cari Tautan</button>
                        {$resetSearchBtn}
                    </div>
                </div>
            </form>
        </section>

        <section class="public-directory-section" aria-label="Direktori Tautan Publik Resmi">
            <div class="directory-section-header">
                <div>
                    <h2>Daftar Tautan Publik Resmi</h2>
                    <p>Seluruh tautan pendek resmi diverifikasi dengan kebijakan domain HTTPS dan perlindungan anti-phishing.</p>
                </div>
            </div>
            <div class="public-cards-list">
                {$directoryCardsHtml}
            </div>
            {$paginationHtml}
        </section>
    </main>
    <footer role="contentinfo" class="app-footer public-footer">
        <div class="footer-copy">
            <small>&copy; @@ORG_NAME@@. Dilindungi Kebijakan HTTPS, Fail-Closed PostgreSQL RLS &amp; Privasi Tanpa Pelacakan Individu.</small>
        </div>
        <div class="footer-version">
            <span class="badge badge-version" title="Versi Aplikasi Resmi AW Shortlink">v{$appVersion}</span>
        </div>
    </footer>
PUBLIC_HOME;
        } else {
            $isLapActive = ($screenId === 'UI-018') ? ' active' : '';
            $contentHtml = <<<PUBLIC
    <header class="topbar" role="banner">
        <div class="topbar-inner">
            <div class="brand-meta">
                <a href="/buka/" class="brand-logo-link" style="display:flex;align-items:center;gap:0.75rem;text-decoration:none">
                    <div class="brand-logo" style="background:transparent;border:none">
                        <img src="@@LOGO_URL@@" alt="Logo @@ORG_SHORT@@" style="height:34px;width:auto">
                    </div>
                    <div>
                        <div class="brand-subtitle">@@ORG_NAME@@</div>
                        <div class="brand-title">Portal Tautan Pendek Resmi (<code>/buka</code>) <span class="badge" style="font-size:0.72rem;background:rgba(15,118,110,0.1);color:var(--brand-700);border:1px solid rgba(15,118,110,0.25);margin-left:0.35rem;padding:0.15rem 0.5rem;border-radius:4px;font-weight:600;vertical-align:middle">v{$appVersion}</span></div>
                    </div>
                </a>
            </div>
            <nav class="main-nav" aria-label="Navigasi Utama">
                <a href="/buka/" class="nav-link">Beranda Direktori</a>
                <a href="/buka/admin/links/create" class="btn btn-primary btn-sm" style="color:#ffffff;margin-right:0.25rem">➕ Buat Tautan Pendek</a>
                <a href="/buka/laporan" class="nav-link{$isLapActive}">Laporkan Penyalahgunaan</a>
                <a href="/buka/admin" class="nav-link">Panel Admin Staf</a>{$logoutHtml}
            </nav>
        </div>
    </header>
    <main id="main-content" class="container" role="main" tabindex="-1">
        {$statusBanner}
        <section class="card" aria-labelledby="page-heading">
            <div class="card-header">
                <div>
                    <h1 id="page-heading" data-screen-id="{$screenId}">{$heading}</h1>
                    <p>{$message}</p>
                </div>
            </div>
            {$bodyHtml}
        </section>
    </main>
    <footer role="contentinfo" class="app-footer public-footer">
        <div class="footer-copy">
            <small>&copy; @@ORG_NAME@@. Dilindungi Kebijakan HTTPS, Fail-Closed PostgreSQL RLS &amp; Privasi Tanpa Pelacakan Individu.</small>
        </div>
        <div class="footer-version">
            <span class="badge badge-version" title="Versi Aplikasi Resmi AW Shortlink">v{$appVersion}</span>
        </div>
    </footer>
PUBLIC;
        }

        return <<<HTML
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{$title} — Portal Tautan Resmi @@ORG_SHORT@@</title>
    <meta name="description" content="Layanan penyingkat tautan resmi @@ORG_NAME@@. Terverifikasi aman, terlindungi kebijakan domain HTTPS resmi, dan bebas phishing.">

    <!-- Favicon -->
    <link rel="icon" type="image/png" href="@@LOGO_URL@@">
    <link rel="shortcut icon" type="image/png" href="@@LOGO_URL@@">
    <link rel="apple-touch-icon" href="@@LOGO_URL@@">

    <!-- Open Graph / Facebook / WhatsApp / Telegram / LinkedIn Share Preview -->
    <meta property="og:type" content="website">
    <meta property="og:site_name" content="@@ORG_NAME@@">
    <meta property="og:title" content="{$title} — Portal Tautan Resmi @@ORG_SHORT@@">
    <meta property="og:description" content="Layanan penyingkat tautan resmi @@ORG_NAME@@. Terverifikasi aman, terlindungi kebijakan domain HTTPS resmi, dan bebas phishing.">
    <meta property="og:image" content="@@LOGO_URL@@">
    <meta property="og:image:width" content="512">
    <meta property="og:image:height" content="512">
    <meta property="og:image:alt" content="Logo @@ORG_NAME@@">
    <meta property="og:url" content="@@PUBLIC_BASE_URL@@/">

    <!-- Twitter Card -->
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="{$title} — Portal Tautan Resmi @@ORG_SHORT@@">
    <meta name="twitter:description" content="Layanan penyingkat tautan resmi @@ORG_NAME@@.">
    <meta name="twitter:image" content="@@LOGO_URL@@">
    <style>
        :root {
            --brand-50:  #effaf8;
            --brand-100: #d5f2ec;
            --brand-500: #14907f;
            --brand-600: #0f766e;
            --brand-700: #115e59;
            --brand-900: #0b3b38;
            --navy-800:  #0b4f6c;
            --navy-900:  #08384d;
            --gray-0:    #ffffff;
            --gray-50:   #f8fafc;
            --gray-100:  #f1f5f9;
            --gray-200:  #e2e8f0;
            --gray-300:  #cbd5e1;
            --gray-500:  #64748b;
            --gray-600:  #475569;
            --gray-700:  #334155;
            --gray-800:  #1e293b;
            --gray-900:  #0f172a;
            --success-50: #ecfdf3; --success-600: #15803d; --success-700: #166534;
            --warning-50: #fffbeb; --warning-600: #b45309; --warning-800: #92400e;
            --danger-50:  #fef2f2; --danger-600:  #b91c1c; --danger-700:  #991b1b;
            --font-sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            --radius-sm: 6px;
            --radius-md: 10px;
            --radius-lg: 14px;
            --shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(15, 23, 42, 0.08), 0 2px 4px -2px rgba(15, 23, 42, 0.05);
            --shadow-lg: 0 10px 15px -3px rgba(15, 23, 42, 0.1), 0 4px 6px -4px rgba(15, 23, 42, 0.05);
            --focus-ring: 0 0 0 3px #ffffff, 0 0 0 5px #0f766e;
        }
        *, *::before, *::after { box-sizing: border-box; }
        html, body { margin: 0; padding: 0; width: 100%; max-width: 100vw; overflow-x: hidden; font-family: var(--font-sans); background: var(--gray-50); color: var(--gray-800); line-height: 1.55; }
        a { color: var(--brand-600); text-decoration: none; }
        a:hover { color: var(--brand-700); text-decoration: underline; }
        :focus-visible { outline: none; box-shadow: var(--focus-ring); }
        .skip-link { position: absolute; left: -9999px; top: 0; background: var(--brand-600); color: #FFF; padding: 0.75rem 1.25rem; z-index: 1000; font-weight: 600; border-radius: 0 0 8px 0; }
        .skip-link:focus { left: 0; top: 0; }
        
        /* Layout Topbar */
        .topbar { background: var(--navy-800); color: #ffffff; border-bottom: 1px solid var(--navy-900); padding: 0.75rem 1.5rem; position: sticky; top: 0; z-index: 50; box-shadow: 0 2px 4px rgba(0,0,0,0.06); }
        .topbar-inner { max-width: 1280px; margin: 0 auto; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 1rem; }
        .brand-meta { display: flex; align-items: center; gap: 0.75rem; }
        .brand-logo { width: 38px; height: 38px; background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.2); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; }
        .brand-title { font-size: 0.95rem; font-weight: 700; color: #ffffff; letter-spacing: -0.01em; margin: 0; }
        .brand-subtitle { font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin: 0; }
        
        .main-nav { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
        .nav-link { color: #cbd5e1; font-size: 0.82rem; font-weight: 500; padding: 0.4rem 0.75rem; border-radius: var(--radius-sm); transition: all 0.15s; }
        .nav-link:hover { color: #ffffff; background: rgba(255,255,255,0.1); text-decoration: none; }
        .nav-link.active { color: #ffffff; background: var(--brand-600); font-weight: 600; text-decoration: none; }

        .container { max-width: 1280px; margin: 0 auto; padding: 1.75rem 1.5rem; min-height: calc(100vh - 140px); }
        .card { background: var(--gray-0); border: 1px solid var(--gray-200); border-radius: var(--radius-lg); padding: 1.75rem; box-shadow: var(--shadow-sm); margin-bottom: 1.5rem; }
        .card-header { border-bottom: 1px solid var(--gray-100); padding-bottom: 1rem; margin-bottom: 1.25rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.75rem; }
        
        h1 { font-size: 1.5rem; font-weight: 750; color: var(--gray-900); margin: 0 0 0.4rem 0; letter-spacing: -0.02em; }
        h2 { font-size: 1.15rem; font-weight: 700; color: var(--gray-900); margin: 0 0 0.5rem 0; }
        h3 { font-size: 0.98rem; font-weight: 700; color: var(--gray-900); margin: 0 0 0.25rem 0; }
        p { margin: 0 0 0.75rem 0; color: var(--gray-600); font-size: 0.9rem; }
        
        /* Stats KPI Grid */
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
        .stat-card { background: var(--gray-0); border: 1px solid var(--gray-200); border-radius: var(--radius-md); padding: 1.25rem; box-shadow: var(--shadow-sm); position: relative; overflow: hidden; }
        .stat-card::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--brand-600); }
        .stat-num { font-size: 1.85rem; font-weight: 800; color: var(--gray-900); line-height: 1.1; margin: 0.25rem 0; }
        .stat-label { font-size: 0.75rem; font-weight: 650; text-transform: uppercase; letter-spacing: 0.05em; color: var(--gray-500); margin: 0; }
        .stat-hint { font-size: 0.75rem; color: var(--brand-600); margin-top: 0.35rem; font-weight: 500; }
        
        /* Dashboard Charts */
        .dashboard-chart-grid { display: grid; grid-template-columns: 1.45fr 1fr; gap: 1.25rem; }
        .chart-card { background: var(--gray-0); border: 1px solid var(--gray-200); border-radius: var(--radius-md); padding: 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,0.03); position: relative; }
        .chart-card-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.85rem; gap: 0.5rem; flex-wrap: wrap; }
        .chart-title { font-size: 0.95rem; font-weight: 700; color: var(--gray-900); }
        .chart-sub { font-size: 0.75rem; color: var(--gray-500); margin-top: 0.15rem; }
        .chart-legend { display: flex; gap: 0.75rem; font-size: 0.74rem; align-items: center; }
        .chart-legend-item { display: flex; align-items: center; gap: 0.35rem; color: var(--gray-600); font-weight: 500; }
        .chart-point circle { transition: r 0.15s ease, stroke-width 0.15s ease; cursor: pointer; }
        .chart-point:hover circle { r: 6.5; stroke-width: 3.5; fill: #0d9488; }
        @media (max-width: 960px) { .dashboard-chart-grid { grid-template-columns: 1fr; } }
        
        /* Navigation Hub Grid */
        .hub-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; margin-top: 1rem; }
        .hub-card { display: block; background: var(--gray-0); border: 1px solid var(--gray-200); border-radius: var(--radius-md); padding: 1rem 1.25rem; transition: all 0.2s; text-decoration: none; color: inherit; }
        .hub-card:hover { border-color: var(--brand-500); box-shadow: var(--shadow-md); transform: translateY(-2px); text-decoration: none; }
        .hub-group { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--brand-600); margin-bottom: 0.25rem; }
        .hub-title { font-size: 0.95rem; font-weight: 700; color: var(--gray-900); margin: 0 0 0.25rem 0; }
        .hub-desc { font-size: 0.8rem; color: var(--gray-500); margin: 0; line-height: 1.4; }
        
        /* Tables */
        .table-wrap { overflow-x: auto; border: 1px solid var(--gray-200); border-radius: var(--radius-md); margin: 1rem 0; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }
        th { background: var(--gray-100); color: var(--gray-700); font-weight: 650; padding: 0.75rem 1rem; border-bottom: 1px solid var(--gray-200); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.03em; }
        td { padding: 0.85rem 1rem; border-bottom: 1px solid var(--gray-200); color: var(--gray-800); }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: var(--brand-50); }
        .mono { font-family: var(--font-mono); font-size: 0.88em; font-weight: 600; color: var(--brand-900); }
        
        /* Badges */
        .badge { display: inline-flex; align-items: center; gap: 0.35rem; padding: 0.25rem 0.65rem; border-radius: 999px; font-size: 0.75rem; font-weight: 650; }
        .badge::before { content: ""; width: 6px; height: 6px; border-radius: 50%; }
        .badge-success { background: var(--success-50); color: var(--success-700); border: 1px solid #bbf7d0; }
        .badge-success::before { background: var(--success-600); }
        .badge-warning { background: var(--warning-50); color: var(--warning-800); border: 1px solid #fde68a; }
        .badge-warning::before { background: var(--warning-600); }
        .badge-danger { background: var(--danger-50); color: var(--danger-700); border: 1px solid #fecaca; }
        .badge-danger::before { background: var(--danger-600); }
        
        /* Buttons */
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem; min-height: 40px; padding: 0.55rem 1.25rem; font-size: 0.85rem; font-weight: 600; border-radius: var(--radius-sm); border: none; cursor: pointer; transition: all 0.15s; text-decoration: none; }
        .btn-primary { background: var(--brand-600); color: #ffffff; }
        .btn-primary:hover { background: var(--brand-700); text-decoration: none; color: #ffffff; box-shadow: var(--shadow-sm); }
        .btn-outline { background: #ffffff; border: 1px solid var(--gray-300); color: var(--gray-700); }
        .btn-outline:hover { background: var(--gray-50); border-color: var(--gray-400); text-decoration: none; }
        .btn-danger { background: var(--danger-600); color: #ffffff; }
        .btn-danger:hover { background: var(--danger-700); text-decoration: none; color: #ffffff; }
        .btn-outline-danger { background: #ffffff; border: 1px solid #fca5a5; color: var(--danger-600); }
        .btn-outline-danger:hover { background: #fef2f2; border-color: var(--danger-600); text-decoration: none; color: var(--danger-700); }
        .btn-sm { min-height: 32px; padding: 0.3rem 0.75rem; font-size: 0.78rem; border-radius: 4px; }
        
        /* Category Selection Cards */
        .category-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 0.75rem; margin-top: 0.5rem; }
        .category-card { display: flex; align-items: flex-start; gap: 0.75rem; padding: 0.85rem 1rem; border: 1.5px solid var(--gray-300); border-radius: var(--radius-md); background: #ffffff; cursor: pointer; transition: all 0.15s ease-in-out; }
        .category-card:hover { border-color: var(--brand-500); background: var(--brand-50); }
        .category-card:has(input:checked) { border-color: var(--brand-600); background: #f0fdfa; box-shadow: 0 0 0 1px var(--brand-600); }
        .category-card input[type="radio"] { margin-top: 0.25rem; flex-shrink: 0; }
        .category-card-body { flex: 1; min-width: 0; }
        .category-card-title { font-weight: 700; font-size: 0.88rem; color: var(--gray-900); margin-bottom: 0.2rem; }
        .category-card-desc { font-size: 0.78rem; color: var(--gray-600); line-height: 1.4; }
        
        /* Form Controls */
        .form-group { margin-bottom: 1.25rem; }
        label { display: block; font-size: 0.82rem; font-weight: 650; color: var(--gray-800); margin-bottom: 0.4rem; }
        input[type="text"], input[type="email"], input[type="password"], input[type="search"], input[type="url"], input[type="tel"], input[type="number"], select, textarea {
            width: 100%; min-height: 42px; padding: 0.6rem 0.85rem; border: 1px solid var(--gray-300); border-radius: var(--radius-sm); font-size: 0.9rem; font-family: inherit; background: #ffffff; color: var(--gray-900); transition: border-color 0.15s; box-sizing: border-box;
        }
        input:focus, select:focus, textarea:focus { border-color: var(--brand-600); outline: none; box-shadow: 0 0 0 3px rgba(15, 118, 110, 0.15); }
        
        /* Login Card */
        .login-wrap { max-width: 440px; margin: 2rem auto; }
        .login-card { background: #ffffff; border: 1px solid var(--gray-200); border-radius: var(--radius-lg); padding: 2rem; box-shadow: var(--shadow-lg); }
        .login-header { text-align: center; margin-bottom: 1.5rem; }
        .login-logo { width: 52px; height: 52px; background: var(--navy-800); color: #ffffff; border-radius: 12px; display: inline-flex; align-items: center; justify-content: center; font-size: 1.6rem; margin-bottom: 0.75rem; box-shadow: var(--shadow-md); }
        
        /* Status Banner */
        .status-banner { background: var(--brand-50); border: 1px solid var(--brand-200); color: var(--brand-900); padding: 0.85rem 1.25rem; border-radius: var(--radius-md); font-size: 0.85rem; font-weight: 500; margin-bottom: 1.25rem; display: flex; align-items: center; gap: 0.5rem; }
        .banner-icon { font-size: 1.2rem; }
        
        /* Admin Layout with Left Sidebar */
        .admin-shell { display: flex; min-height: 100vh; background: var(--gray-50); position: relative; }
        .admin-sidebar { width: 280px; flex-shrink: 0; background: var(--navy-900); color: #cbd5e1; display: flex; flex-direction: column; border-right: 1px solid rgba(255,255,255,0.08); position: sticky; top: 0; height: 100vh; max-height: 100vh; overflow: hidden; z-index: 40; transition: margin-left 0.25s cubic-bezier(0.4, 0, 0.2, 1), transform 0.25s cubic-bezier(0.4, 0, 0.2, 1); }
        .sidebar-header { padding: 0.85rem 1.15rem 0.75rem; border-bottom: 1px solid rgba(255,255,255,0.08); display: flex; align-items: center; justify-content: space-between; flex-shrink: 0; }
        .sidebar-brand { display: flex; align-items: center; gap: 0.75rem; text-decoration: none; color: #ffffff; min-width: 0; }
        .sidebar-logo { width: 34px; height: 34px; background: rgba(255,255,255,0.12); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 1.1rem; flex-shrink: 0; }
        .sidebar-brand-title { font-size: 0.95rem; font-weight: 750; color: #ffffff; margin: 0; line-height: 1.2; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .sidebar-brand-sub { font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.04em; margin: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .sidebar-close-btn { display: none; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); color: #ffffff; font-size: 1.1rem; width: 32px; height: 32px; border-radius: 6px; cursor: pointer; align-items: center; justify-content: center; flex-shrink: 0; transition: all 0.15s; }
        .sidebar-close-btn:hover { background: rgba(255,255,255,0.25); color: #ffffff; }

        .sidebar-nav { padding: 0.65rem 0.6rem; flex: 1; min-height: 0; display: flex; flex-direction: column; gap: 0.65rem; overflow-y: auto; overflow-x: hidden; scrollbar-width: thin; scrollbar-color: rgba(255,255,255,0.12) transparent; }
        .sidebar-nav::-webkit-scrollbar { width: 4px; }
        .sidebar-nav::-webkit-scrollbar-track { background: transparent; }
        .sidebar-nav::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 4px; }
        .sidebar-nav::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.3); }

        .sidebar-group-title { font-size: 0.65rem; font-weight: 750; text-transform: uppercase; letter-spacing: 0.06em; color: #64748b; padding: 0 0.5rem 0.2rem; }
        .sidebar-group-items { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.12rem; }
        .sidebar-link { display: flex; align-items: center; gap: 0.6rem; padding: 0.42rem 0.65rem; color: #94a3b8; font-size: 0.8rem; font-weight: 500; border-radius: var(--radius-sm); text-decoration: none; transition: all 0.15s; }
        .sidebar-link:hover { color: #ffffff; background: rgba(255,255,255,0.08); text-decoration: none; }
        .sidebar-link.active { color: #ffffff; background: var(--brand-600); font-weight: 600; box-shadow: 0 1px 3px rgba(0,0,0,0.2); }
        .sidebar-link-icon { font-size: 0.95rem; width: 1.25rem; text-align: center; }
        .sidebar-link-text { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .sidebar-footer { padding: 0.75rem 0.85rem; border-top: 1px solid rgba(255,255,255,0.08); background: rgba(0,0,0,0.2); display: flex; flex-direction: column; gap: 0.45rem; flex-shrink: 0; }
        .sidebar-user { font-size: 0.76rem; color: #e2e8f0; display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }

        .admin-main { flex: 1; min-width: 0; display: flex; flex-direction: column; min-height: 100vh; transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1); }
        .admin-topbar { background: #ffffff; border-bottom: 1px solid var(--gray-200); padding: 0.75rem 1.5rem; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 30; gap: 0.75rem; box-shadow: 0 1px 2px rgba(0,0,0,0.02); }
        .admin-content { padding: 1.75rem; flex: 1; max-width: 1400px; width: 100%; margin: 0 auto; box-sizing: border-box; }

        /* Sidebar Toggle Button */
        .sidebar-toggle-btn { display: inline-flex; align-items: center; justify-content: center; width: 38px; height: 38px; border-radius: var(--radius-sm); border: 1px solid var(--gray-300); background: #ffffff; color: var(--gray-700); cursor: pointer; transition: all 0.15s; flex-shrink: 0; padding: 0; }
        .sidebar-toggle-btn:hover { background: var(--gray-100); border-color: var(--gray-400); color: var(--brand-700); }
        .sidebar-toggle-btn:focus-visible { outline: 2px solid var(--brand-600); outline-offset: 2px; }

        .breadcrumb-wrap { display: flex; align-items: center; gap: 0.5rem; min-width: 0; }
        .breadcrumb-root { font-size: 0.85rem; color: var(--gray-500); font-weight: 500; white-space: nowrap; }
        .breadcrumb-sep { color: var(--gray-300); }
        .breadcrumb-current { font-size: 0.85rem; color: var(--gray-800); font-weight: 650; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

        /* Desktop Sidebar Collapsed State */
        @media (min-width: 901px) {
            .admin-shell.sidebar-collapsed .admin-sidebar {
                margin-left: -280px;
            }
        }

        /* Mobile & Tablet Drawer (< 900px) */
        @media (max-width: 900px) {
            .sidebar-close-btn { display: inline-flex; }
            .admin-sidebar {
                position: fixed !important;
                top: 0;
                left: 0;
                bottom: 0;
                width: 280px;
                max-width: 85vw;
                height: 100vh;
                z-index: 1000;
                transform: translateX(-100%);
                box-shadow: 0 0 35px rgba(0,0,0,0.5);
            }
            .admin-shell.sidebar-mobile-open .admin-sidebar {
                transform: translateX(0);
            }
            .sidebar-backdrop {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(15, 23, 42, 0.65);
                backdrop-filter: blur(2px);
                z-index: 990;
            }
            .admin-shell.sidebar-mobile-open .sidebar-backdrop {
                display: block;
            }
            .breadcrumb-root, .breadcrumb-sep {
                display: none;
            }
        }

        /* Public Hero Banner */
        .public-home-container { max-width: 1100px; margin: 0 auto; padding: 1.5rem 1rem 3rem 1rem; min-height: calc(100vh - 140px); width: 100%; box-sizing: border-box; }
        .hero-banner { background: linear-gradient(135deg, var(--navy-900) 0%, var(--navy-800) 50%, var(--brand-700) 100%); color: #ffffff; border-radius: var(--radius-lg); padding: 2.25rem 2rem; margin-bottom: 1.5rem; box-shadow: var(--shadow-md); position: relative; overflow: hidden; border: 1px solid rgba(255, 255, 255, 0.1); }
        .hero-top-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 0.85rem; }
        .hero-tag { display: inline-block; background: rgba(255,255,255,0.15); border: 1px solid rgba(255,255,255,0.25); color: #ffffff; padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.74rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
        .hero-banner h1 { font-size: 1.7rem; font-weight: 800; color: #ffffff; margin: 0 0 0.65rem 0; letter-spacing: -0.02em; line-height: 1.25; }
        .hero-banner h2 { font-size: 1.5rem; font-weight: 800; color: #ffffff; margin: 0 0 0.5rem 0; letter-spacing: -0.02em; }
        .hero-banner p { color: #e2e8f0; font-size: 0.95rem; max-width: 800px; margin: 0 0 1rem 0; line-height: 1.55; }
        .hero-actions { display: flex; gap: 0.75rem; flex-wrap: wrap; }
        .hero-trust-row { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.75rem; }
        .trust-pill { display: inline-flex; align-items: center; gap: 0.35rem; background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.2); color: #f1f5f9; font-size: 0.76rem; font-weight: 600; padding: 0.3rem 0.65rem; border-radius: 999px; }

        /* Public Search Card */
        .public-search-card { background: #ffffff; border: 1px solid var(--gray-200); border-radius: var(--radius-lg); padding: 1.25rem 1.5rem; margin-bottom: 1.75rem; box-shadow: var(--shadow-sm); box-sizing: border-box; width: 100%; }
        .public-search-card label { font-size: 0.88rem; font-weight: 700; color: var(--gray-800); margin-bottom: 0.5rem; display: block; }
        .search-input-wrap { display: flex; gap: 0.6rem; align-items: stretch; width: 100%; box-sizing: border-box; }
        .search-input-box { position: relative; flex: 1; display: flex; align-items: center; min-width: 0; }
        .search-box-icon { position: absolute; left: 0.85rem; pointer-events: none; font-size: 0.95rem; opacity: 0.6; }
        .search-input-box input { padding-left: 2.35rem !important; width: 100%; }
        .search-submit-btn { white-space: nowrap; padding: 0.6rem 1.5rem; }
        .search-reset-btn { white-space: nowrap; }

        /* Public Directory Section */
        .public-directory-section { margin-top: 0.5rem; width: 100%; box-sizing: border-box; }
        .directory-section-header { margin-bottom: 1.25rem; }
        .directory-section-header h2 { font-size: 1.25rem; font-weight: 750; color: var(--gray-900); margin: 0 0 0.25rem 0; }
        .directory-section-header p { font-size: 0.88rem; color: var(--gray-600); margin: 0; }
        .public-cards-list { display: flex; flex-direction: column; gap: 1rem; width: 100%; box-sizing: border-box; }

        /* Public Link Cards */
        .public-link-card { background: #ffffff; border: 1px solid var(--gray-200); border-radius: var(--radius-md); padding: 1.25rem 1.5rem; display: flex; justify-content: space-between; align-items: center; gap: 1.25rem; box-shadow: var(--shadow-sm); transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); box-sizing: border-box; width: 100%; overflow: hidden; }
        .public-link-card:hover { border-color: var(--brand-500); box-shadow: var(--shadow-md); transform: translateY(-1px); }
        .public-link-info { flex: 1; min-width: 0; }
        .public-link-meta { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.35rem; }
        .public-link-unit { font-size: 0.72rem; font-weight: 650; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.04em; }
        .public-link-title { font-size: 1.15rem; font-weight: 750; color: var(--gray-900); margin: 0 0 0.35rem 0; line-height: 1.35; word-break: break-word; }
        .public-link-slug { display: flex; align-items: center; flex-wrap: wrap; gap: 0.25rem; font-size: 0.88rem; margin-bottom: 0.5rem; }
        .public-link-prefix { color: var(--gray-500); }
        .public-slug-highlight { font-weight: 750; color: var(--brand-700); word-break: break-all; }
        .public-link-target { background: var(--gray-50); border: 1px solid var(--gray-200); border-radius: var(--radius-sm); padding: 0.5rem 0.75rem; font-size: 0.78rem; width: 100%; box-sizing: border-box; }
        .target-title { display: block; font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--gray-500); margin-bottom: 0.2rem; }
        .target-address { font-family: var(--font-mono); color: var(--navy-900); word-break: break-all; overflow-wrap: anywhere; white-space: normal; display: block; font-size: 0.8rem; line-height: 1.45; }
        .public-link-action { flex-shrink: 0; }
        .public-link-action .btn { min-width: 140px; white-space: nowrap; }

        .public-empty-state { text-align: center; padding: 3rem 1.5rem; background: #ffffff; border: 1px solid var(--gray-200); border-radius: var(--radius-md); color: var(--gray-600); }
        .empty-title { font-size: 1.05rem; font-weight: 700; color: var(--gray-800); margin-bottom: 0.5rem; }
        .empty-sub { font-size: 0.88rem; color: var(--gray-500); }
        .btn-link { color: var(--brand-700); font-weight: 650; text-decoration: underline; }

        /* Pagination & Filters */
        .filter-card { background: #ffffff; border: 1px solid var(--gray-200); border-radius: var(--radius-md); padding: 1rem 1.25rem; margin-bottom: 1.25rem; }
        .filter-row { display: flex; gap: 0.75rem; align-items: flex-end; flex-wrap: wrap; }
        .filter-col { flex: 1; min-width: 200px; }
        .pagination { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; margin-top: 1.25rem; padding-top: 1rem; border-top: 1px solid var(--gray-200); }
        .pagination-info { font-size: 0.82rem; color: var(--gray-600); }
        .pagination-controls { display: flex; align-items: center; gap: 0.35rem; }
        .page-btn { display: inline-flex; align-items: center; justify-content: center; min-width: 34px; height: 34px; padding: 0 0.65rem; font-size: 0.82rem; font-weight: 600; border-radius: var(--radius-sm); border: 1px solid var(--gray-300); background: #ffffff; color: var(--gray-700); text-decoration: none; }
        .page-btn:hover { background: var(--gray-50); border-color: var(--gray-400); text-decoration: none; }
        .page-btn.active { background: var(--brand-600); border-color: var(--brand-600); color: #ffffff; font-weight: 700; }
        .page-btn.disabled { opacity: 0.45; pointer-events: none; background: var(--gray-100); }

        /* QR Code Preview & Download Card */
        .qr-preview-box {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.25rem;
            background: #ffffff;
            border: 1px solid var(--gray-200);
            border-radius: var(--radius-md);
            margin: 0 auto 1.25rem auto;
            width: 280px;
            height: 280px;
            box-sizing: border-box;
            box-shadow: inset 0 0 0 1px rgba(0,0,0,0.03);
        }
        .qr-svg {
            width: 100% !important;
            max-width: 250px !important;
            height: auto !important;
            display: block !important;
            margin: 0 auto !important;
        }
        
        /* Footer */
        .app-footer {
            border-top: 1px solid var(--gray-200);
            background: #ffffff;
            padding: 1.15rem 1.75rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.75rem;
            font-size: 0.75rem;
            color: var(--gray-500);
        }
        .public-footer {
            max-width: 1200px;
            margin: 2rem auto 1.5rem auto;
            border-radius: var(--radius-md);
            box-shadow: 0 1px 3px rgba(0,0,0,0.03);
            border: 1px solid var(--gray-200);
        }
        .footer-copy { flex: 1; min-width: 250px; text-align: left; }
        .footer-version { flex-shrink: 0; text-align: right; }
        .badge-version {
            display: inline-block;
            font-size: 0.72rem;
            font-weight: 650;
            color: var(--gray-600);
            background: var(--gray-100);
            border: 1px solid var(--gray-300);
            padding: 0.2rem 0.55rem;
            border-radius: var(--radius-sm);
            letter-spacing: 0.02em;
        }
        @media (max-width: 640px) {
            .app-footer { flex-direction: column; text-align: center; gap: 0.5rem; padding: 1rem; }
            .footer-copy, .footer-version { text-align: center; width: 100%; }
        }
        footer { border-top: 1px solid var(--gray-200); background: #ffffff; padding: 1.25rem 1.5rem; text-align: center; font-size: 0.75rem; color: var(--gray-500); }
        
        /* Tablet & Mobile Breakpoints (<= 768px down to 360px) */
        @media (max-width: 768px) {
            .topbar { padding: 0.65rem 0.85rem; }
            .topbar-inner { flex-direction: column; align-items: stretch; gap: 0.65rem; }
            .brand-meta { gap: 0.6rem; width: 100%; justify-content: flex-start; }
            .brand-logo img { height: 28px !important; }
            .brand-title { font-size: 0.82rem; line-height: 1.25; }
            .brand-subtitle { font-size: 0.65rem; }
            .main-nav { justify-content: flex-start; gap: 0.35rem; flex-wrap: wrap; width: 100%; }
            .main-nav .nav-link, .main-nav .btn { font-size: 0.75rem; padding: 0.35rem 0.6rem; white-space: nowrap; }
            
            .admin-topbar { padding: 0.6rem 0.85rem; gap: 0.5rem; }
            .breadcrumb-current { font-size: 0.82rem; max-width: 135px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: inline-block; }
            .topbar-actions .btn { font-size: 0.75rem; padding: 0.35rem 0.6rem; min-height: 32px; }
            .topbar-btn-public { display: none; }
            
            .container, .admin-content { padding: 0.85rem 0.65rem; width: 100%; max-width: 100%; box-sizing: border-box; }
            .public-home-container { padding: 0.85rem 0.65rem 2rem 0.65rem; }
            .card { padding: 1rem 0.75rem; border-radius: var(--radius-md); max-width: 100%; box-sizing: border-box; }
            .card-header { padding-bottom: 0.65rem; margin-bottom: 0.85rem; }
            h1#page-heading { font-size: 1.15rem; }
            
            .table-wrap { margin: 0.75rem 0; border-radius: var(--radius-sm); width: 100%; max-width: 100%; }
            table { min-width: 520px; font-size: 0.78rem; }
            th, td { padding: 0.6rem 0.5rem; }
            
            .filter-card { padding: 0.85rem; }
            .filter-row { flex-direction: column; align-items: stretch; gap: 0.65rem; }
            .filter-col { min-width: 100%; width: 100%; }
            .pagination { flex-direction: column; align-items: center; gap: 0.65rem; }
            
            [style*="grid-template-columns"] { grid-template-columns: 1fr !important; }
            .hero-banner { padding: 1.5rem 1rem; border-radius: var(--radius-md); margin-bottom: 1rem; }
            .hero-banner h1 { font-size: 1.25rem; line-height: 1.3; }
            .hero-banner h2 { font-size: 1.25rem; }
            .hero-banner p { font-size: 0.85rem; margin-bottom: 0.85rem; }
            .hero-actions { flex-direction: column; }
            .hero-actions .btn { width: 100%; }
            .hero-trust-row { flex-direction: column; align-items: flex-start; gap: 0.35rem; }
            .trust-pill { font-size: 0.72rem; padding: 0.25rem 0.55rem; }

            .public-search-card { padding: 1rem 0.85rem; margin-bottom: 1.25rem; border-radius: var(--radius-md); }
            .search-input-wrap { flex-direction: column; gap: 0.5rem; }
            .search-submit-btn, .search-reset-btn { width: 100%; min-height: 42px; }

            .public-link-card { flex-direction: column; align-items: stretch; padding: 1rem 0.85rem; gap: 0.85rem; border-radius: var(--radius-md); }
            .public-link-title { font-size: 1.02rem; }
            .public-link-slug { font-size: 0.82rem; }
            .public-link-action { width: 100%; }
            .public-link-action .btn { width: 100%; min-height: 42px; }
        }

        /* 360px - 480px Smartphone adjustments */
        @media (max-width: 480px) {
            .stat-grid { grid-template-columns: repeat(2, 1fr); gap: 0.5rem; }
            .stat-card { padding: 0.75rem 0.65rem; }
            .stat-num { font-size: 1.3rem; }
            .stat-label { font-size: 0.65rem; }
            .stat-hint { font-size: 0.65rem; }
            .hub-grid { grid-template-columns: 1fr; }
            .btn { font-size: 0.8rem; padding: 0.45rem 0.75rem; }
            input[type="text"], input[type="email"], input[type="password"], input[type="search"], input[type="url"], input[type="tel"], input[type="number"], select, textarea {
                font-size: 0.85rem; padding: 0.5rem 0.65rem;
            }
            .qr-preview-box { width: 100% !important; max-width: 250px !important; height: 250px !important; padding: 0.75rem !important; }
        }

        @media (max-width: 360px) {
            .stat-grid { grid-template-columns: 1fr; }
            .breadcrumb-current { max-width: 95px; }
            .brand-title { font-size: 0.78rem; }
            .container, .admin-content { padding: 0.5rem 0.4rem; }
            .public-home-container { padding: 0.5rem 0.4rem 1.5rem 0.4rem; }
            .card { padding: 0.75rem 0.55rem; }
            .hero-banner { padding: 1.15rem 0.75rem; }
            .hero-banner h1 { font-size: 1.15rem; }
            .public-search-card { padding: 0.75rem 0.55rem; }
            .public-link-card { padding: 0.75rem 0.55rem; }
            .target-address { font-size: 0.75rem; }
        }
    </style>
</head>
<body>
    <a href="#main-content" class="skip-link">Lewati ke konten utama</a>
    {$contentHtml}
    <script src="/buka/livewire/livewire.js" defer></script>
    <script>
    (function() {
        var shell = document.querySelector('.admin-shell');
        var toggleBtn = document.getElementById('sidebar-toggle');
        var closeBtn = document.getElementById('sidebar-close');
        var backdrop = document.getElementById('sidebar-backdrop');
        
        if (!shell || !toggleBtn) return;
        
        try {
            if (window.innerWidth > 900 && localStorage.getItem('aw_sidebar_collapsed') === '1') {
                shell.classList.add('sidebar-collapsed');
            }
        } catch(e) {}
        
        function toggle() {
            if (window.innerWidth > 900) {
                shell.classList.toggle('sidebar-collapsed');
                try {
                    localStorage.setItem('aw_sidebar_collapsed', shell.classList.contains('sidebar-collapsed') ? '1' : '0');
                } catch(e) {}
            } else {
                shell.classList.toggle('sidebar-mobile-open');
            }
        }
        
        function closeMobile() {
            shell.classList.remove('sidebar-mobile-open');
        }
        
        toggleBtn.addEventListener('click', toggle);
        if (closeBtn) closeBtn.addEventListener('click', closeMobile);
        if (backdrop) backdrop.addEventListener('click', closeMobile);
        
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && shell.classList.contains('sidebar-mobile-open')) {
                closeMobile();
            }
        });
        
        var links = document.querySelectorAll('.sidebar-link');
        for (var i = 0; i < links.length; i++) {
            links[i].addEventListener('click', function() {
                if (window.innerWidth <= 900) {
                    closeMobile();
                }
            });
        }
    })();
    </script>
</body>
</html>
HTML;
    }
}
