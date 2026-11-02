-- 0010_schema_and_tables.sql: Physical PostgreSQL DDL for AW Shortlink (SPEC-05, #12, #38)
-- All objects owned by awshortlink_owner so runtime role awshortlink_app is never table owner.

SET ROLE awshortlink_owner;
SET search_path = shortlink, pg_catalog;

-- Transaction-local context helper functions (STABLE, SECURITY INVOKER, fixed search_path)
CREATE OR REPLACE FUNCTION shortlink.ctx_actor() RETURNS uuid
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
    SELECT CASE
        WHEN coalesce(current_setting('app.actor_id', true), '') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        THEN current_setting('app.actor_id', true)::uuid
        ELSE NULL
    END
$$;

CREATE OR REPLACE FUNCTION shortlink.ctx_unit_ids() RETURNS uuid[]
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
    SELECT CASE
        WHEN coalesce(current_setting('app.unit_ids', true), '') = '' THEN ARRAY[]::uuid[]
        ELSE string_to_array(current_setting('app.unit_ids', true), ',')::uuid[]
    END
$$;

CREATE OR REPLACE FUNCTION shortlink.ctx_is_global() RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
    SELECT coalesce(current_setting('app.scope', true), '') = 'global'
           AND shortlink.ctx_actor() IS NOT NULL
$$;

-- TBL-001: units
CREATE TABLE IF NOT EXISTS shortlink.units (
    id uuid PRIMARY KEY,
    parent_id uuid REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    code text NOT NULL UNIQUE CHECK (code ~ '^[A-Z0-9_]{2,32}$'),
    name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 160),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- TBL-002: unit_closure (DES-002)
CREATE TABLE IF NOT EXISTS shortlink.unit_closure (
    ancestor_id uuid NOT NULL REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    descendant_id uuid NOT NULL REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    depth smallint NOT NULL CHECK (depth >= 0),
    PRIMARY KEY (ancestor_id, descendant_id)
);
CREATE INDEX IF NOT EXISTS idx_unit_closure_descendant ON shortlink.unit_closure (descendant_id);

-- TBL-003: users (PII-001 name, PII-002 email)
CREATE TABLE IF NOT EXISTS shortlink.users (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 120),
    email text NOT NULL UNIQUE CHECK (email = lower(email) AND position('@' IN email) > 1),
    password_hash text,
    mfa_secret_encrypted text,
    mfa_enrolled_at timestamptz,
    status text NOT NULL DEFAULT 'invited' CHECK (status IN ('invited', 'active', 'suspended', 'disabled')),
    is_protected_owner boolean NOT NULL DEFAULT false,
    last_login_at timestamptz,
    disabled_at timestamptz,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- TBL-004: sessions (PII-003, DES-012 30m idle / 8h absolute)
CREATE TABLE IF NOT EXISTS shortlink.sessions (
    id text PRIMARY KEY CHECK (char_length(id) >= 16),
    user_id uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE CASCADE,
    mfa_verified boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_activity_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON shortlink.sessions (user_id) WHERE revoked_at IS NULL;

-- TBL-005: user_unit_memberships (PII-004)
CREATE TABLE IF NOT EXISTS shortlink.user_unit_memberships (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    unit_id uuid NOT NULL REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    valid_from timestamptz NOT NULL DEFAULT now(),
    valid_until timestamptz,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_by uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    reviewed_by uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    reason text NOT NULL CHECK (char_length(reason) >= 3),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (valid_until IS NULL OR valid_until > valid_from),
    CHECK (created_by <> user_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_user_unit ON shortlink.user_unit_memberships (user_id, unit_id) WHERE status = 'active';

-- TBL-006: roles
CREATE TABLE IF NOT EXISTS shortlink.roles (
    id uuid PRIMARY KEY,
    key text NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_]{2,48}$'),
    label text NOT NULL CHECK (char_length(label) BETWEEN 2 AND 100),
    is_protected boolean NOT NULL DEFAULT false,
    sensitivity text NOT NULL DEFAULT 'normal' CHECK (sensitivity IN ('normal', 'sensitive', 'protected')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    owner_unit_id uuid REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- TBL-007: permissions
CREATE TABLE IF NOT EXISTS shortlink.permissions (
    id uuid PRIMARY KEY,
    code text NOT NULL UNIQUE CHECK (code ~ '^PERM-[0-9]{3}$'),
    key text NOT NULL UNIQUE CHECK (key ~ '^[a-z_]+(\.[a-z_]+)+$'),
    description text NOT NULL,
    risk text NOT NULL CHECK (risk IN ('low', 'medium', 'high', 'critical')),
    catalog_version integer NOT NULL CHECK (catalog_version >= 1)
);

-- TBL-008: role_permissions
CREATE TABLE IF NOT EXISTS shortlink.role_permissions (
    role_id uuid NOT NULL REFERENCES shortlink.roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES shortlink.permissions(id) ON DELETE RESTRICT,
    grantable boolean NOT NULL DEFAULT false,
    granted_by uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    reason text NOT NULL DEFAULT 'Initial catalog seed',
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

-- TBL-009: user_role_assignments (PII-005)
CREATE TABLE IF NOT EXISTS shortlink.user_role_assignments (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    role_id uuid NOT NULL REFERENCES shortlink.roles(id) ON DELETE RESTRICT,
    scope_type text NOT NULL CHECK (scope_type IN ('global', 'unit', 'unit_descendants', 'owned')),
    unit_id uuid REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    valid_from timestamptz NOT NULL DEFAULT now(),
    valid_until timestamptz,
    granted_by uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    approved_by uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    reason text NOT NULL CHECK (char_length(reason) >= 3),
    revoked_at timestamptz,
    revoked_by uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    revoke_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope_type = 'global') = (unit_id IS NULL)),
    CHECK (granted_by <> user_id),
    CHECK (approved_by IS NULL OR approved_by <> granted_by),
    CHECK (valid_until IS NULL OR valid_until > valid_from)
);
CREATE INDEX IF NOT EXISTS idx_role_assignments_user_active ON shortlink.user_role_assignments (user_id) WHERE revoked_at IS NULL;

-- TBL-010: abac_policy_definitions
CREATE TABLE IF NOT EXISTS shortlink.abac_policy_definitions (
    id uuid PRIMARY KEY,
    key text NOT NULL UNIQUE CHECK (key ~ '^POL-[A-Z0-9-]+$'),
    resource text NOT NULL,
    action text NOT NULL,
    current_version_id uuid,
    owner_unit_id uuid REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- TBL-011: abac_policy_versions
CREATE TABLE IF NOT EXISTS shortlink.abac_policy_versions (
    id uuid PRIMARY KEY,
    definition_id uuid NOT NULL REFERENCES shortlink.abac_policy_definitions(id) ON DELETE RESTRICT,
    version integer NOT NULL CHECK (version >= 1),
    rule jsonb NOT NULL,
    checksum text NOT NULL CHECK (char_length(checksum) = 64),
    status text NOT NULL CHECK (status IN ('draft', 'simulated', 'submitted', 'approved', 'active', 'superseded', 'rejected', 'revoked')),
    simulation_report jsonb,
    authored_by uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    approved_by uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    activated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (approved_by IS NULL OR approved_by <> authored_by),
    UNIQUE (definition_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_abac_version ON shortlink.abac_policy_versions (definition_id) WHERE status = 'active';

-- TBL-012: abac_policy_approvals
CREATE TABLE IF NOT EXISTS shortlink.abac_policy_approvals (
    id uuid PRIMARY KEY,
    version_id uuid NOT NULL REFERENCES shortlink.abac_policy_versions(id) ON DELETE RESTRICT,
    actor_id uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    decision text NOT NULL CHECK (decision IN ('approve', 'reject', 'rollback')),
    reason text NOT NULL CHECK (char_length(reason) >= 3),
    occurred_at timestamptz NOT NULL DEFAULT now()
);

-- TBL-013: access_change_requests (PII-006)
CREATE TABLE IF NOT EXISTS shortlink.access_change_requests (
    id uuid PRIMARY KEY,
    unit_id uuid REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    requested_by uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    target_user_id uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    role_id uuid NOT NULL REFERENCES shortlink.roles(id) ON DELETE RESTRICT,
    scope_type text NOT NULL CHECK (scope_type IN ('global', 'unit', 'unit_descendants', 'owned')),
    change_payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    reason text NOT NULL CHECK (char_length(reason) >= 3),
    decided_by uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    decision_reason text,
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (requested_by <> target_user_id),
    CHECK (decided_by IS NULL OR decided_by <> requested_by)
);

-- Campaigns (part of TBL-022 / P1 #28)
CREATE TABLE IF NOT EXISTS shortlink.campaigns (
    id uuid PRIMARY KEY,
    unit_id uuid NOT NULL REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    code text NOT NULL CHECK (code ~ '^[A-Z0-9_-]{2,32}$'),
    name text NOT NULL CHECK (char_length(name) BETWEEN 3 AND 160),
    status text NOT NULL DEFAULT 'planned' CHECK (status IN ('planned', 'running', 'ended', 'archived')),
    owner_id uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    start_at timestamptz,
    end_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (unit_id, code)
);

-- TBL-014: links (DES-013 ASCII slug 3..64)
CREATE TABLE IF NOT EXISTS shortlink.links (
    id uuid PRIMARY KEY,
    namespace text NOT NULL DEFAULT 'buka' CHECK (namespace ~ '^[a-z0-9_-]{2,32}$'),
    unit_id uuid NOT NULL REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    creator_id uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    campaign_id uuid REFERENCES shortlink.campaigns(id) ON DELETE SET NULL,
    slug_normalized text NOT NULL CHECK (
        slug_normalized ~ '^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])$'
        AND position('--' IN slug_normalized) = 0
    ),
    display_slug text NOT NULL,
    title text NOT NULL CHECK (char_length(title) BETWEEN 3 AND 160),
    current_destination_id uuid,
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'submitted', 'active', 'suspended', 'archived')),
    visibility text NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'unlisted')),
    published_at timestamptz,
    expires_at timestamptz,
    retired_public_message boolean NOT NULL DEFAULT true,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at IS NULL OR published_at IS NULL OR expires_at > published_at),
    CHECK (status NOT IN ('active', 'suspended', 'archived') OR published_at IS NOT NULL),
    UNIQUE (namespace, slug_normalized),
    UNIQUE (id, unit_id)
);
CREATE INDEX IF NOT EXISTS idx_links_unit_created ON shortlink.links (unit_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_links_status_expires ON shortlink.links (status, expires_at);

-- TBL-015: link_destinations (DES-008 https:// mandatory)
CREATE TABLE IF NOT EXISTS shortlink.link_destinations (
    id uuid PRIMARY KEY,
    link_id uuid NOT NULL,
    unit_id uuid NOT NULL,
    url_canonical text NOT NULL CHECK (url_canonical ~ '^https://' AND char_length(url_canonical) <= 2048),
    host_canonical text NOT NULL CHECK (char_length(host_canonical) BETWEEN 3 AND 253),
    risk_class text NOT NULL CHECK (risk_class IN ('low', 'medium', 'high', 'forbidden')),
    policy_verdict jsonb NOT NULL,
    status text NOT NULL CHECK (status IN ('proposed', 'blocked', 'pending_review', 'approved', 'rejected', 'current', 'superseded')),
    version integer NOT NULL CHECK (version >= 1),
    proposed_by uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    approved_by uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    approved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (link_id, unit_id) REFERENCES shortlink.links (id, unit_id) ON DELETE RESTRICT,
    CHECK (approved_by IS NULL OR risk_class = 'low' OR approved_by <> proposed_by),
    UNIQUE (link_id, version),
    UNIQUE (id, link_id)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'current_dest_same_link'
    ) THEN
        ALTER TABLE shortlink.links
            ADD CONSTRAINT current_dest_same_link
            FOREIGN KEY (current_destination_id, id)
            REFERENCES shortlink.link_destinations (id, link_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END
$$;

-- TBL-016: reserved_slugs (permanent tombstone for published slugs)
CREATE TABLE IF NOT EXISTS shortlink.reserved_slugs (
    namespace text NOT NULL DEFAULT 'buka',
    slug_normalized text NOT NULL,
    initial_link_id uuid REFERENCES shortlink.links(id) ON DELETE RESTRICT,
    reason text NOT NULL CHECK (reason IN ('system', 'published', 'policy', 'draft')),
    reserved_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, slug_normalized)
);

-- TBL-017: destination_domain_rules (DES-014)
CREATE TABLE IF NOT EXISTS shortlink.destination_domain_rules (
    id uuid PRIMARY KEY,
    host_pattern text NOT NULL UNIQUE CHECK (char_length(host_pattern) BETWEEN 3 AND 253),
    rule_type text NOT NULL CHECK (rule_type IN ('allowlist_low', 'medium_review', 'denylist_forbidden', 'http_waiver')),
    reason text NOT NULL,
    expires_at timestamptz,
    created_by uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- TBL-018: link_approvals
CREATE TABLE IF NOT EXISTS shortlink.link_approvals (
    id uuid PRIMARY KEY,
    link_id uuid NOT NULL REFERENCES shortlink.links(id) ON DELETE RESTRICT,
    unit_id uuid NOT NULL REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    destination_id uuid NOT NULL REFERENCES shortlink.link_destinations(id) ON DELETE RESTRICT,
    actor_id uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    action text NOT NULL CHECK (action IN ('submit', 'approve', 'reject', 'suspend', 'reinstate', 'emergency_suspend')),
    risk text NOT NULL CHECK (risk IN ('low', 'medium', 'high', 'forbidden')),
    reason text NOT NULL CHECK (char_length(reason) >= 3),
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_link_approvals_link ON shortlink.link_approvals (link_id, occurred_at DESC);

-- TBL-019: link_audit_events (DES-001 BIGINT identity, SHA-256 hash chain)
CREATE TABLE IF NOT EXISTS shortlink.link_audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    unit_id uuid REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    link_id uuid REFERENCES shortlink.links(id) ON DELETE RESTRICT,
    actor_id uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    action text NOT NULL,
    subject_type text NOT NULL,
    subject_id uuid,
    subject_version integer,
    before_hash text,
    after_hash text,
    reason text,
    request_id uuid NOT NULL,
    policy_version_id uuid REFERENCES shortlink.abac_policy_versions(id) ON DELETE RESTRICT,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    prev_hash text NOT NULL CHECK (char_length(prev_hash) = 64),
    row_hash text NOT NULL UNIQUE CHECK (char_length(row_hash) = 64)
);
CREATE INDEX IF NOT EXISTS idx_audit_actor_time ON shortlink.link_audit_events (actor_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_link_time ON shortlink.link_audit_events (link_id, occurred_at DESC);

-- TBL-020: access_decision_audit
CREATE TABLE IF NOT EXISTS shortlink.access_decision_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    unit_id uuid REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    permission text NOT NULL,
    resource_type text NOT NULL,
    verdict text NOT NULL CHECK (verdict IN ('allow', 'deny')),
    reason_code text NOT NULL,
    policy_version_id uuid REFERENCES shortlink.abac_policy_versions(id) ON DELETE RESTRICT,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

-- TBL-021: link_daily_stats (ADR-0003, DES-005, DES-007, DES-011)
CREATE TABLE IF NOT EXISTS shortlink.link_daily_stats (
    link_id uuid NOT NULL REFERENCES shortlink.links(id) ON DELETE RESTRICT,
    unit_id uuid NOT NULL REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    date_utc date NOT NULL,
    channel_code text NOT NULL DEFAULT '',
    valid_clicks bigint NOT NULL DEFAULT 0 CHECK (valid_clicks >= 0),
    suspected_bot bigint NOT NULL DEFAULT 0 CHECK (suspected_bot >= 0),
    rejected bigint NOT NULL DEFAULT 0 CHECK (rejected >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (link_id, date_utc, channel_code)
);
CREATE INDEX IF NOT EXISTS idx_daily_stats_unit_date ON shortlink.link_daily_stats (unit_id, date_utc DESC);

-- TBL-022 Auxiliary & P1 tables: link_qr_assets, api_credentials, app_settings, ops_heartbeats, abuse_reports, link_health_checks
CREATE TABLE IF NOT EXISTS shortlink.link_qr_assets (
    id uuid PRIMARY KEY,
    link_id uuid NOT NULL REFERENCES shortlink.links(id) ON DELETE RESTRICT,
    unit_id uuid NOT NULL REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    style_version integer NOT NULL DEFAULT 1,
    output_format text NOT NULL CHECK (output_format IN ('svg', 'png')),
    encoded_url text NOT NULL,
    is_draft_watermarked boolean NOT NULL DEFAULT false,
    checksum text NOT NULL CHECK (char_length(checksum) = 64),
    generated_by uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS shortlink.api_credentials (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    unit_id uuid REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 100),
    prefix text NOT NULL UNIQUE CHECK (char_length(prefix) BETWEEN 6 AND 20),
    secret_hash text NOT NULL UNIQUE CHECK (char_length(secret_hash) = 64),
    scopes text[] NOT NULL,
    rate_limit_per_minute integer NOT NULL DEFAULT 60 CHECK (rate_limit_per_minute BETWEEN 1 AND 600),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS shortlink.app_settings (
    key text PRIMARY KEY CHECK (key ~ '^[a-z0-9._-]{2,64}$'),
    value_json jsonb NOT NULL,
    updated_by uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    version integer NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS shortlink.ops_heartbeats (
    component text PRIMARY KEY CHECK (component ~ '^[a-z0-9_-]{2,48}$'),
    status text NOT NULL CHECK (status IN ('ok', 'degraded', 'error')),
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS shortlink.abuse_reports (
    id uuid PRIMARY KEY,
    slug_reported text NOT NULL CHECK (char_length(slug_reported) BETWEEN 1 AND 80),
    link_id uuid REFERENCES shortlink.links(id) ON DELETE SET NULL,
    unit_id uuid REFERENCES shortlink.units(id) ON DELETE SET NULL,
    category text NOT NULL CHECK (category IN ('deadlink', 'not_for_public', 'phishing', 'malware', 'inaccurate_target', 'expired_content', 'other')),
    description text NOT NULL CHECK (char_length(description) BETWEEN 5 AND 1000),
    reporter_contact text,
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved_suspended', 'dismissed')),
    resolved_by uuid REFERENCES shortlink.users(id) ON DELETE RESTRICT,
    resolution_notes text,
    created_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);

CREATE TABLE IF NOT EXISTS shortlink.link_health_checks (
    id uuid PRIMARY KEY,
    link_id uuid NOT NULL REFERENCES shortlink.links(id) ON DELETE CASCADE,
    unit_id uuid NOT NULL REFERENCES shortlink.units(id) ON DELETE RESTRICT,
    result_status text NOT NULL CHECK (result_status IN ('healthy', 'redirect_blocked', 'ssrf_blocked', 'timeout', 'http_error')),
    http_status integer,
    safe_error_code text NOT NULL,
    duration_ms integer NOT NULL CHECK (duration_ms >= 0),
    checked_at timestamptz NOT NULL DEFAULT now()
);

-- TBL-023: link_access_logs (Detailed per-link visitor analytics & telemetry)
CREATE TABLE IF NOT EXISTS shortlink.link_access_logs (
    id uuid PRIMARY KEY,
    link_id uuid NOT NULL REFERENCES shortlink.links(id) ON DELETE CASCADE,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    ip_address text,
    country text,
    city text,
    region text,
    latitude numeric(10, 6),
    longitude numeric(10, 6),
    os text,
    browser text,
    device_type text,
    device_model text,
    user_agent text,
    referer text,
    is_bot boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_access_logs_link_time ON shortlink.link_access_logs (link_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_logs_occurred_at ON shortlink.link_access_logs (occurred_at DESC);

RESET ROLE;

