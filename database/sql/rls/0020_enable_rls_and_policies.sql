-- 0020_enable_rls_and_policies.sql: Mandatory PostgreSQL Row-Level Security (RLS-001..022, ADR-0005, #38)
-- Default deny when transaction-local context (`app.actor_id`, `app.unit_ids`, `app.scope`) is missing.

SET ROLE awshortlink_owner;
SET search_path = shortlink, pg_catalog;

-- Enable & Force RLS on all 27 tables in schema shortlink
DO $$
DECLARE
    tbl text;
BEGIN
    FOR tbl IN
        SELECT tablename FROM pg_tables WHERE schemaname = 'shortlink'
    LOOP
        EXECUTE format('ALTER TABLE shortlink.%I ENABLE ROW LEVEL SECURITY', tbl);
        EXECUTE format('ALTER TABLE shortlink.%I FORCE ROW LEVEL SECURITY', tbl);
        EXECUTE format('REVOKE ALL ON TABLE shortlink.%I FROM PUBLIC', tbl);
    END LOOP;
END
$$;

-- Drop existing policies idempotently before recreating
DO $$
DECLARE
    pol record;
BEGIN
    FOR pol IN
        SELECT schemaname, tablename, policyname
        FROM pg_policies
        WHERE schemaname = 'shortlink'
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', pol.policyname, pol.schemaname, pol.tablename);
    END LOOP;
END
$$;

-- Allow NOLOGIN table owner role (assumed only by operator CLI migrator, never runtime)
-- to seed reference catalogs while FORCE ROW LEVEL SECURITY remains active on all tables.
DO $$
DECLARE
    tbl text;
BEGIN
    FOR tbl IN
        SELECT tablename FROM pg_tables WHERE schemaname = 'shortlink'
    LOOP
        EXECUTE format(
            'CREATE POLICY rls_owner_migrator_%I ON shortlink.%I FOR ALL TO awshortlink_owner USING (true) WITH CHECK (true)',
            tbl,
            tbl
        );
    END LOOP;
END
$$;

-- RLS-001: units
CREATE POLICY rls_001_units_select ON shortlink.units FOR SELECT TO awshortlink_app
    USING (id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_001_units_insert ON shortlink.units FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_is_global());
CREATE POLICY rls_001_units_update ON shortlink.units FOR UPDATE TO awshortlink_app
    USING (id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
    WITH CHECK (id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE ON shortlink.units TO awshortlink_app;

-- RLS-002: unit_closure
CREATE POLICY rls_002_closure_select ON shortlink.unit_closure FOR SELECT TO awshortlink_app
    USING (ancestor_id = ANY (shortlink.ctx_unit_ids()) OR descendant_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_002_closure_insert ON shortlink.unit_closure FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_is_global());
CREATE POLICY rls_002_closure_delete ON shortlink.unit_closure FOR DELETE TO awshortlink_app
    USING (shortlink.ctx_is_global());
GRANT SELECT, INSERT, DELETE ON shortlink.unit_closure TO awshortlink_app;

-- RLS-003: users
CREATE POLICY rls_003_users_select ON shortlink.users FOR SELECT TO awshortlink_app
    USING (
        id = shortlink.ctx_actor()
        OR shortlink.ctx_is_global()
        OR EXISTS (
            SELECT 1 FROM shortlink.user_unit_memberships m
            WHERE m.user_id = shortlink.users.id
              AND m.unit_id = ANY (shortlink.ctx_unit_ids())
        )
    );
CREATE POLICY rls_003_users_insert ON shortlink.users FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_is_global() OR cardinality(shortlink.ctx_unit_ids()) > 0);
CREATE POLICY rls_003_users_update ON shortlink.users FOR UPDATE TO awshortlink_app
    USING (
        id = shortlink.ctx_actor()
        OR shortlink.ctx_is_global()
        OR EXISTS (
            SELECT 1 FROM shortlink.user_unit_memberships m
            WHERE m.user_id = shortlink.users.id
              AND m.unit_id = ANY (shortlink.ctx_unit_ids())
        )
    )
    WITH CHECK (
        id = shortlink.ctx_actor()
        OR shortlink.ctx_is_global()
        OR EXISTS (
            SELECT 1 FROM shortlink.user_unit_memberships m
            WHERE m.user_id = shortlink.users.id
              AND m.unit_id = ANY (shortlink.ctx_unit_ids())
        )
    );
GRANT SELECT, INSERT, UPDATE ON shortlink.users TO awshortlink_app;

-- RLS-004: sessions
CREATE POLICY rls_004_sessions_select ON shortlink.sessions FOR SELECT TO awshortlink_app
    USING (user_id = shortlink.ctx_actor() OR shortlink.ctx_is_global());
CREATE POLICY rls_004_sessions_insert ON shortlink.sessions FOR INSERT TO awshortlink_app
    WITH CHECK (user_id = shortlink.ctx_actor() OR shortlink.ctx_is_global());
CREATE POLICY rls_004_sessions_update ON shortlink.sessions FOR UPDATE TO awshortlink_app
    USING (
        user_id = shortlink.ctx_actor()
        OR shortlink.ctx_is_global()
        OR EXISTS (
            SELECT 1 FROM shortlink.user_unit_memberships m
            WHERE m.user_id = shortlink.sessions.user_id
              AND m.unit_id = ANY (shortlink.ctx_unit_ids())
        )
    )
    WITH CHECK (
        user_id = shortlink.ctx_actor()
        OR shortlink.ctx_is_global()
        OR EXISTS (
            SELECT 1 FROM shortlink.user_unit_memberships m
            WHERE m.user_id = shortlink.sessions.user_id
              AND m.unit_id = ANY (shortlink.ctx_unit_ids())
        )
    );
CREATE POLICY rls_004_sessions_delete ON shortlink.sessions FOR DELETE TO awshortlink_app
    USING (user_id = shortlink.ctx_actor() OR shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE, DELETE ON shortlink.sessions TO awshortlink_app;

-- RLS-005: user_unit_memberships
CREATE POLICY rls_005_memberships_select ON shortlink.user_unit_memberships FOR SELECT TO awshortlink_app
    USING (user_id = shortlink.ctx_actor() OR unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_005_memberships_insert ON shortlink.user_unit_memberships FOR INSERT TO awshortlink_app
    WITH CHECK (
        (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
        AND created_by = shortlink.ctx_actor()
        AND user_id <> shortlink.ctx_actor()
    );
CREATE POLICY rls_005_memberships_update ON shortlink.user_unit_memberships FOR UPDATE TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
    WITH CHECK (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE ON shortlink.user_unit_memberships TO awshortlink_app;

-- RLS-006: roles
CREATE POLICY rls_006_roles_select ON shortlink.roles FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_actor() IS NOT NULL);
CREATE POLICY rls_006_roles_insert ON shortlink.roles FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_is_global());
CREATE POLICY rls_006_roles_update ON shortlink.roles FOR UPDATE TO awshortlink_app
    USING (shortlink.ctx_is_global() AND NOT is_protected)
    WITH CHECK (shortlink.ctx_is_global() AND NOT is_protected);
GRANT SELECT, INSERT, UPDATE ON shortlink.roles TO awshortlink_app;

-- RLS-007: permissions (read-only for runtime; seeded by migrator)
CREATE POLICY rls_007_permissions_select ON shortlink.permissions FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_actor() IS NOT NULL);
GRANT SELECT ON shortlink.permissions TO awshortlink_app;

-- RLS-008: role_permissions
CREATE POLICY rls_008_role_perms_select ON shortlink.role_permissions FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_actor() IS NOT NULL);
CREATE POLICY rls_008_role_perms_insert ON shortlink.role_permissions FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_is_global() AND granted_by = shortlink.ctx_actor());
CREATE POLICY rls_008_role_perms_delete ON shortlink.role_permissions FOR DELETE TO awshortlink_app
    USING (shortlink.ctx_is_global());
GRANT SELECT, INSERT, DELETE ON shortlink.role_permissions TO awshortlink_app;

-- RLS-009: user_role_assignments
CREATE POLICY rls_009_assignments_select ON shortlink.user_role_assignments FOR SELECT TO awshortlink_app
    USING (user_id = shortlink.ctx_actor() OR unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_009_assignments_insert ON shortlink.user_role_assignments FOR INSERT TO awshortlink_app
    WITH CHECK (
        (
            (scope_type = 'global' AND shortlink.ctx_is_global())
            OR (unit_id IS NOT NULL AND (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global()))
        )
        AND (
            (approved_by IS NULL AND granted_by = shortlink.ctx_actor())
            OR (approved_by = shortlink.ctx_actor() AND granted_by <> shortlink.ctx_actor())
        )
        AND user_id <> shortlink.ctx_actor()
    );
CREATE POLICY rls_009_assignments_update ON shortlink.user_role_assignments FOR UPDATE TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
    WITH CHECK (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE ON shortlink.user_role_assignments TO awshortlink_app;

-- RLS-010: abac_policy_definitions
CREATE POLICY rls_010_abac_def_select ON shortlink.abac_policy_definitions FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_actor() IS NOT NULL);
CREATE POLICY rls_010_abac_def_insert ON shortlink.abac_policy_definitions FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_is_global());
CREATE POLICY rls_010_abac_def_update ON shortlink.abac_policy_definitions FOR UPDATE TO awshortlink_app
    USING (shortlink.ctx_is_global())
    WITH CHECK (shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE ON shortlink.abac_policy_definitions TO awshortlink_app;

-- RLS-011: abac_policy_versions
CREATE POLICY rls_011_abac_ver_select ON shortlink.abac_policy_versions FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_actor() IS NOT NULL);
CREATE POLICY rls_011_abac_ver_insert ON shortlink.abac_policy_versions FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_is_global() AND authored_by = shortlink.ctx_actor());
CREATE POLICY rls_011_abac_ver_update ON shortlink.abac_policy_versions FOR UPDATE TO awshortlink_app
    USING (shortlink.ctx_is_global())
    WITH CHECK (shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE ON shortlink.abac_policy_versions TO awshortlink_app;

-- RLS-012: abac_policy_approvals (append-only)
CREATE POLICY rls_012_abac_app_select ON shortlink.abac_policy_approvals FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_is_global());
CREATE POLICY rls_012_abac_app_insert ON shortlink.abac_policy_approvals FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_is_global() AND actor_id = shortlink.ctx_actor());
GRANT SELECT, INSERT ON shortlink.abac_policy_approvals TO awshortlink_app;

-- RLS-013: access_change_requests
CREATE POLICY rls_013_change_req_select ON shortlink.access_change_requests FOR SELECT TO awshortlink_app
    USING (
        requested_by = shortlink.ctx_actor()
        OR target_user_id = shortlink.ctx_actor()
        OR unit_id = ANY (shortlink.ctx_unit_ids())
        OR shortlink.ctx_is_global()
    );
CREATE POLICY rls_013_change_req_insert ON shortlink.access_change_requests FOR INSERT TO awshortlink_app
    WITH CHECK (
        (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
        AND requested_by = shortlink.ctx_actor()
        AND target_user_id <> shortlink.ctx_actor()
    );
CREATE POLICY rls_013_change_req_update ON shortlink.access_change_requests FOR UPDATE TO awshortlink_app
    USING (shortlink.ctx_is_global())
    WITH CHECK (shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE ON shortlink.access_change_requests TO awshortlink_app;

-- RLS-014: links
CREATE POLICY rls_014_links_select ON shortlink.links FOR SELECT TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_014_links_insert ON shortlink.links FOR INSERT TO awshortlink_app
    WITH CHECK ((unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global()) AND creator_id = shortlink.ctx_actor());
CREATE POLICY rls_014_links_update ON shortlink.links FOR UPDATE TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
    WITH CHECK (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_014_links_resolver ON shortlink.links FOR SELECT TO awshortlink_resolver
    USING (published_at IS NOT NULL);
GRANT SELECT, INSERT, UPDATE ON shortlink.links TO awshortlink_app;

-- RLS-015: link_destinations
CREATE POLICY rls_015_dest_select ON shortlink.link_destinations FOR SELECT TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_015_dest_insert ON shortlink.link_destinations FOR INSERT TO awshortlink_app
    WITH CHECK ((unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global()) AND proposed_by = shortlink.ctx_actor());
CREATE POLICY rls_015_dest_update ON shortlink.link_destinations FOR UPDATE TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
    WITH CHECK (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_015_dest_resolver ON shortlink.link_destinations FOR SELECT TO awshortlink_resolver
    USING (status = 'current');
GRANT SELECT, INSERT, UPDATE ON shortlink.link_destinations TO awshortlink_app;

-- RLS-016: reserved_slugs
CREATE POLICY rls_016_reserved_select ON shortlink.reserved_slugs FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_actor() IS NOT NULL);
CREATE POLICY rls_016_reserved_insert ON shortlink.reserved_slugs FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_actor() IS NOT NULL);
CREATE POLICY rls_016_reserved_update ON shortlink.reserved_slugs FOR UPDATE TO awshortlink_app
    USING (shortlink.ctx_actor() IS NOT NULL AND reason = 'draft')
    WITH CHECK (shortlink.ctx_actor() IS NOT NULL AND reason IN ('draft', 'published'));
CREATE POLICY rls_016_reserved_delete ON shortlink.reserved_slugs FOR DELETE TO awshortlink_app
    USING (shortlink.ctx_actor() IS NOT NULL AND reason = 'draft');
GRANT SELECT, INSERT, UPDATE, DELETE ON shortlink.reserved_slugs TO awshortlink_app;

-- RLS-017: destination_domain_rules
CREATE POLICY rls_017_domain_rules_select ON shortlink.destination_domain_rules FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_actor() IS NOT NULL);
CREATE POLICY rls_017_domain_rules_insert ON shortlink.destination_domain_rules FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_is_global());
CREATE POLICY rls_017_domain_rules_update ON shortlink.destination_domain_rules FOR UPDATE TO awshortlink_app
    USING (shortlink.ctx_is_global())
    WITH CHECK (shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE ON shortlink.destination_domain_rules TO awshortlink_app;

-- RLS-018: link_approvals (append-only)
CREATE POLICY rls_018_approvals_select ON shortlink.link_approvals FOR SELECT TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_018_approvals_insert ON shortlink.link_approvals FOR INSERT TO awshortlink_app
    WITH CHECK ((unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global()) AND actor_id = shortlink.ctx_actor());
GRANT SELECT, INSERT ON shortlink.link_approvals TO awshortlink_app;

-- RLS-019: link_audit_events (append-only, no UPDATE/DELETE grant)
CREATE POLICY rls_019_audit_select ON shortlink.link_audit_events FOR SELECT TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_019_audit_insert ON shortlink.link_audit_events FOR INSERT TO awshortlink_app
    WITH CHECK (
        shortlink.ctx_actor() IS NOT NULL
        AND (unit_id IS NULL OR unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
    );
GRANT SELECT, INSERT ON shortlink.link_audit_events TO awshortlink_app;
GRANT USAGE, SELECT ON SEQUENCE shortlink.link_audit_events_id_seq TO awshortlink_app;

-- RLS-020: access_decision_audit (append-only, no UPDATE/DELETE grant)
CREATE POLICY rls_020_access_audit_select ON shortlink.access_decision_audit FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_is_global() OR unit_id = ANY (shortlink.ctx_unit_ids()));
CREATE POLICY rls_020_access_audit_insert ON shortlink.access_decision_audit FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_actor() IS NOT NULL);
GRANT SELECT, INSERT ON shortlink.access_decision_audit TO awshortlink_app;
GRANT USAGE, SELECT ON SEQUENCE shortlink.access_decision_audit_id_seq TO awshortlink_app;

-- RLS-021: link_daily_stats (writes via shortlink.record_click only)
CREATE POLICY rls_021_stats_select ON shortlink.link_daily_stats FOR SELECT TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
GRANT SELECT ON shortlink.link_daily_stats TO awshortlink_app;

-- RLS-022: Auxiliary & P1 tables (link_qr_assets, campaigns, api_credentials, app_settings, ops_heartbeats, abuse_reports, link_health_checks)
CREATE POLICY rls_022_qr_select ON shortlink.link_qr_assets FOR SELECT TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_022_qr_insert ON shortlink.link_qr_assets FOR INSERT TO awshortlink_app
    WITH CHECK ((unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global()) AND generated_by = shortlink.ctx_actor());
GRANT SELECT, INSERT ON shortlink.link_qr_assets TO awshortlink_app;

CREATE POLICY rls_022_campaigns_select ON shortlink.campaigns FOR SELECT TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_022_campaigns_insert ON shortlink.campaigns FOR INSERT TO awshortlink_app
    WITH CHECK (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_022_campaigns_update ON shortlink.campaigns FOR UPDATE TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
    WITH CHECK (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE ON shortlink.campaigns TO awshortlink_app;

CREATE POLICY rls_022_apikeys_select ON shortlink.api_credentials FOR SELECT TO awshortlink_app
    USING (owner_id = shortlink.ctx_actor() OR shortlink.ctx_is_global());
CREATE POLICY rls_022_apikeys_insert ON shortlink.api_credentials FOR INSERT TO awshortlink_app
    WITH CHECK (owner_id = shortlink.ctx_actor() OR shortlink.ctx_is_global());
CREATE POLICY rls_022_apikeys_update ON shortlink.api_credentials FOR UPDATE TO awshortlink_app
    USING (owner_id = shortlink.ctx_actor() OR shortlink.ctx_is_global())
    WITH CHECK (owner_id = shortlink.ctx_actor() OR shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE ON shortlink.api_credentials TO awshortlink_app;

CREATE POLICY rls_022_settings_select ON shortlink.app_settings FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_actor() IS NOT NULL);
CREATE POLICY rls_022_settings_write ON shortlink.app_settings FOR ALL TO awshortlink_app
    USING (shortlink.ctx_is_global())
    WITH CHECK (shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE ON shortlink.app_settings TO awshortlink_app;

CREATE POLICY rls_022_heartbeats_select ON shortlink.ops_heartbeats FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_is_global());
CREATE POLICY rls_022_heartbeats_write ON shortlink.ops_heartbeats FOR ALL TO awshortlink_app
    USING (shortlink.ctx_is_global())
    WITH CHECK (shortlink.ctx_is_global());
GRANT SELECT, INSERT, UPDATE ON shortlink.ops_heartbeats TO awshortlink_app;

CREATE POLICY rls_022_abuse_select ON shortlink.abuse_reports FOR SELECT TO awshortlink_app
    USING (shortlink.ctx_is_global() OR unit_id = ANY (shortlink.ctx_unit_ids()));
CREATE POLICY rls_022_abuse_insert_app ON shortlink.abuse_reports FOR INSERT TO awshortlink_app
    WITH CHECK (shortlink.ctx_actor() IS NOT NULL);
CREATE POLICY rls_022_abuse_insert_public ON shortlink.abuse_reports FOR INSERT TO awshortlink_resolver
    WITH CHECK (status = 'open' AND resolved_by IS NULL);
CREATE POLICY rls_022_abuse_update ON shortlink.abuse_reports FOR UPDATE TO awshortlink_app
    USING (shortlink.ctx_is_global() OR unit_id = ANY (shortlink.ctx_unit_ids()))
    WITH CHECK (shortlink.ctx_is_global() OR unit_id = ANY (shortlink.ctx_unit_ids()));
GRANT SELECT, INSERT, UPDATE ON shortlink.abuse_reports TO awshortlink_app;
GRANT INSERT ON shortlink.abuse_reports TO awshortlink_resolver;

CREATE POLICY rls_022_health_select ON shortlink.link_health_checks FOR SELECT TO awshortlink_app
    USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY rls_022_health_insert ON shortlink.link_health_checks FOR INSERT TO awshortlink_app
    WITH CHECK (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
GRANT SELECT, INSERT ON shortlink.link_health_checks TO awshortlink_app;

-- RLS-023: link_access_logs (detailed visitor telemetry)
ALTER TABLE shortlink.link_access_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE shortlink.link_access_logs FORCE ROW LEVEL SECURITY;
-- Unit-scoped: a row is visible only if its link is visible, and `links` is itself unit-scoped by RLS.
CREATE POLICY rls_023_access_logs_select ON shortlink.link_access_logs FOR SELECT TO awshortlink_app
    USING (EXISTS (SELECT 1 FROM shortlink.links l WHERE l.id = link_access_logs.link_id));
-- Retention purge (schedule:run) runs in the global system context only.
CREATE POLICY rls_023_access_logs_delete ON shortlink.link_access_logs FOR DELETE TO awshortlink_app
    USING (shortlink.ctx_is_global());
CREATE POLICY rls_023_access_logs_insert_app ON shortlink.link_access_logs FOR INSERT TO awshortlink_app
    WITH CHECK (true);
CREATE POLICY rls_023_access_logs_insert_resolver ON shortlink.link_access_logs FOR INSERT TO awshortlink_resolver
    WITH CHECK (true);
GRANT SELECT, INSERT, DELETE ON shortlink.link_access_logs TO awshortlink_app;
GRANT SELECT, INSERT ON shortlink.link_access_logs TO awshortlink_resolver;

-- Backup role (DES-010): SELECT on all tables and sequences for pg_dump
GRANT SELECT ON ALL TABLES IN SCHEMA shortlink TO awshortlink_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA shortlink TO awshortlink_backup;

RESET ROLE;
