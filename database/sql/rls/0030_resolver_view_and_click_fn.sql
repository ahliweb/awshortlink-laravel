-- 0030_resolver_view_and_click_fn.sql: Isolated public resolver surface & bounded click counter (ALG-003, ALG-005, DES-003, DES-011)
-- Owned by awshortlink_owner; awshortlink_resolver has SELECT on the view and EXECUTE on record_click() only.

SET ROLE awshortlink_owner;
SET search_path = shortlink, pg_catalog;

DROP VIEW IF EXISTS shortlink.public_resolvable_links;
CREATE VIEW shortlink.public_resolvable_links WITH (security_barrier = true) AS
SELECT
    l.id AS id,
    l.id AS link_id,
    l.unit_id,
    l.namespace,
    l.slug_normalized AS slug,
    l.title,
    l.visibility,
    l.retired_public_message,
    CASE
        WHEN l.status = 'active'
             AND l.published_at <= now()
             AND (l.expires_at IS NULL OR l.expires_at > now())
             AND d.id IS NOT NULL
        THEN 'active'
        WHEN (l.status = 'archived' OR (l.status = 'active' AND l.expires_at <= now()))
             AND l.retired_public_message = true
        THEN 'retired'
        ELSE 'unavailable'
    END AS status,
    CASE
        WHEN l.status = 'active'
             AND l.published_at <= now()
             AND (l.expires_at IS NULL OR l.expires_at > now())
        THEN d.url_canonical
        ELSE NULL
    END AS target_url,
    l.expires_at
FROM shortlink.links l
LEFT JOIN shortlink.link_destinations d
       ON d.id = l.current_destination_id
      AND d.link_id = l.id
      AND d.status = 'current'
WHERE l.published_at IS NOT NULL;

REVOKE ALL ON shortlink.public_resolvable_links FROM PUBLIC;
GRANT SELECT ON shortlink.public_resolvable_links TO awshortlink_resolver, awshortlink_app, awshortlink_backup;

-- Narrow SECURITY DEFINER function for bounded daily click aggregation (DES-011)
CREATE OR REPLACE FUNCTION shortlink.record_click(
    p_link_id uuid,
    p_bot_class smallint DEFAULT 0,
    p_channel_code text DEFAULT ''
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = shortlink, pg_temp
AS $$
DECLARE
    v_unit_id uuid;
    v_safe_channel text;
BEGIN
    IF p_link_id IS NULL OR p_bot_class < 0 OR p_bot_class > 3 THEN
        RAISE EXCEPTION 'Invalid record_click parameters' USING ERRCODE = '22023';
    END IF;

    -- Synthetic health probes (bot_class = 3) are never counted in campaign analytics
    IF p_bot_class = 3 THEN
        RETURN;
    END IF;

    SELECT l.unit_id INTO v_unit_id
    FROM shortlink.links l
    WHERE l.id = p_link_id
      AND l.status = 'active'
      AND l.published_at IS NOT NULL
      AND l.published_at <= now()
      AND (l.expires_at IS NULL OR l.expires_at > now());

    IF v_unit_id IS NULL THEN
        RETURN;
    END IF;

    v_safe_channel := coalesce(regexp_replace(lower(p_channel_code), '[^a-z0-9_-]', '', 'g'), '');

    INSERT INTO shortlink.link_daily_stats (
        link_id,
        unit_id,
        date_utc,
        channel_code,
        valid_clicks,
        suspected_bot,
        rejected,
        updated_at
    )
    VALUES (
        p_link_id,
        v_unit_id,
        (now() AT TIME ZONE 'UTC')::date,
        v_safe_channel,
        CASE WHEN p_bot_class = 0 THEN 1 ELSE 0 END,
        CASE WHEN p_bot_class IN (1, 2) THEN 1 ELSE 0 END,
        0,
        now()
    )
    ON CONFLICT (link_id, date_utc, channel_code)
    DO UPDATE SET
        valid_clicks = shortlink.link_daily_stats.valid_clicks + EXCLUDED.valid_clicks,
        suspected_bot = shortlink.link_daily_stats.suspected_bot + EXCLUDED.suspected_bot,
        updated_at = now();
END;
$$;

REVOKE ALL ON FUNCTION shortlink.record_click(uuid, smallint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION shortlink.record_click(uuid, smallint, text) TO awshortlink_resolver, awshortlink_app;

-- Narrow SECURITY DEFINER function to serialize hash-chain appends and return ONLY the latest row_hash
-- without exposing cross-unit audit payloads to unit-scoped transactions (#18).
CREATE OR REPLACE FUNCTION shortlink.audit_chain_tail() RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = shortlink, pg_catalog
AS $$
DECLARE
    v_tail text;
BEGIN
    PERFORM pg_advisory_xact_lock(20261101);
    SELECT row_hash INTO v_tail
    FROM shortlink.link_audit_events
    ORDER BY id DESC
    LIMIT 1;

    RETURN coalesce(v_tail, encode(sha256('AWSHORTLINK-GENESIS-V1'::bytea), 'hex'));
END;
$$;

REVOKE ALL ON FUNCTION shortlink.audit_chain_tail() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION shortlink.audit_chain_tail() TO awshortlink_app;

RESET ROLE;
