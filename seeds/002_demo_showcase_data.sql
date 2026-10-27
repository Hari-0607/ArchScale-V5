-- =============================================================================
-- Seed 002: Executive Demonstration Data for ArchScale Authorisation Layer
-- =============================================================================

DO $$
DECLARE
    v_founder_uid UUID;
    v_founder_mem UUID;
    v_owner_uid UUID;
    v_leader_uid UUID;
    v_intern_uid UUID;
    v_collab_uid UUID;
    v_org_id UUID;
    v_owner_mem UUID;
    v_leader_mem UUID;
    v_intern_mem UUID;
    v_collab_mem UUID;
    v_ws_id UUID;
    v_ws_tower UUID;
    v_seat_limits JSONB;
    v_req_id UUID;
    v_lreq_id UUID;
    v_ireq_id UUID;
    v_ctx_id UUID;
BEGIN
    -- 1. Setup Platform Founder User & Membership
    IF NOT EXISTS (SELECT 1 FROM users WHERE user_code = 'USR-FOUNDER-01') THEN
        INSERT INTO users (user_code, email) 
        VALUES ('USR-FOUNDER-01', 'clara.oswald@archscale.io') 
        RETURNING id INTO v_founder_uid;

        INSERT INTO memberships (user_id, organisation_id, role_key, status)
        VALUES (v_founder_uid, '00000000-0000-0000-0000-000000000001', 'founder', 'ACTIVE')
        RETURNING id INTO v_founder_mem;
    ELSE
        SELECT id INTO v_founder_uid FROM users WHERE user_code = 'USR-FOUNDER-01';
        SELECT id INTO v_founder_mem FROM memberships WHERE user_id = v_founder_uid;
    END IF;

    -- 2. Setup Ecosystem Applications
    INSERT INTO app_catalogue (app_key, name, description)
    VALUES ('app_bim', 'ArchScale BIM Studio', 'Collaborative 3D Building Information Modeling Suite')
    ON CONFLICT (app_key) DO UPDATE SET name = EXCLUDED.name;

    INSERT INTO app_catalogue (app_key, name, description)
    VALUES ('app_contracts', 'ArchScale Smart Contracts', 'Automated construction contracting & milestone escrow')
    ON CONFLICT (app_key) DO UPDATE SET name = EXCLUDED.name;

    -- 3. Setup Subscriber Organisation (Metropolis Architecture Studio)
    IF NOT EXISTS (SELECT 1 FROM organisations WHERE name = 'Metropolis Architecture Studio') THEN
        INSERT INTO users (user_code, email) 
        VALUES ('USR-OWNER-01', 'marcus.vance@metropolis.design') 
        RETURNING id INTO v_owner_uid;

        INSERT INTO organisations (name, portal, tenant_type_key, status)
        VALUES ('Metropolis Architecture Studio', 'subscriber', 'studio_owner', 'APPLIED')
        RETURNING id INTO v_org_id;

        INSERT INTO access_requests (request_type, requester_user_id, organisation_id, justification, requested_apps)
        VALUES ('organisation', v_owner_uid, v_org_id, 'Enterprise Tier Studio Onboarding for 45 architects', ARRAY['app_bim', 'app_contracts'])
        RETURNING id INTO v_req_id;

        v_seat_limits := '[
            {"app_key": "app_bim", "role_key": "business_owner", "seat_limit": 2},
            {"app_key": "app_bim", "role_key": "leader", "seat_limit": 2},
            {"app_key": "app_bim", "role_key": "intern", "seat_limit": 1},
            {"app_key": "app_contracts", "role_key": "business_owner", "seat_limit": 1}
        ]'::jsonb;

        -- Approve organisation via stored procedure
        PERFORM fn_approve_organisation(
            v_req_id,
            v_founder_mem,
            'studio_owner',
            ARRAY['app_bim', 'app_contracts'],
            v_seat_limits,
            v_owner_uid,
            'Approved by Executive Governance Board'
        );

        SELECT id INTO v_owner_mem FROM memberships WHERE user_id = v_owner_uid AND organisation_id = v_org_id;

        -- Workspaces
        INSERT INTO workspaces (organisation_id, name, is_default)
        VALUES (v_org_id, 'Metropolis HQ Studio', true)
        RETURNING id INTO v_ws_id;

        INSERT INTO workspaces (organisation_id, name, is_default)
        VALUES (v_org_id, 'Skyline Tower Project', false)
        RETURNING id INTO v_ws_tower;

        -- Team Leader: Elena Rostova
        INSERT INTO users (user_code, email) 
        VALUES ('USR-LEAD-01', 'elena.rostova@metropolis.design') 
        RETURNING id INTO v_leader_uid;

        INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification, requested_apps)
        VALUES ('membership', v_leader_uid, v_org_id, 'leader', 'Lead Project Architect on Skyline Tower', ARRAY['app_bim'])
        RETURNING id INTO v_lreq_id;
        
        PERFORM fn_approve_membership(
            v_lreq_id,
            v_owner_mem,
            'Approved for lead role by Marcus Vance'
        );
        SELECT id INTO v_leader_mem FROM memberships WHERE user_id = v_leader_uid;

        -- Intern: Alex Chen (Requires Expiry)
        INSERT INTO users (user_code, email) 
        VALUES ('USR-INT-01', 'alex.chen@metropolis.design') 
        RETURNING id INTO v_intern_uid;

        INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification, requested_apps, requested_duration)
        VALUES ('membership', v_intern_uid, v_org_id, 'intern', 'Graduate Architecture Intern - 90 Days Cohort', ARRAY['app_bim'], interval '90 days')
        RETURNING id INTO v_ireq_id;

        PERFORM fn_approve_membership(
            v_ireq_id,
            v_owner_mem,
            'Approved intern placement with 90-day timebound access'
        );
        SELECT id INTO v_intern_mem FROM memberships WHERE user_id = v_intern_uid;

        -- External Collaborator: David Kim (Structural Engineer)
        INSERT INTO users (user_code, email)
        VALUES ('USR-COLLAB-01', 'david.kim@apex-engineers.test')
        RETURNING id INTO v_collab_uid;

        INSERT INTO memberships (user_id, organisation_id, role_key, status, expires_at)
        VALUES (v_collab_uid, v_org_id, 'collaborator', 'ACTIVE', now() + interval '60 days')
        RETURNING id INTO v_collab_mem;

        -- Active Access Context (Session for Elena Rostova)
        INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at)
        VALUES (v_leader_uid, 'sess-elena-bim-01', v_org_id, v_ws_tower, v_leader_mem, now() + interval '14 hours')
        RETURNING id INTO v_ctx_id;

        -- Share Grant (Sharing Skyline Tower Project with External Collaborator)
        INSERT INTO share_grants (source_organisation_id, target_user_id, resource_type, resource_id, granted_by, expires_at)
        VALUES (v_org_id, v_collab_uid, 'workspace', v_ws_tower::text, v_owner_mem, now() + interval '30 days');

        -- Populate initial realistic audit records
        INSERT INTO audit_logs (organisation_id, actor_user_id, action, target_entity, target_id, diff)
        VALUES 
            (v_org_id, v_founder_uid, 'ORGANISATION_APPROVED', 'organisations', v_org_id::text, '{"portal":"subscriber","tier":"enterprise"}'),
            (v_org_id, v_owner_uid, 'MEMBERSHIP_APPROVED', 'memberships', v_leader_mem::text, '{"role":"leader","apps":["app_bim"]}'),
            (v_org_id, v_owner_uid, 'MEMBERSHIP_APPROVED', 'memberships', v_intern_mem::text, '{"role":"intern","duration":"90 days"}'),
            (v_org_id, v_leader_uid, 'CONTEXT_GENERATED', 'access_contexts', v_ctx_id::text, '{"workspace":"Skyline Tower Project","session":"sess-elena-bim-01"}');
    END IF;
END $$;
