-- One provider tool call owns one all-or-nothing child group. Serial delegations are migrated as
-- one-child groups so existing evidence and result semantics remain intact.
CREATE TABLE delegation_group (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    parent_run_id TEXT NOT NULL REFERENCES run(id) ON DELETE RESTRICT,
    parent_tool_call_id TEXT REFERENCES tool_call(tool_call_id) ON DELETE RESTRICT,
    mode TEXT NOT NULL CHECK (mode IN ('serial', 'parallel')),
    completion_policy TEXT NOT NULL CHECK (completion_policy = 'all_terminal'),
    child_count INTEGER NOT NULL CHECK (child_count BETWEEN 1 AND 8),
    state TEXT NOT NULL CHECK (state IN ('active', 'settled')),
    created_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    UNIQUE (parent_run_id, parent_tool_call_id),
    CHECK (
        (mode = 'serial' AND child_count = 1)
        OR
        (mode = 'parallel' AND child_count BETWEEN 2 AND 8)
    ),
    CHECK (
        (state = 'active' AND completed_at_ms IS NULL)
        OR
        (state = 'settled' AND completed_at_ms IS NOT NULL
         AND completed_at_ms >= created_at_ms)
    )
) STRICT;

ALTER TABLE delegation ADD COLUMN group_id TEXT
    REFERENCES delegation_group(id) ON DELETE RESTRICT;
ALTER TABLE delegation ADD COLUMN group_ordinal INTEGER
    CHECK (group_ordinal IS NULL OR group_ordinal BETWEEN 1 AND 8);
ALTER TABLE delegation ADD COLUMN child_key TEXT CHECK (
    child_key IS NULL OR (
        length(CAST(child_key AS BLOB)) BETWEEN 1 AND 64
        AND child_key NOT GLOB '*[^a-z0-9._-]*'
        AND substr(child_key, 1, 1) GLOB '[a-z0-9]'
    )
);

INSERT INTO delegation_group(
    id, parent_run_id, parent_tool_call_id, mode, completion_policy, child_count, state,
    created_at_ms, completed_at_ms
)
SELECT
    delegation.id,
    delegation.parent_run_id,
    CASE
        WHEN EXISTS(
            SELECT 1 FROM tool_call
            WHERE tool_call.tool_call_id =
                json_extract(delegation.context_package_json, '$.parentToolCallId')
              AND tool_call.run_id = delegation.parent_run_id
        )
        THEN json_extract(delegation.context_package_json, '$.parentToolCallId')
        ELSE NULL
    END,
    'serial',
    'all_terminal',
    1,
    CASE
        WHEN delegation.state IN ('queued', 'running') THEN 'active'
        ELSE 'settled'
    END,
    delegation.created_at_ms,
    delegation.completed_at_ms
FROM delegation;

UPDATE delegation
SET group_id = id, group_ordinal = 1, child_key = 'result';

CREATE UNIQUE INDEX delegation_group_ordinal_idx
    ON delegation(group_id, group_ordinal);
CREATE UNIQUE INDEX delegation_group_child_key_idx
    ON delegation(group_id, child_key);
CREATE INDEX delegation_group_parent_state_idx
    ON delegation_group(parent_run_id, state, created_at_ms, id);

CREATE TRIGGER delegation_group_child_insert
BEFORE INSERT ON delegation
BEGIN
    SELECT CASE WHEN NEW.group_id IS NULL
        OR NEW.group_ordinal IS NULL
        OR NEW.child_key IS NULL
        OR NOT EXISTS(
            SELECT 1 FROM delegation_group child_group
            WHERE child_group.id = NEW.group_id
              AND child_group.parent_run_id = NEW.parent_run_id
              AND child_group.state = 'active'
              AND NEW.group_ordinal <= child_group.child_count
              AND (
                  child_group.parent_tool_call_id IS NULL
                  OR EXISTS(
                      SELECT 1 FROM tool_call
                      WHERE tool_call.tool_call_id = child_group.parent_tool_call_id
                        AND tool_call.run_id = child_group.parent_run_id
                        AND tool_call.state IN ('prepared', 'running')
                  )
              )
        )
    THEN RAISE(ABORT, 'delegation group child binding is inconsistent') END;
END;

CREATE TRIGGER delegation_group_identity_immutable
BEFORE UPDATE OF group_id, group_ordinal, child_key ON delegation
BEGIN
    SELECT RAISE(ABORT, 'delegation group child identity is immutable');
END;

CREATE TRIGGER delegation_group_contract_immutable
BEFORE UPDATE OF
    parent_run_id, parent_tool_call_id, mode, completion_policy, child_count, created_at_ms
ON delegation_group
BEGIN
    SELECT RAISE(ABORT, 'delegation group contract is immutable');
END;

CREATE TRIGGER delegation_group_settlement
BEFORE UPDATE OF state, completed_at_ms ON delegation_group
WHEN NEW.state = 'settled'
BEGIN
    SELECT CASE WHEN OLD.state <> 'active'
        OR NEW.completed_at_ms IS NULL
        OR (
            SELECT COUNT(*) FROM delegation
            WHERE delegation.group_id = NEW.id
        ) <> NEW.child_count
        OR EXISTS(
            SELECT 1 FROM delegation
            WHERE delegation.group_id = NEW.id
              AND delegation.state IN ('queued', 'running')
        )
        OR NEW.completed_at_ms < COALESCE(
            (SELECT MAX(completed_at_ms) FROM delegation WHERE group_id = NEW.id),
            NEW.created_at_ms
        )
    THEN RAISE(ABORT, 'delegation group cannot settle before every child is terminal') END;
END;

CREATE TRIGGER delegation_group_no_reopen
BEFORE UPDATE OF state, completed_at_ms ON delegation_group
WHEN OLD.state = 'settled'
BEGIN
    SELECT RAISE(ABORT, 'settled delegation group is immutable');
END;

CREATE TRIGGER delegation_group_no_delete
BEFORE DELETE ON delegation_group
BEGIN
    SELECT RAISE(ABORT, 'delegation group evidence is immutable');
END;
