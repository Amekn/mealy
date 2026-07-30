-- The model supplies only an image prompt. The trusted daemon injects the immutable
-- operator-controlled provider/model/format/cost/output authority during normalization. Preserve
-- exact model provenance for ordinary effects while proving this intentionally asymmetric image
-- contract without pretending the model supplied the injected authority.
DROP TRIGGER agent_effect_invocation_origin_insert;

CREATE TRIGGER agent_effect_invocation_origin_insert
BEFORE INSERT ON agent_effect_invocation
BEGIN
    SELECT CASE WHEN NOT EXISTS(
        SELECT 1
        FROM effect_intent intent
        JOIN effect ON effect.id = intent.effect_id
        JOIN model_attempt attempt ON attempt.attempt_id = NEW.model_attempt_id
        WHERE intent.effect_id = NEW.effect_id
          AND intent.run_id = NEW.run_id
          AND intent.task_id = NEW.task_id
          AND effect.task_id = NEW.task_id
          AND effect.run_id = NEW.run_id
          AND attempt.run_id = NEW.run_id
          AND attempt.state = 'completed'
          AND attempt.response_kind = 'tool_call'
          AND json_extract(attempt.response_json, '$.kind') = 'tool_call'
          AND json_extract(attempt.response_json, '$.tool_id') = effect.tool_id
          AND (
              (
                  effect.tool_id <> 'image.generate'
                  AND json(json_extract(attempt.response_json, '$.arguments'))
                      = json(intent.normalized_arguments_json)
              )
              OR
              (
                  effect.tool_id = 'image.generate'
                  AND json(json_extract(attempt.response_json, '$.arguments'))
                      = json_object(
                          'prompt',
                          json_extract(intent.normalized_arguments_json, '$.prompt')
                        )
                  AND json_type(
                        intent.normalized_arguments_json, '$.maximumCostMicrounits'
                      ) = 'integer'
                  AND json_extract(
                        intent.normalized_arguments_json, '$.maximumCostMicrounits'
                      ) > 0
                  AND json_type(intent.normalized_arguments_json, '$.model') = 'text'
                  AND json_extract(intent.normalized_arguments_json, '$.outputFormat') = 'jpeg'
                  AND json_type(intent.normalized_arguments_json, '$.quality') = 'text'
                  AND json_type(intent.normalized_arguments_json, '$.size') = 'text'
                  AND (
                      SELECT COUNT(*) FROM json_each(intent.normalized_arguments_json)
                  ) = 6
              )
          )
    ) THEN RAISE(ABORT, 'agent effect origin does not match normalized model result') END;
END;

-- A governed external image generation reserves its complete approved financial and output
-- authority before the run is parked. Exactly one terminal settlement releases that reservation.
CREATE TABLE agent_effect_budget_reservation (
    effect_id TEXT PRIMARY KEY
        REFERENCES agent_effect_invocation(effect_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES run_budget_usage(run_id) ON DELETE RESTRICT,
    maximum_cost_microunits INTEGER NOT NULL CHECK (maximum_cost_microunits > 0),
    maximum_output_bytes INTEGER NOT NULL CHECK (maximum_output_bytes > 0),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'settled')),
    charged_cost_microunits INTEGER NOT NULL DEFAULT 0
        CHECK (charged_cost_microunits >= 0
               AND charged_cost_microunits <= maximum_cost_microunits),
    charged_output_bytes INTEGER NOT NULL DEFAULT 0
        CHECK (charged_output_bytes >= 0
               AND charged_output_bytes <= maximum_output_bytes),
    created_at_ms INTEGER NOT NULL,
    settled_at_ms INTEGER,
    UNIQUE(effect_id, run_id),
    FOREIGN KEY (effect_id, run_id)
        REFERENCES agent_effect_invocation(effect_id, run_id) ON DELETE RESTRICT,
    CHECK (
        (state = 'reserved' AND charged_cost_microunits = 0
         AND charged_output_bytes = 0 AND settled_at_ms IS NULL)
        OR
        (state = 'settled' AND settled_at_ms IS NOT NULL
         AND settled_at_ms >= created_at_ms)
    )
) STRICT;

CREATE INDEX agent_effect_budget_reservation_run_idx
    ON agent_effect_budget_reservation(run_id, state, created_at_ms, effect_id);

CREATE TRIGGER agent_effect_budget_reservation_insert_guard
BEFORE INSERT ON agent_effect_budget_reservation
BEGIN
    SELECT CASE WHEN NEW.state <> 'reserved'
        OR NOT EXISTS(
            SELECT 1
            FROM agent_effect_invocation invocation
            JOIN effect_intent intent ON intent.effect_id = invocation.effect_id
            WHERE invocation.effect_id = NEW.effect_id
              AND invocation.run_id = NEW.run_id
              AND json_extract(intent.descriptor_json, '$.toolId') = 'image.generate'
              AND intent.effect_class = 'non_idempotent'
              AND intent.idempotency_class = 'non_idempotent'
              AND intent.recovery_strategy = 'never_retry'
              AND intent.executor_kind = 'builtin'
              AND json_extract(
                    intent.normalized_arguments_json, '$.maximumCostMicrounits'
                  ) = NEW.maximum_cost_microunits
              AND json_extract(
                    intent.descriptor_json, '$.maximumOutputBytes'
                  ) = NEW.maximum_output_bytes
        )
    THEN RAISE(ABORT, 'image effect budget reservation does not match durable authority') END;
END;

CREATE TRIGGER agent_effect_budget_reservation_update_guard
BEFORE UPDATE ON agent_effect_budget_reservation
BEGIN
    SELECT CASE WHEN OLD.state <> 'reserved'
        OR NEW.state <> 'settled'
        OR NEW.effect_id <> OLD.effect_id
        OR NEW.run_id <> OLD.run_id
        OR NEW.maximum_cost_microunits <> OLD.maximum_cost_microunits
        OR NEW.maximum_output_bytes <> OLD.maximum_output_bytes
        OR NEW.created_at_ms <> OLD.created_at_ms
        OR NEW.settled_at_ms IS NULL
    THEN RAISE(ABORT, 'image effect budget reservation transition is invalid') END;
END;

CREATE TRIGGER agent_effect_budget_reservation_delete_guard
BEFORE DELETE ON agent_effect_budget_reservation
BEGIN
    SELECT RAISE(ABORT, 'image effect budget reservation is immutable');
END;
