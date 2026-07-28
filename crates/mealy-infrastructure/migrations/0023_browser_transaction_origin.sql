-- browser.transact materializes omitted optional arrays before approval. Its security-sensitive
-- initial URL must already be canonical, preserving exact provider-origin proof.
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
                  effect.tool_id NOT IN ('image.generate', 'browser.transact')
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
              OR
              (
                  effect.tool_id = 'browser.transact'
                  AND json_type(attempt.response_json, '$.arguments.initialUrl') = 'text'
                  AND json_extract(attempt.response_json, '$.arguments.initialUrl')
                      = json_extract(intent.normalized_arguments_json, '$.initialUrl')
                  AND json_type(attempt.response_json, '$.arguments.formDigest') = 'text'
                  AND json_extract(attempt.response_json, '$.arguments.formDigest')
                      = json_extract(intent.normalized_arguments_json, '$.formDigest')
                  AND (
                      json_type(attempt.response_json, '$.arguments.fields') IS NULL
                      OR json_type(attempt.response_json, '$.arguments.fields') = 'array'
                  )
                  AND json(
                        COALESCE(
                            json_extract(attempt.response_json, '$.arguments.fields'),
                            '[]'
                        )
                      ) = json(json_extract(intent.normalized_arguments_json, '$.fields'))
                  AND (
                      json_type(attempt.response_json, '$.arguments.uploads') IS NULL
                      OR json_type(attempt.response_json, '$.arguments.uploads') = 'array'
                  )
                  AND json(
                        COALESCE(
                            json_extract(attempt.response_json, '$.arguments.uploads'),
                            '[]'
                        )
                      ) = json(json_extract(intent.normalized_arguments_json, '$.uploads'))
                  AND (
                      (
                          json_type(attempt.response_json, '$.arguments.submitter') IS NULL
                          OR json_type(attempt.response_json, '$.arguments.submitter') = 'null'
                      )
                      AND json_type(intent.normalized_arguments_json, '$.submitter') IS NULL
                      OR
                      json_type(attempt.response_json, '$.arguments.submitter') = 'object'
                      AND json(json_extract(attempt.response_json, '$.arguments.submitter'))
                          = json(json_extract(intent.normalized_arguments_json, '$.submitter'))
                  )
                  AND NOT EXISTS(
                      SELECT 1
                      FROM json_each(
                          json_extract(attempt.response_json, '$.arguments')
                      ) raw_argument
                      WHERE raw_argument.key NOT IN (
                          'initialUrl', 'formDigest', 'fields', 'submitter', 'uploads'
                      )
                  )
                  AND (
                      SELECT COUNT(*) FROM json_each(intent.normalized_arguments_json)
                  ) = 4 + CASE
                      WHEN json_type(
                          intent.normalized_arguments_json, '$.submitter'
                      ) = 'object' THEN 1
                      ELSE 0
                  END
              )
          )
    ) THEN RAISE(ABORT, 'agent effect origin does not match normalized model result') END;
END;
