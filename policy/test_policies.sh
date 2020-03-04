#!/usr/bin/env bash

POLICY="pipeline_verification"
INPUT="execution_context.input"

curl --request POST ${VAULT_ENDPOINT}/v1/kv-v2/spinnaker/pipelines
