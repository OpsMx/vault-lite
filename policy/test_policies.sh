#!/usr/bin/env bash

POLICY="pipeline_verification"
INPUT="execution_context.input"

. .env

curl --request POST ${VAULT_ADDR}/v1/kv-v2/spinnaker/pipelines
