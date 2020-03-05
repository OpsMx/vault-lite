#!/usr/bin/env bash

POLICY="spinnaker/pipelines"
POLICY="pipelines/pipeline_verification"
POLICY="spinnaker/pipelines/pipeline_verification"

INPUT="execution_context.input"

. .env

curl --request POST \
    --data @${INPUT} \
    ${VAULT_ADDR}/v1/kv-v2/${POLICY}
