#!/usr/bin/env bash

POLICY="spinnaker/pipelines"
POLICY="pipelines/pipeline_verification"
POLICY="spinnaker/pipelines/pipeline_verification"

INPUT="../inputs/execution_context.input"

. $(git rev-parse --show-toplevel)/tests/.env

curl --request POST \
    --data @${INPUT} \
    ${VAULT_ADDR}/v1/kv-v2/${POLICY}
