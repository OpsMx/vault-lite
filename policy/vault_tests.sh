#!/usr/bin/env bash
#

set -e

POLICY_KEY=pipeline_verification
POLICY_FILE=${POLICY_KEY}.sentinel
POLICY_LEVEL=hard-mandatory
POLICY_PATHS="kv-v2/pipelines/time"
POLICY_GOOD=""
POLICY_BAD=""

. .env

export VAULT_ADDR
POLICY=$(base64 ${POLICY_FILE})
vault write sys/policies/egp/${POLICY_KEY} \
	policy="${POLICY}" \
	paths="${POLICY_PATHS}" \
	enforcement_level="${POLICY_LEVEL}"
vault read sys/policies/egp/${POLICY}
vault kv put ${POLICY_PATHS} @execution_context.input
