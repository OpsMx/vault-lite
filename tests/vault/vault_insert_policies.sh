#!/usr/bin/env bash
#

set -e

POLICY_KEY=pipeline_verification
POLICY_DIR="../policies"
POLICY_FILE=${POLICY_DIR}/${POLICY_KEY}.sentinel
POLICY_LEVEL=hard-mandatory
POLICY_PATHS="kv-v2/pipelines/${POLICY_KEY}"
POLICY_PATHS="kv-v2/spinnaker/pipelines/${POLICY_KEY}"
POLICY_INPUTS_DIR="../inputs"
POLICY_GOOD="${POLICY_INPUTS_DIR}/execution_context.input"
POLICY_BAD="${POLICY_INPUTS_DIR}/fail.input"

. $(git rev-parse --show-toplevel)/tests/.env

export VAULT_ADDR
POLICY=$(base64 ${POLICY_FILE})
writePolicy=$(vault write sys/policies/egp/${POLICY_KEY} \
  	policy="${POLICY}" \
  	paths="${POLICY_PATHS}" \
  	enforcement_level="${POLICY_LEVEL}")
echo "wr: $writePolicy"
