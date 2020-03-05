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
readPolicy=$(vault read sys/policies/egp/${POLICY_KEY})
echo "rd: $reacPolicy"
