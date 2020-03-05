#!/usr/bin/env bash
#

set -e

POLICY_KEY=pipeline_verification
POLICY_FILE=${POLICY_KEY}.sentinel
POLICY_LEVEL=hard-mandatory
POLICY_PATHS="kv-v2/pipelines/${POLICY_KEY}"
POLICY_PATHS="kv-v2/spinnaker/pipelines/${POLICY_KEY}"
POLICY_GOOD=""
POLICY_BAD=""

. .env

export VAULT_ADDR
POLICY=$(base64 ${POLICY_FILE})
# writePolicy=$(vault write sys/policies/egp/${POLICY_KEY} \
#  	policy="${POLICY}" \
#  	paths="${POLICY_PATHS}" \
#  	enforcement_level="${POLICY_LEVEL}")
# echo "wr: $writePolicy"
# readPolicy=$(vault read sys/policies/egp/${POLICY_KEY})
# echo "rd: $reacPolicy"
successPolicy=$(vault kv put ${POLICY_PATHS} @execution_context.input)
# failPolicy=$(vault kv put ${POLICY_PATHS} @fail.input)

echo "sp: $successPolicy"
# failPolicy=$(vault kv put ${POLICY_PATHS} fail=me)
# echo "fp: $failPolicy"