#!/usr/bin/env bash
#
# https://learn.hashicorp.com/vault/identity-access-management/iam-sentinel
#
# Simple script to do some policy insertions
# a) for testing vault lite
# b) for demoing sentinel integration
#

# We are only this, norhing else yet.
LEVEL="hard-mandatory"
# We don't care about the path yet, should be used though for uniqueness
PATHS="kv-v2/spinnaker/pipelines"
TOKEN="my-secret-vault-token"
PAYLOAD=".payload.json"
POLICIES="../policies"

. $(git rev-parse --show-toplevel)/tests/.env

for policy in `ls -1 ${POLICIES}/*.sentinel`; do
  filename=${policy##*/}
  EGP=$( echo $filename| awk -F\. '{ print $1 }')
  POLICY=$(base64 ${policy})
  tee ${PAYLOAD} <<EOF
  {
    "policy": "${POLICY}",
    "paths": ["${PATHS}", "${PATHS}/${EGP}"],
    "enforcement_level": "${LEVEL}"
  }
EOF
  curl --header "X-Vault-Token: ${TOKEN}" \
         --request PUT \
         --data @${PAYLOAD} \
         ${VAULT_ADDR}/v1/sys/policies/egp/${EGP}
  # rm ${PAYLOAD}
done
