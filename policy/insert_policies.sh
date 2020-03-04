#!/usr/bin/env bash
#
# https://learn.hashicorp.com/vault/identity-access-management/iam-sentinel
#
# Simple script to do some policy insertions
# a) for testing vault lite
# b) for demoing sentinel integration
#

# Sample policy to push
FILE="time.sentinel"
# We are only this, norhing else yet.
LEVEL="hard-mandatory"
# We don't care about the path yet, should be used though for uniqueness
PATHS="secrets/spinnaker/*"
TOKEN="my-secret-vault-token"
ENDPOINT="http://127.0.0.1:8001"
PAYLOAD=".payload.json"

for policy in `ls -1 *.sentinel`; do
  EGP=$( echo $policy | awk -F\. '{ print $1 }')
  POLICY=$(base64 ${policy})
  tee ${PAYLOAD} <<EOF
  {
    "policy": "${POLICY}",
    "paths": ["${PATHS}"],
    "enforcement_level": "${LEVEL}"
  }
EOF

  curl --header "X-Vault-Token: ${TOKEN}" \
         --request PUT \
         --data @${PAYLOAD} \
         ${ENDPOINT}/v1/sys/policies/egp/${EGP}
  # rm ${PAYLOAD}
done
