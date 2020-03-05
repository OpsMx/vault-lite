#!/usr/bin/env bash
#

. $(git rev-parse --show-toplevel)/tests/.env

curl --request GET ${VAULT_ADDR}/v1/sys/policies/egp
curl --request GET ${VAULT_ADDR}/v1/sys/policies/egp/pipeline_verification
