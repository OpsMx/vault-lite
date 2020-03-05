#!/usr/bin/env bash
#

. $(git rev-parse --show-toplevel)/tests/.env

curl --request LIST ${VAULT_ADDR}/v1/sys/policies/egp
