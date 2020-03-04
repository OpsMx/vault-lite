#!/usr/bin/env bash
#

. .env

curl --request LIST ${VAULT_ADDR}/v1/sys/policies/egp
