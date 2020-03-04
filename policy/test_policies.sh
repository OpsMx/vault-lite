#!/usr/bin/env bash

POLICY="pipeline_verification"
INPUT="execution_context.input"
ENDPOINT="http://127.0.0.1:8001"

curl --request POST ${ENDPOINT}/v1/kv-v2/spinnaker/pipelines
