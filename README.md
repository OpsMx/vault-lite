Vault-lite is by no means a full vault implementation. It's meant as a
testing and implementation harness for Sentinel policies that can be
placed in Vault as a policy endpoint. Vault-lite should allow for easy
implementation and testing of Policies with Sentinel as one would do through
Enterprise Vault. It by no means implements any of the other enforcement
components vault does, it's just there to test policy.

Supports no secrets. Just policy validation with PUTs, can be expanded to
simulate secrets but checking if policies exist or not.

Supports no namespaces. No notion of namespaces, url namespaces can be used
but are not honored in any way.

TODO:
  * Review insertion of policies, seems like paths are not updated correctly
  * add globbing of policies, now only direct match is allowed now
    - ok now: kv-v2/spinnaker/pipelines/my_policy
    - not ok now: kv-v2/spinnaker/pipelines/*
    - however: kv-v2/spinnaker/pipeline is ok, instead of a regex..
  * transform error output to strings, for niceness
  * transform trace, and comment arrays to nice strings..
    https://learn.hashicorp.com/vault/getting-started/first-secret
    https://github.com/hashicorp/vault/blob/master/api/secret.go
  * Implement param insertion for policy. Now we don't support params.
    - Handle params from vault / curl
    - insert params where data prep (mock) is done. Add:
        {
          "param": {
            "token": "xxx",
            "ext_host": "http://192.168.121.1:8888/test.json"
          },
          "mock"
