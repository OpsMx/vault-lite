Vault-lite is by no means a full vault implementation. It's meant as a
testing and implementation harness for Sentinel policies that can be
placed in Vault as a policy endpoint. Vault-lite should allow for easy
implementation and testing of Policies with Sentinel as one would do through
enterprise Vault. It by no means implements any of the other enforcement
components vault does.

TODO: Fix name globbing pickup of policies...

Supports no namespaces
Supports no secrets

First off testing is done with HTTP calls, and later the Vault client (Not implemented now)
HTTP Calls:

Using Vault:
0) go get github.com/hashicorp/vault/api
1) export VAULT_ADDR="http://127.0.0.1:8001"
2)

TODO:
Implement the api.Secret as a Return, until then Vault marshalling will fail, CURL will work
https://github.com/hashicorp/vault/blob/master/api/secret.go


### Follow this implementation example
echo "Writing token-metadata.sentinel policy to vault egp"
vault write sys/policies/egp/token-metadata policy="${POLICY}" paths="kv-v2/*" enforcement_level="hard-mandatory"

echo "Reading the policy as stored in vault"
vault read sys/policies/egp/token-metadata

echo "Writing good data to kv-v2 from good_example.json"
vault kv put kv-v2/example @token_metadata_good_example.json

echo "Writing bad data to kv-v2 from bad_example.json"
vault kv put kv-v2/example @token_metadata_bad_example.json
