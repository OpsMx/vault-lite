Vault-lite is by no means a full vault implementation. It's meant as a
testing and implementation harness for Sentinel policies that can be
placed in Vault as a policy endpoint. Vault-lite should allow for easy
implementation and testing of Policies with Sentinel as one would do through
enterprise Vault. It by no means implements any of the other enforcement
components vault does.

TODO:
  * Fix ok return code on policy Validation Ok
  * Fix input format, now we're sending in the full Mock
    should be split in context, and then build the mock based
    on params + context..
    1) Initially just build the context / mock builder
    2) Build the params insertion

  Fix name globbing pickup of policies...
  Fix logging
  Returning of data https://learn.hashicorp.com/vault/getting-started/first-secret
  https://github.com/hashicorp/vault/blob/master/api/secret.go
  Supports no namespaces
  Supports no secrets

Vault, and HTTP test examples are in the policy dir
