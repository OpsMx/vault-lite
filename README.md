## Vault-lite
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

## TODO:
  * move policy saving to tmp space in the container
  * move config to .env file
  * use default vault and build in sentinel as a backend...
    - downside is the whole consul circus is required
    - this should be doable with the sdk, or as a builtin
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



## Background
Sentinel today is part of closed source HashiCorp Enterprise, where it integrates
with several components; Vault, Terraform and Consul. As it is closed source
integration is problematic. An option to create "modules" is there, but the modules
are outbound facing. This means that a module is able to retrieve data / information
for HashiCorp's integrated enterprise products, but not vice versa. As an external
software company you're not able to use Sentinel directly E.g. A customer /
company wants to use a single policy engine and tie non HashiCorp, their own,
applications into Sentinel.

It is possible to run Sentinel standalone and wrap policy, although hashiCorp
advises against that, possibly due to the security risks involved. Also running
this way would mean the policy delivery mechanism and feedback loop would go missing.
Which both get tied together today in HashiCorp Enterprise. It would be advisable
to use an intermediary to communicate with Sentinel, e.g. use one of the other
integrated products to except the JSON and have sentinel evaluate that and have
the ability to parse out the result of the evaluation.
An option here is to bundle Sentinel with the proxy, and have Policy Portability.
Where we create an API endpoint that supports Sentinel's Language, and OPA to
enforce policy. Giving customers the possibility to at least use their preferred
policy language (I'd not go for this though.

This would mean pushing in an EGP (Endpoint Governing Policy) or
(Role Governing Policy)

When creating Sentinel based policies through Vault the (properties)[https://www.vaultproject.io/docs/enterprise/sentinel/properties/]
when writing the policy are important. For Spinnaker the request properties will
be leading to retrieve the actual request that was done.

This means the policy proxy has to be integrated with Vault to push the contents
to vault, but also have the ability to interpret the resulting return from it.
The theory for now is that the JSON would come into the policy proxy, move to
vault, where it is pushed under a namespace that has Sentinel Policies applied
to it. Sentinel will trigger based on the insertion, which in turn will evaluate
the policy. Depending on what the result of that is, and if the result's feedback
actually comes out, we can relay the result back to Spinnaker. If this turns out
to be a lengthy process this could be solved with an async call that waits for
the results.

The last scenario advocates for moving from a custom stage to a Plugin, or having
a more solid integration.

The details of the KV integration would look somewhat like https://github.com/hashicorp/vault-guides/tree/master/governance/validation-policies,
and https://github.com/trodemaster/sentinel-sandbox. The first outlines the
creation of policies in Vault combined with Sentinel, and then pushing a KV to
Vault. The same can be done for the JSON that is generated by Spinnaker. This
JSON can be pushed to vault, validated there, and the return is either Success
or not. If it is Success we know the validation passed. After this we delete
the data we pushed and are done.
