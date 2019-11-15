Candid Configuration
==============================

Introduction
------------
This document describes the configuration options for the Candid
identity server.

Configuration File
------------------
Candid loads its configuration at startup from a YAML
file. In a usual installation this file is stored in
/etc/candid/config.yaml. An example configuration file is:

```yaml
listen-address: :8081
location: 'http://jujucharms.com/identity'
storage:
    type: mongodb
    address: localhost:27017
public-key: OAG9EVDFgXzWQKIk+MTxpLVO1Mp1Ws/pIkzhxv5Jk1M=
private-key: q2G3A2NjTe7MP9D8iugCH9XfBAyrnV8n8u8ACbNyNOY=
identity-providers:
- type: usso
```

Here is a description of the most commonly used configuration
options. Some less useful options are omitted here - the remaining
ones are all documented [here](https://godoc.org/github.com/CanonicalLtd/candid/config#Config).

### listen-address
(Required) This is the address that the service will listen on. This consists of
an optional host followed by a port. If the host is omitted then the
server will listen on all interface addresses. The port may be a well
known service name for example ":http".

### location
(Required) This is the externally addressable location of the Candid server API.
Candid needs to know its own address so that it can add third-party
caveats addressed to itself and to create response addresses for identity
providers such as OpenID that use browser redirection for communication.

### storage
Storage holds configuration for the storage backend used by the
server. See below for documentation on the supported storage backends.

### public-key & private-key
(Required) Services wishing to discharge caveats against this identity manager
encrypt their third party caveats using this public-key. The private
key is needed for the identity manager to be able to discharge those
caveats. You can use the `bakery-keygen` command (available
with `go install gopkg.in/macaroon-bakery.v2/cmd/bakery-keygen` to generate
a suitable key pair.

### access-log
The access-log configures the name of a file used to record all
accesses to the identity manager. If this is not configured then no
logging will take place.

### identity-providers
This is a list of the configured identity providers with their
configuration. See below for the supported identity providers. If this
is not configured then a default set of providers will be used
containing the Ubuntu SSO and Agent identity providers.

### api-macaroon-timeout
This is the maximum time a login to the /v1 API will remain logged
in for. As candid uses itself as it's authentication provider,
for all practical purpose the login time will be the minimum of
`api-macaroon-timeout` and `discharge-macaroon-timeout`. The default
value is 24 hours.

### discharge-macaroon-timeout
This is the maximum time the discharge macaroon will be valid for on
the target service. This is the maximum time the client will be able to
access the target service without requiring re-authentication. Note that
the target service may also have it's own maximum time.

### discharge-token-timeout
This is the maximum time that the discharge token issued to the client
can be used to discharge tokens without requiring re-authentication.

Storage Backends
-----------

The `storage` field holds an object containing a `type` field
which names the storage backend to use.

For example:

	storage:
	    type: mongodb
	    address: localhost:1234

Currently supported backends are:

### memory

The memory provider has no extra parameters. It stores
all data ephemerally in RAM.

### mongodb

This uses MongoDB for the backend. It has two parameters:

`address` (required) is the address of the mongoDB server to connect to,
in `host:port` form.

`database` holds the database name to use. If not specified, this will default to `candid`.

### postgres

This uses PostgresQL for the backend. It takes one parameter:

`connection-string` is the connection string to use when connecting to the database.
This is added to connection string parameters already present
as environment variables when making a connection.
See [here](https://godoc.org/github.com/lib/pq#hdr-Connection_String_Parameters)
for details.

Identity Providers
------------------
The identity manager can support a number of different identity
providers. These can be broken loosely into two categories,
interactive and custom. Interactive providers use html based forms in
some way to authorize the user and are compatible with the most basic
supported clients. Custom providers use a protocol not necessarily
supported in the client to provide additional authentication methods
that are not necessarily based around users interacting with web
pages. While it is possible to configure more than one interactive
identity provider in a given identity manager, in most case this does
not make sense as the identity manager will only use the first one
that is found.

### Agent
The agent identity provider is a custom provider that is always configured, and allows non-interactive
logins to clients using public-key authentication.
the agent protocol to log in. See
https://github.com/CanonicalLtd/candid/blob/master/docs/login.txt
for details on the agent login protocol.

### UbuntuSSO
```yaml
- type: usso
  launchpad-teams:
    - group1
    - group2
```

The UbuntuSSO identity provider is an interactive identity provider
that uses OpenID with UbuntuSSO to log in.

The launchpad-teams contains any private launchpad teams that candid needs to know about.

### UbuntuSSO OAuth
```yaml
- type: usso_oauth
```

The UbuntuSSO OAuth identity provider is an custom identity provider that
uses a previously obtained UbuntuSSO OAuth token to log in.

### Keystone
```yaml
- type: keystone
  name: canonistack
  domain: canonistack
  description: Canonistack
  url: https://keystone.canonistack.canonical.com:443/
  hidden: false
```

The Keystone identity provider is an interactive identity provider
that uses a keystone service to log the user in using their openstack
credentials.

The Keystone identity provider has a number of additional options.

The `name` parameter specifies the name of the provider, this should be
a short name that reflects the name of the system being logged in to.
The name is used in some URLS and is best if it consists only of
lower-case letters.

The `domain` is a string added to the names of users logging in through
this identity provider. The user jsmith for example would be changed
to jsmith@canonistack in the configuration above. If no domain is
specified the username will remain unchanged.

The `description` is optional and will be used if the identity provider
is presented in a human readable form, if this is not set the name
will be used.

The `url` is the location of the keystone server that will be used to
authenticate the user.

The `hidden` value is an optional value that can be used to not list
this identity provider in the list of possible identity providers when
performing an interactive login.

### Keystone Token
```yaml
- type: keystone_token
  name: jujugui
  domain: canonistack
  description: Canonistack
  url: https://keystone.canonistack.canonical.com:443/

```

The Keystone Token identity provider is a custom identity provider
that uses a keystone service to authenticate a user that already has a
keystone authentication token by logging in previously through some
external means. It is designed to be used in jujugui system embedded
in horizon services to prevent a user having to log in twice.

The Keystone Token identity provider has a number of additional options.

The `name` parameter specifies the name of the provider. The name is
used in some URLS and is best if it consists only of lower-case
letters. The name "jujugui" can be used to indicate to a jujugui
instance that this provider can be used to log in with an existing
token.

The `domain` is a string added to the names of users logging in through
this identity provider. The user jsmith for example would be changed
to jsmith@canonistack in the configuration above. If no domain is
specified the username will remain unchanged.

The `description` is optional and will be used if the identity provider
is presented in a human readable form, if this is not set the name
will be used.

The `url` is the location of the keystone server that will be used to
authenticate the user.

### Keystone Userpass
```yaml
- type: keystone_userpass
  name: form
  domain: canonistack
  description: Canonistack
  url: https://keystone.canonistack.canonical.com:443/
  
```

The Keystone Userpass identity provider is a custom identity provider
that uses a keystone service to authenticate users that have provided
their username and password through a form mechanism in the client. It
is designed to allow credentials to be provided through a CLI where
web page access is not practical.

The Keystone Userpass identity provider has a number of additional
options.

The `name` parameter specifies the name of the provider. The name is
used in some URLS and is best if it consists only of lower-case
letters. The name "form" can be used to indicate to clients that
support the form protocol that the protocol can be used.

The `domain` is a string added to the names of users logging in through
this identity provider. The user jsmith for example would be changed
to jsmith@canonistack in the configuration above. If no domain is
specified the username will remain unchanged.

The `description` is optional and will be used if the identity provider
is presented in a human readable form, if this is not set the name
will be used.

The `url` is the location of the keystone server that will be used to
authenticate the user.

### Azure OpenID Connect
```yaml
- type: azure
  client-id: 43444f68-3666-4f95-bd34-6fc24b108019
  client-secret: tXV2SRFflAGT9sUdxkdIi7mwfmQ=
  hidden: false
```

The Azure identity provider uses OpenID Connect to log in using Microsoft
credentials via https://login.live.com. When a user first logs in with
this IDP they will be prompted to create a new identity. The new identity
must have a unique username and will be in the domain "@azure".

The `client-id` and `client-secret` parameters must be specified and
are created by registering the candid instance as an application at
https://apps.dev.microsoft.com. When registering the application the
redirect URLs should include `$CANDID_URL/login/azure/callback`.

The `hidden` value is an optional value that can be used to not list
this identity provider in the list of possible identity providers when
performing an interactive login.

### Google OpenID Connect
```yaml
- type: google
  client-id: 483156874216-rh0j89ltslhuqirk7deh70d3mp49kdvq.apps.googleusercontent.com
  client-secret: 8aENrwCL/+PU87ROkXwMB+09xe0=
  hidden: false
```

The Google identity provider uses OpenID Connect to log in using Google
credentials. When a user first logs in with this IDP they will be prompted
to create a new identity. The new identity must have a unique username
and will be in the domain "@google".

The `client-id` and `client-secret` parameters must be specified and
are created by registering the candid instance as an application
at https://console.developers.google.com/apis/credentials. When
registering the application the authorized redirect URLs should include
`$CANDID_URL/login/google/callback`.

The `hidden` value is an optional value that can be used to not list
this identity provider in the list of possible identity providers when
performing an interactive login.

### LDAP
```yaml
- type: ldap
  name: ldap
  description: LDAP Login
  domain: example
  url: ldap://ldap.example.com/dc=example,dc=com
  ca-cert: |
    -----BEGIN CERTIFICATE-----
    MIIBWTCCAQOgAwIBAgIBADANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDExBsZGFw
    LmV4YW1wbGUuY29tMB4XDTE4MDQxODEwMDUzMVoXDTI4MDQyMDEwMDUzMVowGzEZ
    MBcGA1UEAxMQbGRhcC5leGFtcGxlLmNvbTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgC
    QQDN2tltcVwW0bs80ABocjSZrqBDnpuxnzq2DlrLL+hldwDxVZ0sqU+o768GB6bP
    8k3WVf81yYBRbfq7pD/MX0BhAgMBAAGjMjAwMA8GA1UdEwEB/wQFMAMBAf8wHQYD
    VR0OBBYEFEMAeAXsITzTXHDfJSzrezBkaSvwMA0GCSqGSIb3DQEBCwUAA0EAw6Rh
    RlR4L5mvvDaN4NP/aNOaWGe+x1Oa7V3L75MmD3DbwcUgDCn45EaUGofbOTrbYuzm
    mrVoMF002dpQoqc38w==
    -----END CERTIFICATE-----
  dn: cn=candid,dc=example,dc=com
  password: 6IaWWtW/aTN0CIVYwLgeOayyZW8o
  user-query-filter: (objectClass=account)
  user-query-attrs:
    id: uid
    email: mail
    display-name: displayName
  group-query-filter: (&(objectClass=groupOfNames)(member={{.User}}))
  hidden: false
```

The LDAP identity provider allows a user to login using an LDAP server.
Candid will prompt for a username and password and attempt to use those
to authenticate with the LDAP server.

`name` is the name to use for the LDAP IDP instance. It is possible
to configure more than one LDAP IDP on a given candid server and this
allows them to be identified. The name will be used in the login URL.

`description` (optional) provides a human readable description of the
identity provider. If it is not set it will default to the value of
`name`.

`domain` (optional) is the domain in which all identities will be
created. If this is not set then no domain is used.

`url` contains the URL of the LDAP server being authenticated against. The
path component of the URL is used as the base DN for the connection.

`ca-cert` (optional) contains the CA certificate that signed the LDAPs
server certificate. If this is not set then the connection either has
to be unauthenticated or the CA certificate has to be in the system's
certificate pool.

`dn` (optional) contains the distinguished name that candid uses to bind
to the LDAP server to perform searches. If this is not configured then
candid binds anonymously and `password` is ignored.

`password` (optional) contains the password used when candid binds to
the LDAP server.

`user-query-filter` contains the filter that candid uses when attempting
to find the user that is authenticating.

`user-query-attrs` contains the attributes candid uses when searching
for authenticating users.  When authenticating a user candid will
perform a search like `($id=$username)` where the value of `$id` is
specified in the `id` parameter and $username is the value entered by
the authenticating user. `email` and `display-name` are used to populate
the created identity.

`group-query-filter` contains the filter candid uses when finding
group memberships for a user.  The filter is specified as a template
(see https://golang.org/pkg/text/template) where the value of `.User`
will be replaced with the DN of the user for whom candid is attempting
to find group memberships.

The `hidden` value is an optional value that can be used to not list
this identity provider in the list of possible identity providers when
performing an interactive login.

### Static identity provider
```yaml
- type: static
  name: static
  domain: mydomain
  description: Static Identity Provider
  users:
    user1:
      name: User One
      email: user1@example.com
      password: password1
      groups: [group1, group2]
    user2:
      name: User Two
      email: user2@example.com
      password: password2
      groups: [group3, group4]
  hidden: false
```

The `static` identity provider is meant for testing and allows defining a set of
users that can authenticate, along with their passwords and a list of groups
they are part of.

Note that this provider is *not meant for production use* as it's insecure.

`name` is the name to use for the LDAP IDP instance. It is possible
to configure more than one LDAP IDP on a given candid server and this
allows them to be identified. The name will be used in the login URL.

`domain` (optional) is the domain in which all identities will be
created. If this is not set then no domain is used.

`description` (optional) provides a human readable description of the
identity provider. If it is not set it will default to the value of
`name`.

`users` contains a static mapping of username to user entries for all
of the users defined by the identity provider.

The `hidden` value is an optional value that can be used to not list
this identity provider in the list of possible identity providers when
performing an interactive login.

Charm Configuration
-------------------
If the candid charm is being used then most of the parameters
will be set with sensible defaults.

The charm parameters that must be configured for each deployment are:

 * password
 * private-key
 * public-key
 * location

Most deployments will probably also want to configure the
identity-providers unless the default ones are being used.
