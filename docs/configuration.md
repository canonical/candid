Identity Manager Configuration
==============================

Introduction
------------
This document describes the configuration options for an identity
manager.

Configuration File
------------------
The identity manager loads its configuration at startup from a yaml
file. In a usual installation this file is stored in
/etc/candid/config.yaml. An example configuration file is:

```yaml
api-addr: :8081
location: 'http://jujucharms.com/identity'
mongo-addr: localhost:27017
max-mgo-sessions: 300
request-timeout: 2s
auth-username: admin
auth-password: password
public-key: OAG9EVDFgXzWQKIk+MTxpLVO1Mp1Ws/pIkzhxv5Jk1M=
private-key: q2G3A2NjTe7MP9D8iugCH9XfBAyrnV8n8u8ACbNyNOY=
access-log: access.log
identity-providers:
- type: usso
- type: usso_oauth
- type: agent
```

### api-addr
This is the address that the service will listen on. This consists of
an optional host followed by a port. If the host is omitted then the
server will listen on all interface addresses. The port may be a well
known service name for example ":http".

### location
This is the externally addressable location of the identity provider
within the system. The identity manager needs to know how to address
itself in order to address macaroons to itself where needed to access
API endpoints and to create response addresses for identity providers
such as OpenID that use browser redirection for communication.

### mongo-addr
This is the address of the the MongoDB server containing the identity
manager's database. Identity manager requires a MongoDB server to run.

### max-mgo-sessions
To prevent overloading the system identity manager restricts the
number of concurrent connections to the MongoDB server to this number.

## request-timeout
If the number of concurrent MongoDB connections has exceeded
max-mgo-sessions new requests will wait until the request-timeout time
has been exceeded for a connection to become available. If no
connection becomes available then the request will fail.

### auth-username & auth-password
Some operations require privileged access. This is accomplished by
providing basic authentication credentials with a request. These
settings specify the the credentials that can be used. Using these
credentials makes the client all-powerful and as such these should be
used with care. The use of this mechanism will eventually be phased
out.

### public-key & private-key
Services wishing to discharge caveats against this identity manager
encrypt their third party caveats using this public-key. The private
key is needed for the identity manager to be able to discharge those
caveats.

### access-log
The access-log configures the name of the file used to record all
accesses to the identity manager. If this is not configured then no
logging will take place.

### identity-providers
This is a list of the configured identity providers with their
configuration. See below for the supported identity providers. If this
is not configured then a default set of providers will be used
containing UbuntuSSO, UbuntuSSO OAuth and Agent identity providers.

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

### UbuntuSSO
```yaml
- type: usso
```

The UbuntuSSO identity provider is an interactive identity provider
that uses OpenID with UbuntuSSO to log in.

### UbuntuSSO OAuth
```yaml
- type: usso_oauth
```

The UbuntuSSO identity provider is an custom identity provider that
uses a previously obtained UbuntuSSO OAuth token to log in.

### Agent
```yaml
- type: agent
```

The agent identity provider is a custom identity provider that uses
the agent protocol to log in. See
https://github.com/CanonicalLtd/candid/blob/master/docs/login.txt
for details on the agent login protocol.

### Keystone
```yaml
- type: keystone
  name: canonistack
  domain: canonistack
  description: Canonistack
  url: https://keystone.canonistack.canonical.com:443/
  
```

The Keystone identity provider is an interactive identity provider
that uses a keystone service to log the user in using their openstack
credentials.

The Keystone identity provider has a number of additional options.

The name parameter specifies the name of the provider, this should be
a short name that reflects the name of the system being logged in to.
The name is used in some URLS and is best if it consists only of
lower-case letters.

The domain is a string added to the names of users logging in through
this identity provider. The user jsmith for example would be changed
to jsmith@canonistack in the configuration above. If no domain is
specified the username will remain unchanged.

The description is optional and will be used if the identity provider
is presented in a human readable form, if this is not set the name
will be used.

The url is the location of the keystone server that will be used to
authenticate the user.

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

The name parameter specifies the name of the provider. The name is
used in some URLS and is best if it consists only of lower-case
letters. The name "jujugui" can be used to indicate to a jujugui
instance that this provider can be used to log in with an existing
token.

The domain is a string added to the names of users logging in through
this identity provider. The user jsmith for example would be changed
to jsmith@canonistack in the configuration above. If no domain is
specified the username will remain unchanged.

The description is optional and will be used if the identity provider
is presented in a human readable form, if this is not set the name
will be used.

The url is the location of the keystone server that will be used to
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

The name parameter specifies the name of the provider. The name is
used in some URLS and is best if it consists only of lower-case
letters. The name "form" can be used to indicate to clients that
support the form protocol that the protocol can be used.

The domain is a string added to the names of users logging in through
this identity provider. The user jsmith for example would be changed
to jsmith@canonistack in the configuration above. If no domain is
specified the username will remain unchanged.

The description is optional and will be used if the identity provider
is presented in a human readable form, if this is not set the name
will be used.

The url is the location of the keystone server that will be used to
authenticate the user.

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
