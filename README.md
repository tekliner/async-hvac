# ASYNC-HVAC forked by Improvado

[HashiCorp](https://hashicorp.com/) [Vault](https://www.vaultproject.io) API asyncio client for Python 3

This version is forked by Improvado


## Getting started

### Installation

```bash
pip install improvado-async-hvac
```
or
```bash
pip install improvado-async-hvac[parser]
```
if you would like to be able to return parsed HCL data as a Python dict for methods that support it.

### Initialize the client

```python
import os

import async_hvac

# Using plaintext
client = async_hvac.AsyncClient()
client = async_hvac.AsyncClient(url='http://localhost:8200')
client = async_hvac.AsyncClient(url='http://localhost:8200', token=os.environ['VAULT_TOKEN'])

# Using TLS
client = async_hvac.AsyncClient(url='https://localhost:8200')

# Using TLS with client-side certificate authentication
client = async_hvac.AsyncClient(url='https://localhost:8200',
                                cert=('path/to/cert.pem', 'path/to/key.pem'))
 # Skipping TLS verification entirely (should only be used for local development; unsafe for production clusters)
client = async_hvac.AsyncClient(url='https://localhost:8200', verify=False)
```

Note that you will have to close the client with `client.close()` in order to
avoid lingering open aiohttp.client.ClientSession's. An alternative is to open
the client in a `with`-statement:

```python
async with async_hvac.AsyncClient(url='https://localhost:8200') as client:
    print(await client.read('secret/foo'))
```

### Read and write to secret backends

```python
await client.write('secret/foo', baz='bar', lease='1h')

print(await client.read('secret/foo'))

await client.delete('secret/foo')
```

### Authenticate to different auth backends

```python
# Token
client.token = 'MY_TOKEN'
assert await client.is_authenticated() # => True

# App ID
await client.auth_app_id('MY_APP_ID', 'MY_USER_ID')

# App Role
await client.auth_approle('MY_ROLE_ID', 'MY_SECRET_ID')

# AWS (IAM)
client.auth_aws_iam('MY_AWS_ACCESS_KEY_ID', 'MY_AWS_SECRET_ACCESS_KEY')
client.auth_aws_iam('MY_AWS_ACCESS_KEY_ID', 'MY_AWS_SECRET_ACCESS_KEY', 'MY_AWS_SESSION_TOKEN')
client.auth_aws_iam('MY_AWS_ACCESS_KEY_ID', 'MY_AWS_SECRET_ACCESS_KEY', role='MY_ROLE')

import boto3
session = boto3.Session()
credentials = session.get_credentials()
client.auth_aws_iam(credentials.access_key, credentials.secret_key, credentials.token)

# GitHub
await client.auth_github('MY_GITHUB_TOKEN')

# GCP (from GCE instance)
import aiohttp

VAULT_ADDR="https://vault.example.com:8200"
ROLE="example"
AUDIENCE_URL =  VAULT_ADDR + "/vault/" + ROLE
METADATA_HEADERS = {'Metadata-Flavor': 'Google'}
FORMAT = 'full'

url = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={}&format={}'.format(AUDIENCE_URL, FORMAT)
async with aiohttp.ClientSession() as session:
    async with session.get(url, headers=METADATA_HEADERS) as resp:
        await client.auth_gcp(ROLE, await resp.text())

# Kubernetes (from k8s pod)
f = open('/var/run/secrets/kubernetes.io/serviceaccount/token')
jwt = f.read()
await client.auth_kubernetes("example", jwt)

# LDAP, Username & Password
await client.auth_ldap('MY_USERNAME', 'MY_PASSWORD')
await client.auth_userpass('MY_USERNAME', 'MY_PASSWORD')

# TLS
client = Client(cert=('path/to/cert.pem', 'path/to/key.pem'))
await client.auth_tls()

# Non-default mount point (available on all auth types)
await client.auth_userpass('MY_USERNAME', 'MY_PASSWORD', mount_point='CUSTOM_MOUNT_POINT')

# Authenticating without changing to new token (available on all auth types)
result = await client.auth_github('MY_GITHUB_TOKEN', use_token=False)
print(result['auth']['client_token']) # => u'NEW_TOKEN'

# Custom or unsupported auth type
params = {
    'username': 'MY_USERNAME',
    'password': 'MY_PASSWORD',
    'custom_param': 'MY_CUSTOM_PARAM',
}

result = await client.auth('/v1/auth/CUSTOM_AUTH/login', json=params)

# Logout
await client.logout()
```

### Manage tokens

```python
token = await client.create_token(policies=['root'], lease='1h')

current_token = await client.lookup_token()
some_other_token = await client.lookup_token('xxx')

await client.revoke_token('xxx')
await client.revoke_token('yyy', orphan=True)

await client.revoke_token_prefix('zzz')

await client.renew_token('aaa')
```

### Managing tokens using accessors

```python
token = await client.create_token(policies=['root'], lease='1h')
token_accessor = token['auth']['accessor']

same_token = await client.lookup_token(token_accessor, accessor=True)
await client.revoke_token(token_accessor, accessor=True)
```

### Wrapping/unwrapping a token

```python
wrap = await client.create_token(policies=['root'], lease='1h', wrap_ttl='1m')
result = await self.client.unwrap(wrap['wrap_info']['token'])
```

### Manipulate auth backends

```python
backends = await client.list_auth_backends()

await client.enable_auth_backend('userpass', mount_point='customuserpass')
await client.disable_auth_backend('github')
```

### Manipulate secret backends

```python
backends = await client.list_secret_backends()

await client.enable_secret_backend('aws', mount_point='aws-us-east-1')
await client.disable_secret_backend('mysql')

await client.tune_secret_backend('generic', mount_point='test', default_lease_ttl='3600s', max_lease_ttl='8600s')
await client.get_secret_backend_tuning('generic', mount_point='test')

await client.remount_secret_backend('aws-us-east-1', 'aws-east')
```

### Manipulate policies

```python
policies = await client.list_policies() # => ['root']

policy = """
path "sys" {
  policy = "deny"
}

path "secret" {
  policy = "write"
}

path "secret/foo" {
  policy = "read"
}
"""

await client.set_policy('myapp', policy)

await client.delete_policy('oldthing')

policy = await client.get_policy('mypolicy')

# Requires pyhcl to automatically parse HCL into a Python dictionary
policy = await client.get_policy('mypolicy', parse=True)
```

### Manipulate audit backends

```python
backends = await client.list_audit_backends()

options = {
    'path': '/tmp/vault.log',
    'log_raw': True,
}

await client.enable_audit_backend('file', options=options, name='somefile')
await client.disable_audit_backend('oldfile')
```

### Initialize and seal/unseal

```python
print(await client.is_initialized()) # => False

shares = 5
threshold = 3

result = await client.initialize(shares, threshold)

root_token = result['root_token']
keys = result['keys']

print(await client.is_initialized()) # => True

print(await client.is_sealed()) # => True

# unseal with individual keys
await client.unseal(keys[0])
await client.unseal(keys[1])
await client.unseal(keys[2])

# unseal with multiple keys until threshold met
await client.unseal_multi(keys)

print(await client.is_sealed()) # => False

await client.seal()

print(await client.is_sealed()) # => True
```

## Testing

Integration tests will automatically start a Vault server in the background. Just make sure
the latest `vault` binary is available in your `PATH`.

1. [Install Vault](https://vaultproject.io/docs/install/index.html) or execute `VAULT_BRANCH=release scripts/install-vault-release.sh`
2. [Install Tox](http://tox.readthedocs.org/en/latest/install.html)
3. Run tests: `make test`

## Contributing

Feel free to open pull requests with additional features or improvements!


## Publishing

This fork uses a private Improvado PYPI server, so you need credentials to publish new versions.

First of all, you should have developers-admin AWS role.

To publish a new version, bump the version in the `version` file and use the following command:

```sh
aws-vault exec global-management -- docker-compose run --rm publish
```
