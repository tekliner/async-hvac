from __future__ import unicode_literals

import json
import ssl
from base64 import b64encode

import aiohttp
from async_hvac import aws_utils, exceptions, adapters

try:
    import hcl

    has_hcl_parser = True
except ImportError:
    has_hcl_parser = False


class AsyncClient(object):
    """The Async hvac Client class for HashiCorp's Vault."""

    def __init__(self, url='http://127.0.0.1:8200', token=None,
                 cert=None, verify=True, timeout=30, proxies=None,
                 allow_redirects=True, session=None, adapter=None, namespace=None,
                 loop=None):
        """Creates a new async hvac client instance.

        :param url: Base URL for the Vault instance being addressed.
        :type url: str
        :param token: Authentication token to include in requests sent to Vault.
        :type token: str
        :param cert: Certificates for use in requests sent to the Vault instance. This should be a tuple with the
            certificate and then key.
        :type cert: tuple
        :param verify: Either a boolean to indicate whether TLS verification should be performed when sending requests to Vault,
            or a string pointing at the CA bundle to use for verification. See http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification.
        :type verify: Union[bool,str]
        :param timeout: The timeout value for requests sent to Vault.
        :type timeout: int
        :param proxies: Proxies to use when performing requests.
            See: http://docs.python-requests.org/en/master/user/advanced/#proxies
        :type proxies: dict
        :param allow_redirects: Whether to follow redirects when sending requests to Vault.
        :type allow_redirects: bool
        :param session: Optional session object to use when performing request.
        :type session: request.Session
        :param adapter: Optional class to be used for performing requests. If none is provided, defaults to
            hvac.adapters.Request
        :type adapter: hvac.adapters.Adapter
        :param namespace: Optional Vault Namespace.
        :type namespace: str
        :param loop: Optional event loop.
        :type loop
        """

        if adapter is not None:
            self._adapter = adapter
        else:
            self._adapter = adapters.Request(
                base_uri=url,
                token=token,
                cert=cert,
                verify=verify,
                timeout=timeout,
                proxies=proxies,
                allow_redirects=allow_redirects,
                session=session,
                namespace=namespace,
                loop=loop
            )

    def __enter__(self):
        raise TypeError("Use async with instead")

    def __exit__(self, exc_type, exc_val, exc_tb):
        # __exit__ should exist in pair with __enter__ but never executed
        pass  # pragma: no cover

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    @property
    def adapter(self):
        return self._adapter

    @adapter.setter
    def adapter(self, adapter):
        self._adapter = adapter

    @property
    def url(self):
        return self._adapter.base_uri

    @url.setter
    def url(self, url):
        self._adapter.base_uri = url

    @property
    def token(self):
        return self._adapter.token

    @token.setter
    def token(self, token):
        self._adapter.token = token

    @property
    def session(self):
        return self._adapter.session

    @session.setter
    def session(self, session):
        self._adapter.session = session

    @property
    def allow_redirects(self):
        return self._adapter.allow_redirects

    @allow_redirects.setter
    def allow_redirects(self, allow_redirects):
        self._adapter.allow_redirects = allow_redirects

    async def read(self, path, wrap_ttl=None):
        """
        GET /<path>
        """
        try:
            return await (await self._adapter.get('/v1/{0}'.format(path), wrap_ttl=wrap_ttl)).json()
        except exceptions.InvalidPath:
            return None

    async def list(self, path):
        """
        GET /<path>?list=true
        """
        try:
            payload = {
                'list': 'true'
            }
            return await (await self._adapter.get('/v1/{}'.format(path), params=payload)).json()
        except exceptions.InvalidPath:
            return None

    async def write(self, path, wrap_ttl=None, **kwargs):
        """
        POST /<path>
        """
        response = await self._adapter.post('/v1/{0}'.format(path), json=kwargs, wrap_ttl=wrap_ttl)

        if response.status == 200:
            return await response.json()

    def delete(self, path):
        """
        DELETE /<path>
        """
        return self._adapter.delete('/v1/{0}'.format(path))

    async def unwrap(self, token=None):
        """
        POST /sys/wrapping/unwrap
        X-Vault-Token: <token>
        """
        if token:
            payload = {
                'token': token
            }
            return await (await self._adapter.post('/v1/sys/wrapping/unwrap', json=payload)).json()
        else:
            return await (await self._adapter.post('/v1/sys/wrapping/unwrap')).json()

    async def is_initialized(self):
        """
        GET /sys/init
        """
        return (await (await self._adapter.get('/v1/sys/init')).json())['initialized']

    async def initialize(self, secret_shares=5, secret_threshold=3, pgp_keys=None):
        """
        PUT /sys/init
        """
        params = {
            'secret_shares': secret_shares,
            'secret_threshold': secret_threshold,
        }

        if pgp_keys:
            if len(pgp_keys) != secret_shares:
                raise ValueError('Length of pgp_keys must equal secret shares')

            params['pgp_keys'] = pgp_keys

        return await (await self._adapter.put('/v1/sys/init', json=params)).json()

    @property
    async def seal_status(self):
        """
        GET /sys/seal-status
        """
        return await (await self._adapter.get('/v1/sys/seal-status')).json()

    async def is_sealed(self):
        return (await self.seal_status)['sealed']

    def seal(self):
        """
        PUT /sys/seal
        """
        return self._adapter.put('/v1/sys/seal')

    async def unseal_reset(self):
        """
        PUT /sys/unseal
        """
        params = {
            'reset': True,
        }
        return await (await self._adapter.put('/v1/sys/unseal', json=params)).json()

    async def unseal(self, key):
        """
        PUT /sys/unseal
        """
        params = {
            'key': key,
        }

        return await (await self._adapter.put('/v1/sys/unseal', json=params)).json()

    async def unseal_multi(self, keys):
        result = None

        for key in keys:
            result = await self.unseal(key)
            if not result['sealed']:
                break

        return result

    @property
    async def generate_root_status(self):
        """
        GET /sys/generate-root/attempt
        """
        return await (await self._adapter.get('/v1/sys/generate-root/attempt')).json()

    async def start_generate_root(self, key, otp=False):
        """
        PUT /sys/generate-root/attempt
        """
        params = {}
        if otp:
            params['otp'] = key
        else:
            params['pgp_key'] = key

        return await (await self._adapter.put('/v1/sys/generate-root/attempt', json=params)).json()

    async def generate_root(self, key, nonce):
        """
        PUT /sys/generate-root/update
        """
        params = {
            'key': key,
            'nonce': nonce,
        }

        return await (await self._adapter.put('/v1/sys/generate-root/update', json=params)).json()

    async def cancel_generate_root(self):
        """
        DELETE /sys/generate-root/attempt
        """

        return (await self._adapter.delete('/v1/sys/generate-root/attempt')).status == 204

    @property
    async def key_status(self):
        """
        GET /sys/key-status
        """
        return await (await self._adapter.get('/v1/sys/key-status')).json()

    def rotate(self):
        """
        PUT /sys/rotate
        """
        return self._adapter.put('/v1/sys/rotate')

    @property
    async def rekey_status(self):
        """
        GET /sys/rekey/init
        """
        return await (await self._adapter.get('/v1/sys/rekey/init')).json()

    async def start_rekey(self, secret_shares=5, secret_threshold=3, pgp_keys=None,
                          backup=False):
        """
        PUT /sys/rekey/init
        """
        params = {
            'secret_shares': secret_shares,
            'secret_threshold': secret_threshold,
        }

        if pgp_keys:
            if len(pgp_keys) != secret_shares:
                raise ValueError('Length of pgp_keys must equal secret shares')

            params['pgp_keys'] = pgp_keys
            params['backup'] = backup

        resp = await self._adapter.put('/v1/sys/rekey/init', json=params)
        if resp.text:
            return await resp.json()

    def cancel_rekey(self):
        """
        DELETE /sys/rekey/init
        """
        return self._adapter.delete('/v1/sys/rekey/init')

    async def rekey(self, key, nonce=None):
        """
        PUT /sys/rekey/update
        """
        params = {
            'key': key,
        }

        if nonce:
            params['nonce'] = nonce

        return await (await self._adapter.put('/v1/sys/rekey/update', json=params)).json()

    async def rekey_multi(self, keys, nonce=None):
        result = None

        for key in keys:
            result = await self.rekey(key, nonce=nonce)
            if result.get('complete'):
                break

        return result

    async def get_backed_up_keys(self):
        """
        GET /sys/rekey/backup
        """
        return await (await self._adapter.get('/v1/sys/rekey/backup')).json()

    @property
    async def ha_status(self):
        """
        GET /sys/leader
        """
        return await (await self._adapter.get('/v1/sys/leader')).json()

    async def renew_secret(self, lease_id, increment=None):
        """
        PUT /sys/leases/renew
        """
        params = {
            'lease_id': lease_id,
            'increment': increment,
        }
        return await (await self._adapter.post('/v1/sys/renew', json=params)).json()

    def revoke_secret(self, lease_id):
        """
        PUT /sys/revoke/<lease id>
        """
        return self._adapter.put('/v1/sys/revoke/{0}'.format(lease_id))

    def revoke_secret_prefix(self, path_prefix):
        """
        PUT /sys/revoke-prefix/<path prefix>
        """
        return self._adapter.put('/v1/sys/revoke-prefix/{0}'.format(path_prefix))

    def revoke_self_token(self):
        """
        PUT /auth/token/revoke-self
        """
        return self._adapter.put('/v1/auth/token/revoke-self')

    async def list_secret_backends(self):
        """
        GET /sys/mounts
        """
        return await (await self._adapter.get('/v1/sys/mounts')).json()

    def enable_secret_backend(self, backend_type, description=None, mount_point=None, config=None, options=None):
        """
        POST /sys/auth/<mount point>
        """
        if not mount_point:
            mount_point = backend_type

        params = {
            'type': backend_type,
            'description': description,
            'config': config,
            'options': options,
        }

        return self._adapter.post('/v1/sys/mounts/{0}'.format(mount_point), json=params)

    def tune_secret_backend(self, backend_type, mount_point=None, default_lease_ttl=None, max_lease_ttl=None):
        """
        POST /sys/mounts/<mount point>/tune
        """

        if not mount_point:
            mount_point = backend_type

        params = {
            'default_lease_ttl': default_lease_ttl,
            'max_lease_ttl': max_lease_ttl
        }

        return self._adapter.post('/v1/sys/mounts/{0}/tune'.format(mount_point), json=params)

    async def get_secret_backend_tuning(self, backend_type, mount_point=None):
        """
        GET /sys/mounts/<mount point>/tune
        """
        if not mount_point:
            mount_point = backend_type

        return await (await self._adapter.get('/v1/sys/mounts/{0}/tune'.format(mount_point))).json()

    def disable_secret_backend(self, mount_point):
        """
        DELETE /sys/mounts/<mount point>
        """
        return self._adapter.delete('/v1/sys/mounts/{0}'.format(mount_point))

    def remount_secret_backend(self, from_mount_point, to_mount_point):
        """
        POST /sys/remount
        """
        params = {
            'from': from_mount_point,
            'to': to_mount_point,
        }

        return self._adapter.post('/v1/sys/remount', json=params)

    async def list_policies(self):
        """
        GET /sys/policy
        """
        return (await (await self._adapter.get('/v1/sys/policy')).json())['policies']

    async def get_policy(self, name, parse=False):
        """
        GET /sys/policy/<name>
        """
        try:
            policy = (await (await self._adapter.get('/v1/sys/policy/{0}'.format(name))).json())['rules']
            if parse:
                if not has_hcl_parser:
                    raise ImportError('pyhcl is required for policy parsing')

                policy = hcl.loads(policy)

            return policy
        except exceptions.InvalidPath:
            return None

    def set_policy(self, name, rules):
        """
        PUT /sys/policy/<name>
        """

        if isinstance(rules, dict):
            rules = json.dumps(rules)

        params = {
            'rules': rules,
        }

        return self._adapter.put('/v1/sys/policy/{0}'.format(name), json=params)

    def delete_policy(self, name):
        """
        DELETE /sys/policy/<name>
        """
        return self._adapter.delete('/v1/sys/policy/{0}'.format(name))

    async def list_audit_backends(self):
        """
        GET /sys/audit
        """
        return await (await self._adapter.get('/v1/sys/audit')).json()

    def enable_audit_backend(self, backend_type, description=None, options=None, name=None):
        """
        POST /sys/audit/<name>
        """
        if not name:
            name = backend_type

        params = {
            'type': backend_type,
            'description': description,
            'options': options,
        }

        return self._adapter.post('/v1/sys/audit/{0}'.format(name), json=params)

    def disable_audit_backend(self, name):
        """
        DELETE /sys/audit/<name>
        """
        return self._adapter.delete('/v1/sys/audit/{0}'.format(name))

    async def audit_hash(self, name, input):
        """
        POST /sys/audit-hash
        """
        params = {
            'input': input,
        }
        return await (await self._adapter.post('/v1/sys/audit-hash/{0}'.format(name), json=params)).json()

    async def create_token(self, role=None, token_id=None, policies=None, meta=None,
                           no_parent=False, lease=None, display_name=None,
                           num_uses=None, no_default_policy=False,
                           ttl=None, orphan=False, wrap_ttl=None, renewable=None,
                           explicit_max_ttl=None, period=None):
        """
        POST /auth/token/create
        POST /auth/token/create/<role>
        POST /auth/token/create-orphan
        """
        params = {
            'id': token_id,
            'policies': policies,
            'meta': meta,
            'no_parent': no_parent,
            'display_name': display_name,
            'num_uses': num_uses,
            'no_default_policy': no_default_policy,
            'renewable': renewable
        }

        if lease:
            params['lease'] = lease
        else:
            params['ttl'] = ttl
            params['explicit_max_ttl'] = explicit_max_ttl

        if explicit_max_ttl:
            params['explicit_max_ttl'] = explicit_max_ttl

        if period:
            params['period'] = period

        if orphan:
            return await (await self._adapter.post('/v1/auth/token/create-orphan', json=params, wrap_ttl=wrap_ttl)).json()
        elif role:
            return await (await self._adapter.post('/v1/auth/token/create/{0}'.format(role), json=params, wrap_ttl=wrap_ttl)).json()
        else:
            return await (await self._adapter.post('/v1/auth/token/create', json=params, wrap_ttl=wrap_ttl)).json()

    async def lookup_token(self, token=None, accessor=False, wrap_ttl=None):
        """
        GET /auth/token/lookup/<token>
        GET /auth/token/lookup-accessor/<token-accessor>
        GET /auth/token/lookup-self
        """
        token_param = {
            'token': token,
        }
        accessor_param = {
            'accessor': token,
        }
        if token:
            if accessor:
                path = '/v1/auth/token/lookup-accessor'
                return await (await self._adapter.post(path, json=accessor_param, wrap_ttl=wrap_ttl)).json()
            else:
                path = '/v1/auth/token/lookup'
                return await (await self._adapter.post(path, json=token_param)).json()
        else:
            path = '/v1/auth/token/lookup-self'
            return await (await self._adapter.get(path, wrap_ttl=wrap_ttl)).json()

    def revoke_token(self, token, orphan=False, accessor=False):
        """
        POST /auth/token/revoke
        POST /auth/token/revoke-orphan
        POST /auth/token/revoke-accessor
        """
        if accessor and orphan:
            msg = "revoke_token does not support 'orphan' and 'accessor' flags together"
            raise exceptions.InvalidRequest(msg)
        elif accessor:
            params = {'accessor': token}
            return self._adapter.post('/v1/auth/token/revoke-accessor', json=params)
        elif orphan:
            params = {'token': token}
            return self._adapter.post('/v1/auth/token/revoke-orphan', json=params)
        else:
            params = {'token': token}
            return self._adapter.post('/v1/auth/token/revoke', json=params)

    async def revoke_token_prefix(self, prefix):
        """
        POST /auth/token/revoke-prefix/<prefix>
        """
        return self._adapter.post('/v1/auth/token/revoke-prefix/{0}'.format(prefix))

    async def renew_token(self, token=None, increment=None, wrap_ttl=None):
        """
        POST /auth/token/renew/<token>
        POST /auth/token/renew-self
        """
        params = {
            'increment': increment,
        }

        if token:
            path = '/v1/auth/token/renew/{0}'.format(token)
            return await (await self._adapter.post(path, json=params, wrap_ttl=wrap_ttl)).json()
        else:
            return await (await self._adapter.post('/v1/auth/token/renew-self', json=params, wrap_ttl=wrap_ttl)).json()

    def create_token_role(self, role,
                          allowed_policies=None, disallowed_policies=None,
                          orphan=None, period=None, renewable=None,
                          path_suffix=None, explicit_max_ttl=None):
        """
        POST /auth/token/roles/<role>
        """
        params = {
            'allowed_policies': allowed_policies,
            'disallowed_policies': disallowed_policies,
            'orphan': orphan,
            'period': period,
            'renewable': renewable,
            'path_suffix': path_suffix,
            'explicit_max_ttl': explicit_max_ttl
        }
        return self._adapter.post('/v1/auth/token/roles/{0}'.format(role), json=params)

    def token_role(self, role):
        """
        Returns the named token role.
        """
        return self.read('auth/token/roles/{0}'.format(role))

    def delete_token_role(self, role):
        """
        Deletes the named token role.
        """
        return self.delete('auth/token/roles/{0}'.format(role))

    def list_token_roles(self):
        """
        GET /auth/token/roles?list=true
        """
        return self.list('auth/token/roles')

    def logout(self, revoke_token=False):
        """
        Clears the token used for authentication, optionally revoking it before doing so
        """
        if revoke_token:
            return self.revoke_self_token()

        self.token = None

    async def is_authenticated(self):
        """
        Helper method which returns the authentication status of the client
        """
        if not self.token:
            return False

        try:
            await self.lookup_token()
            return True
        except exceptions.Forbidden:
            return False
        except exceptions.InvalidPath:
            return False
        except exceptions.InvalidRequest:
            return False

    def auth_app_id(self, app_id, user_id, mount_point='app-id', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        params = {
            'app_id': app_id,
            'user_id': user_id,
        }

        return self.auth('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)

    def auth_tls(self, mount_point='cert', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        return self.auth('/v1/auth/{0}/login'.format(mount_point), use_token=use_token)

    def auth_userpass(self, username, password, mount_point='userpass', use_token=True, **kwargs):
        """
        POST /auth/<mount point>/login/<username>
        """
        params = {
            'password': password,
        }

        params.update(kwargs)

        return self.auth('/v1/auth/{0}/login/{1}'.format(mount_point, username), json=params, use_token=use_token)

    async def auth_aws_iam(self, access_key, secret_key, session_token=None, header_value=None, mount_point='aws', role='', use_token=True):
        """
        POST /auth/<mount point>/login
        """
        method = 'POST'
        url = 'https://sts.amazonaws.com/'
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8', 'Host': 'sts.amazonaws.com'}
        body = 'Action=GetCallerIdentity&Version=2011-06-15'

        if header_value:
            headers['X-Vault-AWS-IAM-Server-ID'] = header_value

        auth = aws_utils.SigV4Auth(access_key, secret_key, session_token)
        auth.add_auth(method, headers, body)

        # https://github.com/hashicorp/vault/blob/master/builtin/credential/aws/cli.go
        headers = json.dumps({k: [headers[k]] for k in headers})
        params = {
            'iam_http_request_method': method,
            'iam_request_url': b64encode(url.encode('utf-8')).decode('utf-8'),
            'iam_request_headers': b64encode(headers.encode('utf-8')).decode('utf-8'),
            'iam_request_body': b64encode(body.encode('utf-8')).decode('utf-8'),
            'role': role,
        }

        return await self.login('/v1/auth/{0}/login'.format(mount_point), json=params, use_token=use_token)
