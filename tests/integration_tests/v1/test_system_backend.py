import logging
from asynctest import TestCase

from parameterized import parameterized, param

from async_hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestSystemBackend(HvacIntegrationTestCase, TestCase):

    async def tearDown(self):
        await self.client.close()

    async def test_unseal_multi(self):
        cls = type(self)

        await self.client.seal()

        keys = cls.manager.keys

        result = await self.client.unseal_multi(keys[0:2])

        self.assertTrue(result['sealed'])
        self.assertEqual(result['progress'], 2)

        result = await self.client.unseal_reset()
        self.assertEqual(result['progress'], 0)
        result = await self.client.unseal_multi(keys[1:3])
        self.assertTrue(result['sealed'])
        self.assertEqual(result['progress'], 2)
        await self.client.unseal_multi(keys[0:1])
        result = await self.client.unseal_multi(keys[2:3])
        self.assertFalse(result['sealed'])

    async def test_seal_unseal(self):
        cls = type(self)

        self.assertFalse(await self.client.is_sealed())

        await self.client.seal()

        self.assertTrue(await self.client.is_sealed())

        cls.manager.unseal()

        self.assertFalse(await self.client.is_sealed())

    async def test_ha_status(self):
        self.assertIn('ha_enabled', await self.client.ha_status)

    async def test_wrap_write(self):
        if 'approle/' not in (await self.client.list_auth_backends()):
            await self.client.enable_auth_backend("approle")

        await self.client.write("auth/approle/role/testrole")
        result = await self.client.write('auth/approle/role/testrole/secret-id', wrap_ttl="10s")
        self.assertIn('token', result['wrap_info'])
        await self.client.unwrap(result['wrap_info']['token'])
        await self.client.disable_auth_backend("approle")

    async def test_auth_backend_manipulation(self):
        self.assertNotIn('github/', (await self.client.list_auth_backends())['data'])

        await self.client.enable_auth_backend('github')
        self.assertIn('github/', (await self.client.list_auth_backends())['data'])

        self.client.token = self.manager.root_token
        await self.client.disable_auth_backend('github')
        self.assertNotIn('github/', (await self.client.list_auth_backends())['data'])

    async def test_secret_backend_manipulation(self):
        self.assertNotIn('test/', (await self.client.list_secret_backends())['data'])

        await self.client.enable_secret_backend('generic', mount_point='test')
        self.assertIn('test/', (await self.client.list_secret_backends())['data'])

        secret_backend_tuning = await self.client.get_secret_backend_tuning('generic', mount_point='test')
        self.assertEqual(secret_backend_tuning['data']['max_lease_ttl'], 2764800)
        self.assertEqual(secret_backend_tuning['data']['default_lease_ttl'], 2764800)

        await self.client.tune_secret_backend('generic', mount_point='test', default_lease_ttl='3600s', max_lease_ttl='8600s')
        secret_backend_tuning = await self.client.get_secret_backend_tuning('generic', mount_point='test')

        self.assertIn('max_lease_ttl', secret_backend_tuning['data'])
        self.assertEqual(secret_backend_tuning['data']['max_lease_ttl'], 8600)
        self.assertIn('default_lease_ttl', secret_backend_tuning['data'])
        self.assertEqual(secret_backend_tuning['data']['default_lease_ttl'], 3600)

        await self.client.remount_secret_backend('test', 'foobar')
        self.assertNotIn('test/', (await self.client.list_secret_backends())['data'])
        self.assertIn('foobar/', (await self.client.list_secret_backends())['data'])

        self.client.token = self.manager.root_token
        await self.client.disable_secret_backend('foobar')
        self.assertNotIn('foobar/', (await self.client.list_secret_backends())['data'])

    async def test_audit_backend_manipulation(self):
        self.assertNotIn('tmpfile/', (await self.client.list_audit_backends()))

        options = {
            'path': '/tmp/vault.audit.log'
        }

        await self.client.enable_audit_backend('file', options=options, name='tmpfile')
        self.assertIn('tmpfile/', (await self.client.list_audit_backends())['data'])

        self.client.token = self.manager.root_token
        await self.client.disable_audit_backend('tmpfile')
        self.assertNotIn('tmpfile/', (await self.client.list_audit_backends())['data'])

    async def test_policy_manipulation(self):
        self.assertIn('root', (await self.client.list_policies()))
        self.assertIsNone(await self.client.get_policy('test'))
        policy, parsed_policy = await self.prep_policy('test')
        self.assertIn('test', (await self.client.list_policies()))
        self.assertEqual(policy, (await self.client.get_policy('test')))
        self.assertEqual(parsed_policy, (await self.client.get_policy('test', parse=True)))

        await self.client.delete_policy('test')
        self.assertNotIn('test', (await self.client.list_policies()))

    async def test_json_policy_manipulation(self):
        self.assertIn('root', (await self.client.list_policies()))

        policy = '''
            path "sys" {
                policy = "deny"
            }
            path "secret" {
                policy = "write"
            }
        '''
        await self.client.set_policy('test', policy)
        self.assertIn('test', (await self.client.list_policies()))

        await self.client.delete_policy('test')
        self.assertNotIn('test', (await self.client.list_policies()))

    async def test_cubbyhole_auth(self):
        orig_token = self.client.token

        resp = await self.client.create_token(lease='6h', wrap_ttl='1h')
        self.assertEqual(resp['wrap_info']['ttl'], 3600)

        wrapped_token = resp['wrap_info']['token']
        await self.client.auth_cubbyhole(wrapped_token)
        self.assertNotEqual(self.client.token, orig_token)
        self.assertNotEqual(self.client.token, wrapped_token)
        self.assertTrue(await self.client.is_authenticated())

        self.client.token = orig_token
        self.assertTrue(await self.client.is_authenticated())

    async def test_rekey_multi(self):
        cls = type(self)

        self.assertFalse((await self.client.rekey_status)['started'])

        await self.client.start_rekey()
        self.assertTrue((await self.client.rekey_status)['started'])

        await self.client.cancel_rekey()
        self.assertFalse((await self.client.rekey_status)['started'])

        result = await self.client.start_rekey()

        keys = cls.manager.keys

        result = await self.client.rekey_multi(keys, nonce=result['nonce'])
        self.assertTrue(result['complete'])

        cls.manager.keys = result['keys']
        cls.manager.unseal()

    async def test_rotate(self):
        status = await self.client.key_status

        await self.client.rotate()

        self.assertGreater((await self.client.key_status)['term'], status['term'])

    async def test_wrapped_token_success(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        # Unwrap token
        result = await self.client.unwrap(wrap['wrap_info']['token'])
        self.assertTrue(result['auth']['client_token'])

        # Validate token
        lookup = await self.client.lookup_token(result['auth']['client_token'])
        self.assertEqual(result['auth']['client_token'], lookup['data']['id'])

    async def test_wrapped_token_intercept(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        # Intercept wrapped token
        await self.client.unwrap(wrap['wrap_info']['token'])

        # Attempt to retrieve the token after it's been intercepted
        with self.assertRaises(exceptions.InvalidRequest):
            await self.client.unwrap(wrap['wrap_info']['token'])

    async def test_wrapped_token_cleanup(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        _token = self.client.token
        await self.client.unwrap(wrap['wrap_info']['token'])
        self.assertEqual(self.client.token, _token)

    async def test_wrapped_token_revoke(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        # Revoke token before it's unwrapped
        await self.client.revoke_token(wrap['wrap_info']['wrapped_accessor'], accessor=True)

        # Unwrap token anyway
        result = await self.client.unwrap(wrap['wrap_info']['token'])
        self.assertTrue(result['auth']['client_token'])

        # Attempt to validate token
        with self.assertRaises(exceptions.Forbidden):
            await self.client.lookup_token(result['auth']['client_token'])

    async def test_wrapped_client_token_success(self):
        wrap = await self.client.create_token(wrap_ttl='1m')
        self.client.token = wrap['wrap_info']['token']

        # Unwrap token
        result = await self.client.unwrap()
        self.assertTrue(result['auth']['client_token'])

        # Validate token
        self.client.token = result['auth']['client_token']
        lookup = await self.client.lookup_token(result['auth']['client_token'])
        self.assertEqual(result['auth']['client_token'], lookup['data']['id'])

    async def test_wrapped_client_token_intercept(self):
        wrap = await self.client.create_token(wrap_ttl='1m')
        self.client.token = wrap['wrap_info']['token']

        # Intercept wrapped token
        await self.client.unwrap()

        # Attempt to retrieve the token after it's been intercepted
        with self.assertRaises(exceptions.InvalidRequest):
            await self.client.unwrap()

    async def test_wrapped_client_token_cleanup(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        _token = self.client.token
        self.client.token = wrap['wrap_info']['token']
        await self.client.unwrap()

        self.assertNotEqual(self.client.token, wrap)
        self.assertNotEqual(self.client.token, _token)

    async def test_wrapped_client_token_revoke(self):
        wrap = await self.client.create_token(wrap_ttl='1m')

        # Revoke token before it's unwrapped
        await self.client.revoke_token(wrap['wrap_info']['wrapped_accessor'], accessor=True)

        # Unwrap token anyway
        self.client.token = wrap['wrap_info']['token']
        result = await self.client.unwrap()
        self.assertTrue(result['auth']['client_token'])

        # Attempt to validate token
        with self.assertRaises(exceptions.Forbidden):
            await self.client.lookup_token(result['auth']['client_token'])

    async def test_start_generate_root_with_completion(self):
        test_otp = utils.get_generate_root_otp()

        self.assertFalse((await self.client.generate_root_status)['started'])
        start_generate_root_response = await self.client.start_generate_root(
            key=test_otp,
            otp=True,
        )
        logging.debug('generate_root_response: %s' % start_generate_root_response)
        self.assertTrue((await self.client.generate_root_status)['started'])

        nonce = start_generate_root_response['nonce']

        last_generate_root_response = {}
        for key in self.manager.keys[0:3]:
            last_generate_root_response = await self.client.generate_root(
                key=key,
                nonce=nonce,
            )
        logging.debug('last_generate_root_response: %s' % last_generate_root_response)
        self.assertFalse((await self.client.generate_root_status)['started'])

        new_root_token = utils.decode_generated_root_token(
            encoded_token=last_generate_root_response['encoded_root_token'],
            otp=test_otp,
        )
        logging.debug('new_root_token: %s' % new_root_token)
        token_lookup_resp = await self.client.lookup_token(token=new_root_token)
        logging.debug('token_lookup_resp: %s' % token_lookup_resp)

        # Assert our new root token is properly formed and authenticated
        self.client.token = new_root_token
        if await self.client.is_authenticated():
            self.manager.root_token = new_root_token
        else:
            # If our new token was unable to authenticate, set the test client's token back to the original value
            self.client.token = self.manager.root_token
            self.fail('Unable to authenticate with the newly generated root token.')

    async def test_start_generate_root_then_cancel(self):
        test_otp = utils.get_generate_root_otp()

        self.assertFalse((await self.client.generate_root_status)['started'])
        await self.client.start_generate_root(
            key=test_otp,
            otp=True,
        )
        self.assertTrue((await self.client.generate_root_status)['started'])

        await self.client.cancel_generate_root()
        self.assertFalse((await self.client.generate_root_status)['started'])

    async def test_tune_auth_backend(self):
        test_backend_type = 'approle'
        test_mount_point = 'tune-approle'
        test_description = 'this is a test auth backend'
        test_max_lease_ttl = 12345678
        if '{0}/'.format(test_mount_point) in (await self.client.list_auth_backends()):
            await self.client.disable_auth_backend(test_mount_point)
        await self.client.enable_auth_backend(
            backend_type='approle',
            mount_point=test_mount_point
        )

        expected_status_code = 204
        response = await self.client.tune_auth_backend(
            backend_type=test_backend_type,
            mount_point=test_mount_point,
            description=test_description,
            max_lease_ttl=test_max_lease_ttl,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status,
        )

        response = await self.client.get_auth_backend_tuning(
            backend_type=test_backend_type,
            mount_point=test_mount_point
        )

        self.assertEqual(
            first=test_max_lease_ttl,
            second=response['data']['max_lease_ttl']
        )

        await self.client.disable_auth_backend(mount_point=test_mount_point)

    async def test_read_lease(self):
        # Set up a test pki backend and issue a cert against some role so we.
        await self.configure_pki()
        pki_issue_response = await self.client.write(
            path='pki/issue/my-role',
            common_name='test.hvac.com',
        )

        # Read the lease of our test cert that was just issued.
        read_lease_response = await self.client.read_lease(pki_issue_response['lease_id'])

        # Validate we received the expected lease ID back in our response.
        self.assertEquals(
            first=pki_issue_response['lease_id'],
            second=read_lease_response['data']['id'],
        )

        # Reset integration test state.
        await self.disable_pki()

    @parameterized.expand([
        param(
            'hash returned',
        ),
        param(
            'audit backend not enabled',
            enable_first=False,
            raises=exceptions.InvalidRequest,
            exception_message='unknown audit backend',
        ),
    ])
    async def test_audit_hash(self, label, enable_first=True, test_input='hvac-rox', raises=None, exception_message=''):
        audit_backend_path = 'tmpfile'
        await self.client.disable_audit_backend('tmpfile')
        if enable_first:
            options = {
                'path': '/tmp/vault.audit.log'
            }
            await self.client.enable_audit_backend('file', options=options, name=audit_backend_path)

        if raises:
            with self.assertRaises(raises) as cm:
                await self.client.audit_hash(
                    name=audit_backend_path,
                    input=test_input
                )
            if exception_message is not None:
                self.assertIn(
                    member=exception_message,
                    container=str(cm.exception),
                )
        else:
            audit_hash_response = await self.client.audit_hash(
                name=audit_backend_path,
                input=test_input,
            )
            logging.debug('audit_hash_response: %s' % audit_hash_response)
            self.assertIn(
                member='hmac-sha256:',
                container=audit_hash_response['data']['hash'],
            )
        await self.client.disable_audit_backend('tmpfile')

    async def test_get_secret_backend_tuning(self):
        secret_backend_tuning = await self.client.get_secret_backend_tuning('secret')
        self.assertIn(
            member='default_lease_ttl',
            container=secret_backend_tuning['data'],
        )

    async def test_get_backed_up_keys(self):
        with self.assertRaises(exceptions.InvalidRequest) as cm:
            await self.client.get_backed_up_keys()
            self.assertEqual(
                first='no backed-up keys found',
                second=str(cm.exception),
            )
