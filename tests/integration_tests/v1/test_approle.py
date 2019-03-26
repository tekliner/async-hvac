import logging
from asynctest import TestCase

from parameterized import parameterized, param

from async_hvac import exceptions
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestApprole(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = 'approle'

    async def setUp(self):
        await super(TestApprole, self).setUp()
        await self.client.enable_auth_backend(
            backend_type='approle',
            mount_point=self.TEST_MOUNT_POINT,
        )

    async def tearDown(self):
        self.client.token = self.manager.root_token
        await self.client.disable_auth_backend(mount_point=self.TEST_MOUNT_POINT)
        await super(TestApprole, self).tearDown()
        await self.client.close()

    @parameterized.expand([
        param(
            'no secret ids',
            num_secrets_to_create=0,
            raises=exceptions.InvalidPath,
        ),
        param(
            'one secret id',
            num_secrets_to_create=1,
        ),
        param(
            'two secret ids',
            num_secrets_to_create=2,
        ),
    ])
    async def test_list_role_secrets(self, label, num_secrets_to_create=0, raises=None):
        test_role_name = 'testrole'
        await self.client.create_role(
            role_name=test_role_name,
            mount_point=self.TEST_MOUNT_POINT,
        )
        for _ in range(0, num_secrets_to_create):
            await self.client.create_role_secret_id(
                role_name=test_role_name,
                mount_point=self.TEST_MOUNT_POINT,
            )

        if raises:
            with self.assertRaises(raises):
                await self.client.list_role_secrets(
                    role_name=test_role_name,
                    mount_point=self.TEST_MOUNT_POINT,
                )
        else:
            list_role_secrets_response = await self.client.list_role_secrets(
                role_name=test_role_name,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug('list_role_secrets_response: %s' % list_role_secrets_response)
            self.assertEqual(
                first=num_secrets_to_create,
                second=len(list_role_secrets_response['data']['keys'])
            )

    async def test_create_role(self):
        await self.client.create_role('testrole')

        result = await self.client.read('auth/approle/role/testrole')
        lib_result = await self.client.get_role('testrole')
        del result['request_id']
        del lib_result['request_id']

        self.assertEqual(result, lib_result)

    async def test_delete_role(self):
        test_role_name = 'test-role'

        await self.client.create_role(test_role_name)
        # We add a second dummy test role so we can still hit the /role?list=true route after deleting the first role
        await self.client.create_role('test-role-2')

        # Ensure our created role shows up when calling list_roles as expected
        result = await self.client.list_roles()
        actual_list_role_keys = result['data']['keys']
        self.assertIn(
            member=test_role_name,
            container=actual_list_role_keys,
        )

        # Now delete the role and verify its absence when calling list_roles
        await self.client.delete_role(test_role_name)
        result = await self.client.list_roles()
        actual_list_role_keys = result['data']['keys']
        self.assertNotIn(
            member=test_role_name,
            container=actual_list_role_keys,
        )

    async def test_create_delete_role_secret_id(self):
        await self.client.create_role('testrole')
        create_result = await self.client.create_role_secret_id('testrole', {'foo': 'bar'})
        secret_id = create_result['data']['secret_id']
        result = await self.client.get_role_secret_id('testrole', secret_id)
        self.assertEqual(result['data']['metadata']['foo'], 'bar')
        await self.client.delete_role_secret_id('testrole', secret_id)
        with self.assertRaises(ValueError):
            await self.client.get_role_secret_id('testrole', secret_id)

    async def test_auth_approle(self):
        await self.client.create_role('testrole')
        create_result = await self.client.create_role_secret_id('testrole', {'foo': 'bar'})
        secret_id = create_result['data']['secret_id']
        role_id = await self.client.get_role_id('testrole')
        result = await self.client.auth_approle(role_id, secret_id)
        self.assertEqual(result['auth']['metadata']['foo'], 'bar')
        self.assertEqual(self.client.token, result['auth']['client_token'])
        self.assertTrue(await self.client.is_authenticated())

    async def test_auth_approle_dont_use_token(self):
        await self.client.create_role('testrole')
        create_result = await self.client.create_role_secret_id('testrole', {'foo': 'bar'})
        secret_id = create_result['data']['secret_id']
        role_id = await self.client.get_role_id('testrole')
        result = await self.client.auth_approle(role_id, secret_id, use_token=False)
        self.assertEqual(result['auth']['metadata']['foo'], 'bar')
        self.assertNotEqual(self.client.token, result['auth']['client_token'])
