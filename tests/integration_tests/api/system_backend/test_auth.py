from asynctest import TestCase

from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestAuth(HvacIntegrationTestCase, TestCase):
    TEST_AUTH_METHOD_TYPE = 'github'
    TEST_AUTH_METHOD_PATH = 'test-github'

    async def tearDown(self):
        await self.client.sys.disable_auth_method(
            path=self.TEST_AUTH_METHOD_PATH
        )
        await super(TestAuth, self).tearDown()
        await self.client.close()

    async def test_auth_backend_manipulation(self):
        self.assertNotIn(
            member='%s/' % self.TEST_AUTH_METHOD_PATH,
            container=(await self.client.sys.list_auth_methods())['data'],
        )

        await self.client.sys.enable_auth_method(
            method_type=self.TEST_AUTH_METHOD_TYPE,
            path=self.TEST_AUTH_METHOD_PATH,
        )
        self.assertIn(
            member='%s/' % self.TEST_AUTH_METHOD_PATH,
            container=(await self.client.sys.list_auth_methods())['data'],
        )

        await self.client.sys.disable_auth_method(
            path=self.TEST_AUTH_METHOD_PATH,
        )
        self.assertNotIn(
            member='%s/' % self.TEST_AUTH_METHOD_PATH,
            container=(await self.client.sys.list_auth_methods())['data'],
        )

    async def test_tune_auth_backend(self):
        test_description = 'this is a test auth backend'
        test_max_lease_ttl = 12345678
        await self.client.sys.enable_auth_method(
            method_type='approle',
            path=self.TEST_AUTH_METHOD_PATH
        )

        expected_status_code = 204
        response = await self.client.sys.tune_auth_method(
            path=self.TEST_AUTH_METHOD_PATH,
            description=test_description,
            max_lease_ttl=test_max_lease_ttl,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status,
        )

        response = await self.client.sys.read_auth_method_tuning(
            path=self.TEST_AUTH_METHOD_PATH
        )

        self.assertEqual(
            first=test_max_lease_ttl,
            second=response['data']['max_lease_ttl']
        )
