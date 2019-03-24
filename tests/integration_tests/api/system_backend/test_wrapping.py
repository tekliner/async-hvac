import logging
from asynctest import TestCase

from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestWrapping(HvacIntegrationTestCase, TestCase):
    TEST_AUTH_METHOD_TYPE = 'approle'
    TEST_AUTH_METHOD_PATH = 'test-approle'

    async def tearDown(self):
        await self.client.close()

    async def setUp(self):
        await super(TestWrapping, self).setUp()
        await self.client.sys.enable_auth_method(
            method_type=self.TEST_AUTH_METHOD_TYPE,
            path=self.TEST_AUTH_METHOD_PATH,
        )

    async def test_unwrap(self):
        await self.client.write(
            path="auth/{path}/role/testrole".format(path=self.TEST_AUTH_METHOD_PATH),
        )
        result = await self.client.write(
            path='auth/{path}/role/testrole/secret-id'.format(
                path=self.TEST_AUTH_METHOD_PATH
            ),
            wrap_ttl="10s",
        )
        self.assertIn('token', result['wrap_info'])

        unwrap_response = await self.client.sys.unwrap(result['wrap_info']['token'])
        logging.debug('unwrap_response: %s' % unwrap_response)
        self.assertIn(
            member='secret_id_accessor',
            container=unwrap_response['data']
        )
        self.assertIn(
            member='secret_id',
            container=unwrap_response['data']
        )
