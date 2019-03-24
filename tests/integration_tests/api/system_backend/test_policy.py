import json
import logging
from asynctest import TestCase, skipIf

from parameterized import parameterized, param

from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


@skipIf(utils.vault_version_lt('0.9.0'), "Policy class uses new parameters added >= Vault 0.9.0")
class TestPolicy(HvacIntegrationTestCase, TestCase):
    TEST_POLICY_NAME = 'test-policy-policy'

    async def tearDown(self):
        await self.client.sys.delete_policy(
            name=self.TEST_POLICY_NAME,
        )
        await super(TestPolicy, self).tearDown()
        await self.client.close()

    @parameterized.expand([
        param(
            'success',
        ),
        param(
            'pretty print false',
            pretty_print=False,
        ),
    ])
    @skipIf(utils.vault_version_eq('0.11.0'), "Policy parsing broken in Vault version 0.11.0")
    async def test_create_or_update_policy(self, label, pretty_print=True):
        test_policy = {
            'path': {
                'test-path': {
                    'capabilities': ['read'],
                },
            },
        }
        create_policy_response = await self.client.sys.create_or_update_policy(
            name=self.TEST_POLICY_NAME,
            policy=test_policy,
            pretty_print=pretty_print,
        )
        logging.debug('create_policy_response: %s' % create_policy_response)
        self.assertEqual(
            first=create_policy_response.status,
            second=204,
        )

        read_policy_response = await self.client.sys.read_policy(
            name=self.TEST_POLICY_NAME,
        )
        logging.debug('read_policy_response: %s' % read_policy_response)
        self.assertDictEqual(
            d1=json.loads(read_policy_response['data']['rules']),
            d2=test_policy,
        )

    async def test_policy_manipulation(self):
        self.assertIn(
            member='root',
            container=(await self.client.sys.list_policies())['data']['policies'],
        )
        self.assertIsNone(await self.client.get_policy('test'))
        policy, parsed_policy = await self.prep_policy('test')
        self.assertIn(
            member='test',
            container=(await self.client.sys.list_policies())['data']['policies'],
        )
        self.assertEqual(policy, (await self.client.sys.read_policy('test'))['data']['rules'])
        self.assertEqual(parsed_policy, await self.client.get_policy('test', parse=True))

        await self.client.sys.delete_policy(
            name='test',
        )
        self.assertNotIn(
            member='test',
            container=(await self.client.sys.list_policies())['data']['policies'],
        )

    async def test_json_policy_manipulation(self):
        self.assertIn(
            member='root',
            container=(await self.client.sys.list_policies())['data']['policies'],
        )

        policy = '''
            path "sys" {
                policy = "deny"
            }
            path "secret" {
                policy = "write"
            }
        '''
        await self.client.sys.create_or_update_policy(
            name='test',
            policy=policy,
        )
        self.assertIn(
            member='test',
            container=(await self.client.sys.list_policies())['data']['policies'],
        )

        await self.client.delete_policy('test')
        self.assertNotIn(
            member='test',
            container=(await self.client.sys.list_policies())['data']['policies'],
        )
