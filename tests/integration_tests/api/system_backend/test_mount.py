from asynctest import TestCase

from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestMount(HvacIntegrationTestCase, TestCase):

    async def tearDown(self):
        await self.client.close()

    async def test_secret_backend_manipulation(self):
        self.assertNotIn(
            member='test/',
            container=(await self.client.sys.list_mounted_secrets_engines())['data'],
        )

        await self.client.sys.enable_secrets_engine(
            backend_type='generic',
            path='test',
        )
        self.assertIn(
            member='test/',
            container=(await self.client.sys.list_mounted_secrets_engines())['data'],
        )

        secret_backend_tuning = await self.client.sys.read_mount_configuration(path='test')
        self.assertEqual(secret_backend_tuning['data']['max_lease_ttl'], 2764800)
        self.assertEqual(secret_backend_tuning['data']['default_lease_ttl'], 2764800)

        await self.client.sys.tune_mount_configuration(
            path='test',
            default_lease_ttl='3600s',
            max_lease_ttl='8600s',
        )
        secret_backend_tuning = await self.client.sys.read_mount_configuration(path='test')

        self.assertIn('max_lease_ttl', secret_backend_tuning['data'])
        self.assertEqual(secret_backend_tuning['data']['max_lease_ttl'], 8600)
        self.assertIn('default_lease_ttl', secret_backend_tuning['data'])
        self.assertEqual(secret_backend_tuning['data']['default_lease_ttl'], 3600)

        await self.client.sys.move_backend(
            from_path='test',
            to_path='foobar',
        )
        self.assertNotIn(
            member='test/',
            container=(await self.client.sys.list_mounted_secrets_engines())['data'],
        )
        self.assertIn(
            member='foobar/',
            container=(await self.client.sys.list_mounted_secrets_engines())['data'],
        )

        self.client.token = self.manager.root_token
        await self.client.sys.disable_secrets_engine(
            path='foobar'
        )
        self.assertNotIn(
            member='foobar/',
            container=(await self.client.sys.list_mounted_secrets_engines())['data'],
        )

    async def test_get_secret_backend_tuning(self):
        secret_backend_tuning = await self.client.sys.read_mount_configuration(path='secret')
        self.assertIn(
            member='default_lease_ttl',
            container=secret_backend_tuning['data'],
        )
