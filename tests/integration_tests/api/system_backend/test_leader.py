from asynctest import TestCase

from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestLeader(HvacIntegrationTestCase, TestCase):

    async def tearDown(self):
        await self.client.close()

    async def test_read_health_status(self):
        self.assertIn(
            member='ha_enabled',
            container=await self.client.sys.read_leader_status(),
        )
