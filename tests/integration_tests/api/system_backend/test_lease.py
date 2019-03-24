import logging
from asynctest import TestCase

from async_hvac import exceptions
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestLease(HvacIntegrationTestCase, TestCase):

    async def setUp(self):
        await super(TestLease, self).setUp()
        # Set up a test pki backend and issue a cert against some role so we.
        await self.configure_pki()

    async def tearDown(self):
        # Reset integration test state.
        await self.disable_pki()
        await super(TestLease, self).tearDown()
        await self.client.close()

    async def test_read_lease(self):
        pki_issue_response = await self.client.write(
            path='pki/issue/my-role',
            common_name='test.hvac.com',
        )

        # Read the lease of our test cert that was just issued.
        read_lease_response = await self.client.sys.read_lease(
            lease_id=pki_issue_response['lease_id'],
        )
        logging.debug('read_lease_response: %s' % read_lease_response)

        # Validate we received the expected lease ID back in our response.
        self.assertEqual(
            first=pki_issue_response['lease_id'],
            second=read_lease_response['data']['id'],
        )

    async def test_list_leases(self):
        await self.client.write(
            path='pki/issue/my-role',
            common_name='test.hvac.com',
        )

        # List the lease of our test cert that was just issued.
        list_leases_response = await self.client.sys.list_leases(
            prefix='pki',
        )
        logging.debug('list_leases_response: %s' % list_leases_response)
        self.assertIn(
            member='issue/',
            container=list_leases_response['data']['keys'],
        )

    async def test_revoke_lease(self):
        pki_issue_response = await self.client.write(
            path='pki/issue/my-role',
            common_name='test.hvac.com',
        )

        # Revoke the lease of our test cert that was just issued.
        revoke_lease_response = await self.client.sys.revoke_lease(
            lease_id=pki_issue_response['lease_id'],
        )
        logging.debug('revoke_lease_response: %s' % revoke_lease_response)

        self.assertEqual(
            first=revoke_lease_response.status,
            second=204,
        )
        with self.assertRaises(exceptions.InvalidPath):
            await self.client.sys.list_leases(
                prefix='pki',
            )

    async def test_revoke_prefix(self):
        pki_issue_response = await self.client.write(
            path='pki/issue/my-role',
            common_name='test.hvac.com',
        )

        # Revoke the lease prefix of our test cert that was just issued.
        revoke_prefix_response = await self.client.sys.revoke_prefix(
            prefix=pki_issue_response['lease_id'],
        )
        logging.debug('revoke_prefix_response: %s' % revoke_prefix_response)

        self.assertEqual(
            first=revoke_prefix_response.status,
            second=204,
        )

    async def test_revoke_force(self):
        pki_issue_response = await self.client.write(
            path='pki/issue/my-role',
            common_name='test.hvac.com',
        )

        # Force revoke the lease of our test cert that was just issued.
        revoke_force_response = await self.client.sys.revoke_force(pki_issue_response['lease_id'])
        logging.debug('revoke_force_response: %s' % revoke_force_response)

        self.assertEqual(
            first=revoke_force_response.status,
            second=204,
        )
