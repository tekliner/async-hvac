import logging
from asynctest import TestCase

from async_hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class TestKey(HvacIntegrationTestCase, TestCase):

    async def tearDown(self):
        await self.client.close()

    async def test_start_generate_root_with_completion(self):
        test_otp = utils.get_generate_root_otp()

        self.assertFalse((await self.client.sys.read_root_generation_progress())['started'])
        start_generate_root_response = await self.client.sys.start_root_token_generation(
            otp=test_otp,
        )
        logging.debug('generate_root_response: %s' % start_generate_root_response)
        self.assertTrue((await self.client.sys.read_root_generation_progress())['started'])

        nonce = start_generate_root_response['nonce']

        last_generate_root_response = {}
        for key in self.manager.keys[0:3]:
            last_generate_root_response = await self.client.sys.generate_root(
                key=key,
                nonce=nonce,
            )
        logging.debug('last_generate_root_response: %s' % last_generate_root_response)
        self.assertFalse((await self.client.sys.read_root_generation_progress())['started'])

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

        self.assertFalse((await self.client.sys.read_root_generation_progress())['started'])
        await self.client.sys.start_root_token_generation(
            otp=test_otp,
        )
        self.assertTrue((await self.client.sys.read_root_generation_progress())['started'])

        await self.client.sys.cancel_root_generation()
        self.assertFalse((await self.client.sys.read_root_generation_progress())['started'])

    async def test_rotate(self):
        status = await self.client.key_status

        await self.client.sys.rotate_encryption_key()

        self.assertGreater(
            (await self.client.key_status)['term'],
            status['term'],
        )

    async def test_rekey_multi(self):
        cls = type(self)

        self.assertFalse((await self.client.rekey_status)['started'])

        await self.client.sys.start_rekey()
        self.assertTrue((await self.client.rekey_status)['started'])

        await self.client.sys.cancel_rekey()
        self.assertFalse((await self.client.rekey_status)['started'])

        result = await self.client.sys.start_rekey()

        keys = cls.manager.keys

        result = await self.client.sys.rekey_multi(keys, nonce=result['nonce'])
        self.assertTrue(result['complete'])

        cls.manager.keys = result['keys']
        cls.manager.unseal()

    async def test_get_backed_up_keys(self):
        with self.assertRaises(exceptions.InvalidRequest) as cm:
            await self.client.sys.read_backup_keys()
            self.assertEqual(
                first='no backed-up keys found',
                second=str(cm.exception),
            )
