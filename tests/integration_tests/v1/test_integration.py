import logging
from asynctest import TestCase, skipIf

from async_hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase


class IntegrationTest(HvacIntegrationTestCase, TestCase):

    async def tearDown(self):
        await self.client.close()

    async def test_generic_secret_backend(self):
        await self.client.write('secret/foo', zap='zip')
        result = await self.client.read('secret/foo')

        assert result['data']['zap'] == 'zip'

        await self.client.delete('secret/foo')

    async def test_list_directory(self):
        await self.client.write('secret/test-list/bar/foo', value='bar')
        await self.client.write('secret/test-list/foo', value='bar')
        result = await self.client.list('secret/test-list')

        assert result['data']['keys'] == ['bar/', 'foo']

        await self.client.delete('secret/test-list/bar/foo')
        await self.client.delete('secret/test-list/foo')

    async def test_write_with_response(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        plaintext = 'test'

        await self.client.write('transit/keys/foo')

        result = await self.client.write('transit/encrypt/foo', plaintext=plaintext)
        ciphertext = result['data']['ciphertext']

        result = await self.client.write('transit/decrypt/foo', ciphertext=ciphertext)
        assert result['data']['plaintext'] == plaintext

    async def test_read_nonexistent_key(self):
        assert not (await self.client.read('secret/I/dont/exist'))

    async def test_auth_token_manipulation(self):
        result = await self.client.create_token(lease='1h', renewable=True)
        assert result['auth']['client_token']

        lookup = await self.client.lookup_token(result['auth']['client_token'])
        assert result['auth']['client_token'] == lookup['data']['id']

        renew = await self.client.renew_token(lookup['data']['id'])
        assert result['auth']['client_token'] == renew['auth']['client_token']

        await self.client.revoke_token(lookup['data']['id'])

        try:
            lookup = await self.client.lookup_token(result['auth']['client_token'])
            assert False
        except exceptions.Forbidden:
            assert True
        except exceptions.InvalidPath:
            assert True
        except exceptions.InvalidRequest:
            assert True

    async def test_userpass_auth(self):
        if 'userpass/' in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend('userpass')

        await self.client.enable_auth_backend('userpass')

        await self.client.write('auth/userpass/users/testuser', password='testpass', policies='not_root')

        result = await self.client.auth_userpass('testuser', 'testpass')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        self.client.token = self.manager.root_token
        await self.client.disable_auth_backend('userpass')

    async def test_create_userpass(self):
        if 'userpass/' not in (await self.client.list_auth_backends())['data']:
            await self.client.enable_auth_backend('userpass')

        await self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root')

        result = await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        # Test ttl:
        self.client.token = self.manager.root_token
        await self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root', ttl='10s')
        self.client.token = result['auth']['client_token']

        result = await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert result['auth']['lease_duration'] == 10

        self.client.token = self.manager.root_token
        await self.client.disable_auth_backend('userpass')

    async def test_list_userpass(self):
        if 'userpass/' not in (await self.client.list_auth_backends())['data']:
            await self.client.enable_auth_backend('userpass')

        # add some users and confirm that they show up in the list
        await self.client.create_userpass('testuserone', 'testuseronepass', policies='not_root')
        await self.client.create_userpass('testusertwo', 'testusertwopass', policies='not_root')

        user_list = await self.client.list_userpass()
        assert 'testuserone' in user_list['data']['keys']
        assert 'testusertwo' in user_list['data']['keys']

        # delete all the users and confirm that list_userpass() doesn't fail
        for user in user_list['data']['keys']:
            await self.client.delete_userpass(user)

        no_users_list = await self.client.list_userpass()
        assert no_users_list is None

    async def test_read_userpass(self):
        if 'userpass/' not in (await self.client.list_auth_backends())['data']:
            await self.client.enable_auth_backend('userpass')

        # create user to read
        await self.client.create_userpass('readme', 'mypassword', policies='not_root')

        # test that user can be read
        read_user = await self.client.read_userpass('readme')
        assert 'not_root' in read_user['data']['policies']

        # teardown
        await self.client.disable_auth_backend('userpass')

    async def test_update_userpass_policies(self):
        if 'userpass/' not in (await self.client.list_auth_backends())['data']:
            await self.client.enable_auth_backend('userpass')

        # create user and then update its policies
        await self.client.create_userpass('updatemypolicies', 'mypassword', policies='not_root')
        await self.client.update_userpass_policies('updatemypolicies', policies='somethingelse')

        # test that policies have changed
        updated_user = await self.client.read_userpass('updatemypolicies')
        assert 'somethingelse' in updated_user['data']['policies']

        # teardown
        await self.client.disable_auth_backend('userpass')

    async def test_update_userpass_password(self):
        if 'userpass/' not in (await self.client.list_auth_backends())['data']:
            await self.client.enable_auth_backend('userpass')

        # create user and then change its password
        await self.client.create_userpass('changeme', 'mypassword', policies='not_root')
        await self.client.update_userpass_password('changeme', 'mynewpassword')

        # test that new password authenticates user
        result = await self.client.auth_userpass('changeme', 'mynewpassword')
        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        # teardown
        self.client.token = self.manager.root_token
        await self.client.disable_auth_backend('userpass')

    async def test_delete_userpass(self):
        if 'userpass/' not in (await self.client.list_auth_backends())['data']:
            await self.client.enable_auth_backend('userpass')

        await self.client.create_userpass('testcreateuser', 'testcreateuserpass', policies='not_root')

        result = await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        self.client.token = self.manager.root_token
        await self.client.delete_userpass('testcreateuser')
        with self.assertRaises(exceptions.InvalidRequest):
            await self.client.auth_userpass('testcreateuser', 'testcreateuserpass')

    async def test_app_id_auth(self):
        if 'app-id/' in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend('app-id')

        await self.client.enable_auth_backend('app-id')

        await self.client.write('auth/app-id/map/app-id/foo', value='not_root')
        await self.client.write('auth/app-id/map/user-id/bar', value='foo')

        result = await self.client.auth_app_id('foo', 'bar')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())

        self.client.token = self.manager.root_token
        await self.client.disable_auth_backend('app-id')

    async def test_create_app_id(self):
        if 'app-id/' not in (await self.client.list_auth_backends())['data']:
            await self.client.enable_auth_backend('app-id')

        await self.client.create_app_id('testappid', policies='not_root', display_name='displayname')

        result = await self.client.read('auth/app-id/map/app-id/testappid')
        lib_result = await self.client.get_app_id('testappid')
        del result['request_id']
        del lib_result['request_id']
        assert result == lib_result

        assert result['data']['key'] == 'testappid'
        assert result['data']['display_name'] == 'displayname'
        assert result['data']['value'] == 'not_root'
        await self.client.delete_app_id('testappid')
        assert (await self.client.get_app_id('testappid'))['data'] is None

        self.client.token = self.manager.root_token
        await self.client.disable_auth_backend('app-id')

    async def test_create_user_id(self):
        if 'app-id/' not in (await self.client.list_auth_backends())['data']:
            await self.client.enable_auth_backend('app-id')

        await self.client.create_app_id('testappid', policies='not_root', display_name='displayname')
        await self.client.create_user_id('testuserid', app_id='testappid')

        result = await self.client.read('auth/app-id/map/user-id/testuserid')
        lib_result = await self.client.get_user_id('testuserid')
        del result['request_id']
        del lib_result['request_id']
        assert result == lib_result

        assert result['data']['key'] == 'testuserid'
        assert result['data']['value'] == 'testappid'

        result = await self.client.auth_app_id('testappid', 'testuserid')

        assert self.client.token == result['auth']['client_token']
        assert (await self.client.is_authenticated())
        self.client.token = self.manager.root_token
        await self.client.delete_user_id('testuserid')
        assert (await self.client.get_user_id('testuserid'))['data'] is None

        self.client.token = self.manager.root_token
        await self.client.disable_auth_backend('app-id')

    async def test_transit_read_write(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')
        result = await self.client.transit_read_key('foo')
        assert not result['data']['exportable']

        await self.client.transit_create_key('foo_export', exportable=True, key_type="ed25519")
        result = await self.client.transit_read_key('foo_export')
        assert result['data']['exportable']
        assert result['data']['type'] == 'ed25519'

        await self.client.enable_secret_backend('transit', mount_point='bar')
        await self.client.transit_create_key('foo', mount_point='bar')
        result = await self.client.transit_read_key('foo', mount_point='bar')
        assert not result['data']['exportable']

    async def test_transit_list_keys(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo1')
        await self.client.transit_create_key('foo2')
        await self.client.transit_create_key('foo3')

        result = await self.client.transit_list_keys()
        assert result['data']['keys'] == ["foo1", "foo2", "foo3"]

    async def test_transit_update_delete_keys(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')
        await self.client.transit_update_key('foo', deletion_allowed=True)
        result = await self.client.transit_read_key('foo')
        assert result['data']['deletion_allowed']

        await self.client.transit_delete_key('foo')

        try:
            await self.client.transit_read_key('foo')
        except exceptions.InvalidPath:
            assert True
        else:
            assert False

    async def test_transit_rotate_key(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')

        await self.client.transit_rotate_key('foo')
        response = await self.client.transit_read_key('foo')
        assert '2' in response['data']['keys']

        await self.client.transit_rotate_key('foo')
        response = await self.client.transit_read_key('foo')
        assert '3' in response['data']['keys']

    async def test_transit_export_key(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo', exportable=True)
        response = await self.client.transit_export_key('foo', key_type='encryption-key')
        assert response is not None

    async def test_transit_encrypt_data(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')
        ciphertext_resp = (await self.client.transit_encrypt_data('foo', 'abbaabba'))['data']['ciphertext']
        plaintext_resp = (await self.client.transit_decrypt_data('foo', ciphertext_resp))['data']['plaintext']
        assert plaintext_resp == 'abbaabba'

    async def test_transit_rewrap_data(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')
        ciphertext_resp = (await self.client.transit_encrypt_data('foo', 'abbaabba'))['data']['ciphertext']

        await self.client.transit_rotate_key('foo')
        response_wrap = (await self.client.transit_rewrap_data('foo', ciphertext=ciphertext_resp))['data']['ciphertext']
        plaintext_resp = (await self.client.transit_decrypt_data('foo', response_wrap))['data']['plaintext']
        assert plaintext_resp == 'abbaabba'

    async def test_transit_generate_data_key(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')

        response_plaintext = (await self.client.transit_generate_data_key('foo', key_type='plaintext'))['data']['plaintext']
        assert response_plaintext

        response_ciphertext = (await self.client.transit_generate_data_key('foo', key_type='wrapped'))['data']
        assert 'ciphertext' in response_ciphertext
        assert 'plaintext' not in response_ciphertext

    async def test_transit_generate_rand_bytes(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        response_data = (await self.client.transit_generate_rand_bytes(data_bytes=4))['data']['random_bytes']
        assert response_data

    async def test_transit_hash_data(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        response_hash = (await self.client.transit_hash_data('abbaabba'))['data']['sum']
        assert len(response_hash) == 64

        response_hash = (await self.client.transit_hash_data('abbaabba', algorithm="sha2-512"))['data']['sum']
        assert len(response_hash) == 128

    async def test_transit_generate_verify_hmac(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo')

        response_hmac = (await self.client.transit_generate_hmac('foo', 'abbaabba'))['data']['hmac']
        assert response_hmac
        verify_resp = (await self.client.transit_verify_signed_data('foo', 'abbaabba', hmac=response_hmac))['data']['valid']
        assert verify_resp

        response_hmac = (await self.client.transit_generate_hmac('foo', 'abbaabba', algorithm='sha2-512'))['data']['hmac']
        assert response_hmac
        verify_resp = (await self.client.transit_verify_signed_data('foo', 'abbaabba',
                                                             algorithm='sha2-512', hmac=response_hmac))['data']['valid']
        assert verify_resp

    async def test_transit_sign_verify_signature_data(self):
        if 'transit/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('transit')
        await self.client.enable_secret_backend('transit')

        await self.client.transit_create_key('foo', key_type='ed25519')

        signed_resp = (await self.client.transit_sign_data('foo', 'abbaabba'))['data']['signature']
        assert signed_resp
        verify_resp = (await self.client.transit_verify_signed_data('foo', 'abbaabba', signature=signed_resp))['data']['valid']
        assert verify_resp

        signed_resp = (await self.client.transit_sign_data('foo', 'abbaabba', algorithm='sha2-512'))['data']['signature']
        assert signed_resp
        verify_resp = (await self.client.transit_verify_signed_data('foo', 'abbaabba',
                                                             algorithm='sha2-512',
                                                             signature=signed_resp))['data']['valid']
        assert verify_resp

    async def test_missing_token(self):
        client = utils.create_client()
        assert not (await client.is_authenticated())

    async def test_invalid_token(self):
        client = utils.create_client(token='not-a-real-token')
        assert not (await client.is_authenticated())

    async def test_illegal_token(self):
        async with utils.create_client(token='token-with-new-line\n') as client:
            try:
                await client.is_authenticated()
            except ValueError as e:
                assert 'Invalid header value' in str(e)

    async def test_broken_token(self):
        async with utils.create_client(token='\x1b') as client:
            try:
                await client.is_authenticated()
            except exceptions.InvalidRequest as e:
                assert "invalid header value" in str(e)

    async def test_client_authenticated(self):
        assert (await self.client.is_authenticated())

    async def test_client_logout(self):
        await self.client.logout()
        assert not (await self.client.is_authenticated())

    async def test_revoke_self_token(self):
        if 'userpass/' in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend('userpass')

        await self.client.enable_auth_backend('userpass')

        await self.client.write('auth/userpass/users/testuser', password='testpass', policies='not_root')

        await self.client.auth_userpass('testuser', 'testpass')

        await self.client.revoke_self_token()
        assert not (await self.client.is_authenticated())

    async def test_tls_auth(self):
        await self.client.enable_auth_backend('cert')

        with open(utils.get_config_file_path('client-cert.pem')) as fp:
            certificate = fp.read()

        await self.client.write('auth/cert/certs/test', display_name='test',
                          policies='not_root', certificate=certificate)

        await self.client.auth_tls()

    async def test_gh51(self):
        key = 'secret/http://test.com'

        await self.client.write(key, foo='bar')

        result = await self.client.read(key)

        assert result['data']['foo'] == 'bar'

    async def test_token_accessor(self):
        # Create token, check accessor is provided
        result = await self.client.create_token(lease='1h')
        token_accessor = result['auth'].get('accessor', None)
        assert token_accessor

        # Look up token by accessor, make sure token is excluded from results
        lookup = await self.client.lookup_token(token_accessor, accessor=True)
        assert lookup['data']['accessor'] == token_accessor
        assert not lookup['data']['id']

        # Revoke token using the accessor
        await self.client.revoke_token(token_accessor, accessor=True)

        # Look up by accessor should fail
        with self.assertRaises(exceptions.InvalidRequest):
            lookup = await self.client.lookup_token(token_accessor, accessor=True)

        # As should regular lookup
        with self.assertRaises(exceptions.Forbidden):
            lookup = await self.client.lookup_token(result['auth']['client_token'])

    async def test_create_token_explicit_max_ttl(self):

        token = await self.client.create_token(ttl='30m', explicit_max_ttl='5m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 300

        # Validate token
        lookup = await self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']

    async def test_create_token_max_ttl(self):

        token = await self.client.create_token(ttl='5m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 300

        # Validate token
        lookup = await self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']

    async def test_create_token_periodic(self):

        token = await self.client.create_token(period='30m')

        assert token['auth']['client_token']

        assert token['auth']['lease_duration'] == 1800

        # Validate token
        lookup = await self.client.lookup_token(token['auth']['client_token'])
        assert token['auth']['client_token'] == lookup['data']['id']
        assert lookup['data']['period'] == 1800

    async def test_token_roles(self):
        # No roles, list_token_roles == None
        before = await self.client.list_token_roles()
        assert not before

        # Create token role
        assert (await self.client.create_token_role('testrole')).status == 204

        # List token roles
        during = (await self.client.list_token_roles())['data']['keys']
        assert len(during) == 1
        assert during[0] == 'testrole'

        # Delete token role
        await self.client.delete_token_role('testrole')

        # No roles, list_token_roles == None
        after = await self.client.list_token_roles()
        assert not after

    async def test_create_token_w_role(self):
        # Create policy
        await self.prep_policy('testpolicy')

        # Create token role w/ policy
        assert (await self.client.create_token_role('testrole',
                                             allowed_policies='testpolicy')).status == 204

        # Create token against role
        token = await self.client.create_token(lease='1h', role='testrole')
        assert token['auth']['client_token']
        assert token['auth']['policies'] == ['default', 'testpolicy']

        # Cleanup
        await self.client.delete_token_role('testrole')
        await self.client.delete_policy('testpolicy')

    async def test_ec2_role_crud(self):
        if 'aws-ec2/' in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend('aws-ec2')
        await self.client.enable_auth_backend('aws-ec2')

        # create a policy to associate with the role
        await self.prep_policy('ec2rolepolicy')

        # attempt to get a list of roles before any exist
        no_roles = await self.client.list_ec2_roles()
        # doing so should succeed and return None
        assert (no_roles is None)

        # test binding by AMI ID (the old way, to ensure backward compatibility)
        await self.client.create_ec2_role('foo',
                                    'ami-notarealami',
                                    policies='ec2rolepolicy')

        # test binding by Account ID
        await self.client.create_ec2_role('bar',
                                    bound_account_id='123456789012',
                                    policies='ec2rolepolicy')

        # test binding by IAM Role ARN
        await self.client.create_ec2_role('baz',
                                    bound_iam_role_arn='arn:aws:iam::123456789012:role/mockec2role',
                                    policies='ec2rolepolicy')

        # test binding by instance profile ARN
        await self.client.create_ec2_role('qux',
                                    bound_iam_instance_profile_arn='arn:aws:iam::123456789012:instance-profile/mockprofile',
                                    policies='ec2rolepolicy')

        # test binding by bound region
        await self.client.create_ec2_role('quux',
                                    bound_region='ap-northeast-2',
                                    policies='ec2rolepolicy')

        # test binding by bound vpc id
        await self.client.create_ec2_role('corge',
                                    bound_vpc_id='vpc-1a123456',
                                    policies='ec2rolepolicy')

        # test binding by bound subnet id
        await self.client.create_ec2_role('grault',
                                    bound_subnet_id='subnet-123a456',
                                    policies='ec2rolepolicy')

        roles = await self.client.list_ec2_roles()

        assert('foo' in roles['data']['keys'])
        assert('bar' in roles['data']['keys'])
        assert('baz' in roles['data']['keys'])
        assert('qux' in roles['data']['keys'])
        assert('quux' in roles['data']['keys'])
        assert('corge' in roles['data']['keys'])
        assert('grault' in roles['data']['keys'])

        foo_role = await self.client.get_ec2_role('foo')
        assert ('ami-notarealami' in foo_role['data']['bound_ami_id'])
        assert ('ec2rolepolicy' in foo_role['data']['policies'])

        bar_role = await self.client.get_ec2_role('bar')
        assert ('123456789012' in bar_role['data']['bound_account_id'])
        assert ('ec2rolepolicy' in bar_role['data']['policies'])

        baz_role = await self.client.get_ec2_role('baz')
        assert ('arn:aws:iam::123456789012:role/mockec2role' in baz_role['data']['bound_iam_role_arn'])
        assert ('ec2rolepolicy' in baz_role['data']['policies'])

        qux_role = await self.client.get_ec2_role('qux')
        assert('arn:aws:iam::123456789012:instance-profile/mockprofile' in qux_role['data']['bound_iam_instance_profile_arn'])
        assert('ec2rolepolicy' in qux_role['data']['policies'])

        quux_role = await self.client.get_ec2_role('quux')
        assert('ap-northeast-2' in quux_role['data']['bound_region'])
        assert('ec2rolepolicy' in quux_role['data']['policies'])

        corge_role = await self.client.get_ec2_role('corge')
        assert('vpc-1a123456' in corge_role['data']['bound_vpc_id'])
        assert('ec2rolepolicy' in corge_role['data']['policies'])

        grault_role = await self.client.get_ec2_role('grault')
        assert('subnet-123a456' in grault_role['data']['bound_subnet_id'])
        assert('ec2rolepolicy' in grault_role['data']['policies'])

        # teardown
        await self.client.delete_ec2_role('foo')
        await self.client.delete_ec2_role('bar')
        await self.client.delete_ec2_role('baz')
        await self.client.delete_ec2_role('qux')
        await self.client.delete_ec2_role('quux')
        await self.client.delete_ec2_role('corge')
        await self.client.delete_ec2_role('grault')

        await self.client.delete_policy('ec2rolepolicy')

        await self.client.disable_auth_backend('aws-ec2')

    async def test_ec2_role_token_lifespan(self):
        if 'aws-ec2/' not in (await self.client.list_auth_backends())['data']:
            await self.client.enable_auth_backend('aws-ec2')

        # create a policy to associate with the role
        await self.prep_policy('ec2rolepolicy')

        # create a role with no TTL
        await self.client.create_ec2_role('foo',
                                    'ami-notarealami',
                                    policies='ec2rolepolicy')

        # create a role with a 1hr TTL
        await self.client.create_ec2_role('bar',
                                    'ami-notarealami',
                                    ttl='1h',
                                    policies='ec2rolepolicy')

        # create a role with a 3-day max TTL
        await self.client.create_ec2_role('baz',
                                    'ami-notarealami',
                                    max_ttl='72h',
                                    policies='ec2rolepolicy')

        # create a role with 1-day period
        await self.client.create_ec2_role('qux',
                                    'ami-notarealami',
                                    period='24h',
                                    policies='ec2rolepolicy')

        foo_role = await self.client.get_ec2_role('foo')
        assert (foo_role['data']['ttl'] == 0)

        bar_role = await self.client.get_ec2_role('bar')
        assert (bar_role['data']['ttl'] == 3600)

        baz_role = await self.client.get_ec2_role('baz')
        assert (baz_role['data']['max_ttl'] == 259200)

        qux_role = await self.client.get_ec2_role('qux')
        assert (qux_role['data']['period'] == 86400)

        # teardown
        await self.client.delete_ec2_role('foo')
        await self.client.delete_ec2_role('bar')
        await self.client.delete_ec2_role('baz')
        await self.client.delete_ec2_role('qux')

        await self.client.delete_policy('ec2rolepolicy')

        await self.client.disable_auth_backend('aws-ec2')

    async def test_auth_ec2_alternate_mount_point_with_no_client_token_exception(self):
        test_mount_point = 'aws-custom-path'
        # Turn on the aws-ec2 backend with a custom mount_point path specified.
        if '{0}/'.format(test_mount_point) in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend(test_mount_point)
        await self.client.enable_auth_backend('aws-ec2', mount_point=test_mount_point)

        # Drop the client's token to replicate a typical end user's use of any auth method.
        # I.e., its reasonable to expect the method is being called to _retrieve_ a token in the first place.
        self.client.token = None

        # Load a mock PKCS7 encoded self-signed certificate to stand in for a real document from the AWS identity service.
        with open(utils.get_config_file_path('identity_document.p7b')) as fp:
            pkcs7 = fp.read()

        # When attempting to auth (POST) to an auth backend mounted at a different path than the default, we expect a
        # generic 'missing client token' response from Vault.
        with self.assertRaises(exceptions.InvalidRequest) as assertRaisesContext:
            await self.client.auth_ec2(pkcs7=pkcs7)

        expected_exception_message = 'missing client token'
        actual_exception_message = str(assertRaisesContext.exception)
        self.assertEqual(expected_exception_message, actual_exception_message)

        # Reset test state.
        self.client.token = self.manager.root_token
        await self.client.disable_auth_backend(mount_point=test_mount_point)

    async def test_auth_ec2_alternate_mount_point_with_no_client_token(self):
        test_mount_point = 'aws-custom-path'
        # Turn on the aws-ec2 backend with a custom mount_point path specified.
        if '{0}/'.format(test_mount_point) in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend(test_mount_point)
        await self.client.enable_auth_backend('aws-ec2', mount_point=test_mount_point)

        # Drop the client's token to replicate a typical end user's use of any auth method.
        # I.e., its reasonable to expect the method is being called to _retrieve_ a token in the first place.
        self.client.token = None

        # Load a mock PKCS7 encoded self-signed certificate to stand in for a real document from the AWS identity service.
        with open(utils.get_config_file_path('identity_document.p7b')) as fp:
            pkcs7 = fp.read()

        # If our custom path is respected, we'll still end up with Vault's inability to decrypt our dummy PKCS7 string.
        # However this exception indicates we're correctly hitting the expected auth endpoint.
        with self.assertRaises(exceptions.InternalServerError) as assertRaisesContext:
            await self.client.auth_ec2(pkcs7=pkcs7, mount_point=test_mount_point)

        expected_exception_message = 'failed to decode the PEM encoded PKCS#7 signature'
        actual_exception_message = str(assertRaisesContext.exception)
        self.assertEqual(expected_exception_message, actual_exception_message)

        # Reset test state.
        self.client.token = self.manager.root_token
        await self.client.disable_auth_backend(mount_point=test_mount_point)

    async def test_auth_gcp_alternate_mount_point_with_no_client_token_exception(self):
        test_mount_point = 'gcp-custom-path'
        # Turn on the gcp backend with a custom mount_point path specified.
        if '{0}/'.format(test_mount_point) in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend(test_mount_point)
        await self.client.enable_auth_backend('gcp', mount_point=test_mount_point)

        # Drop the client's token to replicate a typical end user's use of any auth method.
        # I.e., its reasonable to expect the method is being called to _retrieve_ a token in the first place.
        self.client.token = None

        # Load a mock JWT stand in for a real document from GCP.
        with open(utils.get_config_file_path('example.jwt')) as fp:
            jwt = fp.read()

        # When attempting to auth (POST) to an auth backend mounted at a different path than the default, we expect a
        # generic 'missing client token' response from Vault.
        with self.assertRaises(exceptions.InvalidRequest) as assertRaisesContext:
            await self.client.auth.gcp.login('example-role', jwt)

        expected_exception_message = 'missing client token'
        actual_exception_message = str(assertRaisesContext.exception)
        self.assertEqual(expected_exception_message, actual_exception_message)

        # Reset test state.
        self.client.token = self.manager.root_token
        await self.client.disable_auth_backend(mount_point=test_mount_point)

    @skipIf(utils.if_vault_version('0.10.0'), "KV version 2 secret engine not available before Vault version 0.10.0")
    async def test_kv2_secret_backend(self):
        if 'test/' in (await self.client.list_secret_backends())['data']:
            await self.client.disable_secret_backend('test')
        await self.client.enable_secret_backend('kv', mount_point='test', options={'version': '2'})

        secret_backends = (await self.client.list_secret_backends())['data']

        assert 'test/' in secret_backends
        self.assertDictEqual(secret_backends['test/']['options'], {'version': '2'})

        await self.client.disable_secret_backend('test')

    async def test_create_kubernetes_configuration(self):
        expected_status_code = 204
        test_mount_point = 'k8s'

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if '{0}/'.format(test_mount_point) in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend(test_mount_point)
        await self.client.enable_auth_backend('kubernetes', mount_point=test_mount_point)

        with open(utils.get_config_file_path('client-cert.pem')) as fp:
            certificate = fp.read()
            response = await self.client.create_kubernetes_configuration(
                kubernetes_host='localhost:80',
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )
        self.assertEqual(
            first=expected_status_code,
            second=response.status,
        )

        # Reset integration test state
        await self.client.disable_auth_backend(mount_point=test_mount_point)

    async def test_get_kubernetes_configuration(self):
        test_host = 'localhost:80'
        test_mount_point = 'k8s'

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if '{0}/'.format(test_mount_point) in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend(test_mount_point)
        await self.client.enable_auth_backend('kubernetes', mount_point=test_mount_point)
        with open(utils.get_config_file_path('client-cert.pem')) as fp:
            certificate = fp.read()
            await self.client.create_kubernetes_configuration(
                kubernetes_host=test_host,
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        # Test that we can retrieve the configuration
        response = await self.client.get_kubernetes_configuration(
            mount_point=test_mount_point
        )
        self.assertIn(
            member='data',
            container=response,
        )
        self.assertEquals(
            first=test_host,
            second=response['data'].get('kubernetes_host')
        )

        # Reset integration test state
        await self.client.disable_auth_backend(mount_point=test_mount_point)

    async def test_create_kubernetes_role(self):
        test_role_name = 'test_role'
        test_mount_point = 'k8s'
        expected_status_code = 204

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if '{0}/'.format(test_mount_point) in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend(test_mount_point)
        await self.client.enable_auth_backend('kubernetes', mount_point=test_mount_point)

        with open(utils.get_config_file_path('client-cert.pem')) as fp:
            certificate = fp.read()
            await self.client.create_kubernetes_configuration(
                kubernetes_host='localhost:80',
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        # Test that we can createa role
        response = await self.client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names='*',
            bound_service_account_namespaces='vault_test',
            mount_point=test_mount_point,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status,
        )

        # Reset integration test state
        await self.client.disable_auth_backend(mount_point=test_mount_point)

    async def test_get_kubernetes_role(self):
        test_role_name = 'test_role'
        test_mount_point = 'k8s'
        test_bound_service_account_namespaces = ['vault-test']

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if '{0}/'.format(test_mount_point) in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend(test_mount_point)
        await self.client.enable_auth_backend('kubernetes', mount_point=test_mount_point)

        with open(utils.get_config_file_path('client-cert.pem')) as fp:
            certificate = fp.read()
            await self.client.create_kubernetes_configuration(
                kubernetes_host='localhost:80',
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        # Test that we can createa role
        await self.client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names='*',
            bound_service_account_namespaces=test_bound_service_account_namespaces,
            mount_point=test_mount_point,
        )
        response = await self.client.get_kubernetes_role(
            name=test_role_name,
            mount_point=test_mount_point,
        )
        self.assertIn(
            member='data',
            container=response,
        )
        self.assertEquals(
            first=test_bound_service_account_namespaces,
            second=response['data'].get('bound_service_account_namespaces')
        )
        # Reset integration test state
        await self.client.disable_auth_backend(mount_point=test_mount_point)

    async def test_list_kubernetes_roles(self):
        test_role_name = 'test_role'
        test_mount_point = 'k8s'
        test_bound_service_account_namespaces = ['vault-test']

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if '{0}/'.format(test_mount_point) in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend(test_mount_point)
        await self.client.enable_auth_backend('kubernetes', mount_point=test_mount_point)

        with open(utils.get_config_file_path('client-cert.pem')) as fp:
            certificate = fp.read()
            await self.client.create_kubernetes_configuration(
                kubernetes_host='localhost:80',
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        # Test that we can createa role
        await self.client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names='*',
            bound_service_account_namespaces=test_bound_service_account_namespaces,
            mount_point=test_mount_point,
        )
        response = await self.client.list_kubernetes_roles(
            mount_point=test_mount_point,
        )
        self.assertIn(
            member='data',
            container=response,
        )
        self.assertEquals(
            first=[test_role_name],
            second=response['data'].get('keys')
        )
        # Reset integration test state
        await self.client.disable_auth_backend(mount_point=test_mount_point)

    async def test_delete_kubernetes_role(self):
        test_role_name = 'test_role'
        test_mount_point = 'k8s'
        expected_status_code = 204

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if '{0}/'.format(test_mount_point) in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend(test_mount_point)
        await self.client.enable_auth_backend('kubernetes', mount_point=test_mount_point)

        with open(utils.get_config_file_path('client-cert.pem')) as fp:
            certificate = fp.read()
            await self.client.create_kubernetes_configuration(
                kubernetes_host='localhost:80',
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        await self.client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names='*',
            bound_service_account_namespaces='vault_test',
            mount_point=test_mount_point,
        )
        # Test that we can delete a role
        response = await self.client.delete_kubernetes_role(
            role=test_role_name,
            mount_point=test_mount_point,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status,
        )

        # Reset integration test state
        await self.client.disable_auth_backend(mount_point=test_mount_point)

    async def test_auth_kubernetes(self):
        test_role_name = 'test_role'
        test_host = 'localhost:80'
        test_mount_point = 'k8s'

        # Turn on the kubernetes backend with a custom mount_point path specified.
        if '{0}/'.format(test_mount_point) in (await self.client.list_auth_backends())['data']:
            await self.client.disable_auth_backend(test_mount_point)
        await self.client.enable_auth_backend('kubernetes', mount_point=test_mount_point)
        with open(utils.get_config_file_path('client-cert.pem')) as fp:
            certificate = fp.read()
            await self.client.create_kubernetes_configuration(
                kubernetes_host=test_host,
                pem_keys=[certificate],
                mount_point=test_mount_point,
            )

        await self.client.create_kubernetes_role(
            name=test_role_name,
            bound_service_account_names='*',
            bound_service_account_namespaces='vault_test',
            mount_point=test_mount_point,
        )

        # Test that we can authenticate
        with open(utils.get_config_file_path('example.jwt')) as fp:
            test_jwt = fp.read()
            with self.assertRaises(exceptions.InternalServerError) as assertRaisesContext:
                # we don't actually have a valid JWT to provide, so this method will throw an exception
                await self.client.auth_kubernetes(
                    role=test_role_name,
                    jwt=test_jwt,
                    mount_point=test_mount_point,
                )

        expected_exception_message = 'claim "iss" is invalid'
        actual_exception_message = str(assertRaisesContext.exception)
        self.assertEqual(expected_exception_message, actual_exception_message)

        # Reset integration test state
        await self.client.disable_auth_backend(mount_point=test_mount_point)

    async def test_seal_status(self):
        seal_status_property = await self.client.seal_status
        logging.debug('seal_status_property: %s' % seal_status_property)
        self.assertIn(
            member='sealed',
            container=seal_status_property,
        )
