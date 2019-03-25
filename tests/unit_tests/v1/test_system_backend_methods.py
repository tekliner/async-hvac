from asynctest import TestCase

from parameterized import parameterized

from async_hvac import AsyncClient

from tests.utils import requests_mock


class TestSystemBackendMethods(TestCase):
    """Unit tests providing coverage for Vault system backend-related methods in the hvac Client class."""

    @parameterized.expand([
        ("pki lease ID", 'pki/issue/my-role/12c7e036-b59e-5e79-3370-03826fc6f34b'),
    ])
    @requests_mock.Mocker()
    async def test_read_lease(self, test_label, test_lease_id, requests_mocker):
        test_path = 'http://localhost:8200/v1/sys/leases/lookup'
        mock_response = {
            'issue_time': '2018-07-15T08:35:34.775859245-05:00',
            'renewable': False,
            'id': test_lease_id,
            'ttl': 259199,
            'expire_time': '2018-07-18T08:35:34.00004241-05:00',
            'last_renewal': None
        }
        requests_mocker.register_uri(
            method='PUT',
            url=test_path,
            json=mock_response,
        )
        async with AsyncClient() as client:
            response = await client.read_lease(
                lease_id=test_lease_id,
            )
            self.assertEquals(
                first=mock_response,
                second=response,
            )
