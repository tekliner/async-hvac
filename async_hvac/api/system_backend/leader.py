from async_hvac.api.system_backend.system_backend_mixin import SystemBackendMixin


class Leader(SystemBackendMixin):

    async def read_leader_status(self):
        """Read the high availability status and current leader instance of Vault.

        Supported methods:
            GET: /sys/leader. Produces: 200 application/json

        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = '/v1/sys/leader'
        response = await self._adapter.get(
            url=api_path,
        )
        return await response.json()
