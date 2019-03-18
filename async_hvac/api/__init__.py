"""Collection of Vault API endpoint classes."""
from async_hvac.api.auth_methods import AuthMethods
from async_hvac.api.secrets_engines import SecretsEngines
from async_hvac.api.system_backend import SystemBackend
from async_hvac.api.vault_api_base import VaultApiBase
from async_hvac.api.vault_api_category import VaultApiCategory

__all__ = (
    'AuthMethods',
    'SecretsEngines',
    'SystemBackend',
    'VaultApiBase',
    'VaultApiCategory',
)
