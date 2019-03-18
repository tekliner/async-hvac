"""Vault secrets engines endpoints"""
from async_hvac.api.secrets_engines.aws import Aws
from async_hvac.api.secrets_engines.azure import Azure
from async_hvac.api.secrets_engines.identity import Identity
from async_hvac.api.secrets_engines.kv import Kv
from async_hvac.api.secrets_engines.kv_v1 import KvV1
from async_hvac.api.secrets_engines.kv_v2 import KvV2
from async_hvac.api.secrets_engines.transit import Transit
from async_hvac.api.vault_api_category import VaultApiCategory

__all__ = (
    'Aws',
    'Azure',
    'Identity',
    'Kv',
    'KvV1',
    'KvV2',
    'Transit',
    'SecretsEngines',
)


class SecretsEngines(VaultApiCategory):
    """Secrets Engines."""

    implemented_classes = [
        Aws,
        Azure,
        Identity,
        Kv,
        Transit,
    ]
    unimplemented_classes = [
        'Ad',
        'AliCloud',
        'Azure',
        'Consul',
        'Database',
        'Gcp',
        'GcpKms',
        'Nomad',
        'Pki',
        'RabbitMq',
        'Ssh',
        'TOTP',
        'Cassandra',
        'MongoDb',
        'Mssql',
        'MySql',
        'PostgreSql',
    ]
