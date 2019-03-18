"""Collection of Vault system backend API endpoint classes."""
import logging

from async_hvac.api.system_backend.audit import Audit
from async_hvac.api.system_backend.auth import Auth
from async_hvac.api.system_backend.health import Health
from async_hvac.api.system_backend.init import Init
from async_hvac.api.system_backend.key import Key
from async_hvac.api.system_backend.leader import Leader
from async_hvac.api.system_backend.lease import Lease
from async_hvac.api.system_backend.mount import Mount
from async_hvac.api.system_backend.policy import Policy
from async_hvac.api.system_backend.seal import Seal
from async_hvac.api.system_backend.wrapping import Wrapping
from async_hvac.api.system_backend.system_backend_mixin import SystemBackendMixin
from async_hvac.api.vault_api_category import VaultApiCategory

__all__ = (
    'Audit',
    'Auth',
    'Health',
    'Init',
    'Key',
    'Leader',
    'Lease',
    'Mount',
    'Policy',
    'Seal',
    'SystemBackend',
    'SystemBackendMixin',
    'Wrapping',
)


logger = logging.getLogger(__name__)


class SystemBackend(VaultApiCategory, Audit, Auth, Health, Init, Key, Leader, Lease, Mount, Policy, Seal, Wrapping):
    implemented_classes = [
        Audit,
        Auth,
        Health,
        Init,
        Key,
        Leader,
        Lease,
        Mount,
        Policy,
        Seal,
        Wrapping,
    ]
    unimplemented_classes = []

    def __init__(self, adapter):
        self._adapter = adapter

    def __getattr__(self, item):
        raise AttributeError
