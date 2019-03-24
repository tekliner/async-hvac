import asyncio
import concurrent
import inspect

from async_hvac.v1 import AsyncClient


def async_to_sync(self, f):
    def wrapper(*args, **kwargs):
        coro = asyncio.coroutine(f)
        future = coro(*args, **kwargs)
        return self._executor.submit(
            self._loop.run_until_complete,
            future).result()
    return wrapper


# Just for test and try and do not work properly in some cases... not part of the Async API
class SyncWrapper(object):

    def __init__(self, obj):
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=3,
        )
        self._obj = obj
        self._loop = asyncio.get_event_loop()
        if self._loop.is_running():
            self._loop = asyncio.new_event_loop()

    def __getattr__(self, name):
        attr = getattr(self._obj, name)
        if inspect.ismethod(attr):
            return async_to_sync(self, attr)
        return SyncWrapper(attr)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        attr = getattr(self._obj, '__aexit__')
        return async_to_sync(self, attr)(exc_type, exc_val, exc_tb)
