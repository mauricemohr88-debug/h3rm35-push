"""The API's standalone module loader and concurrent first adapter imports."""

from concurrent.futures import ThreadPoolExecutor
import threading
import time
import sys

from h3rm35_push_plugin_test import core


def test_concurrent_first_adapter_load_never_returns_partial_module(monkeypatch):
    name = core.__name__ + "_windows_storage"
    monkeypatch.delitem(sys.modules, name, raising=False)
    original = core.importlib.util.spec_from_file_location
    started = threading.Event()
    calls = []
    def spec(name_, *args, **kwargs):
        result = original(name_, *args, **kwargs)
        if name_ == name:
            execute = result.loader.exec_module
            def delayed(module):
                started.set()
                time.sleep(0.05)
                calls.append(name_)
                execute(module)
            result.loader.exec_module = delayed
        return result
    monkeypatch.setattr(core.importlib.util, "spec_from_file_location", spec)
    with ThreadPoolExecutor(max_workers=8) as pool:
        first = pool.submit(core.windows_files)
        assert started.wait(timeout=2)
        futures = [first] + [pool.submit(core.windows_files) for _ in range(7)]
        modules = [future.result(timeout=5) for future in futures]
    assert len(calls) == 1
    assert all(module is modules[0] and callable(module.open_storage) for module in modules)
