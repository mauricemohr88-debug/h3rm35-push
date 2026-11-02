import importlib.util
import os
from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
NAME = "h3rm35_push_plugin_test"
spec = importlib.util.spec_from_file_location(NAME, ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
module = importlib.util.module_from_spec(spec)
sys.modules[NAME] = module
spec.loader.exec_module(module)


@pytest.fixture
def tmp_path(tmp_path_factory):
    root = tmp_path_factory.mktemp("push-fixture")
    if os.name == "nt":
        # Never change inherited TEMP permissions. Create only a new private
        # child so the real Windows storage policy is exercised by every test.
        from h3rm35_push_plugin_test.core import windows_files
        files = windows_files()
        w = files.require_native()
        current, _allowed, system = files._principals(w)
        root = root / "private"
        w.win32file.CreateDirectory(str(root), files._security_attributes(
            w, current, system, directory=True))
    return root
