import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
NAME = "h3rm35_push_plugin_test"
spec = importlib.util.spec_from_file_location(NAME, ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
module = importlib.util.module_from_spec(spec)
sys.modules[NAME] = module
spec.loader.exec_module(module)
