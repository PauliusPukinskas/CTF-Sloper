
"""CTF SLOPER v72 lazy imports.

This keeps app startup and benchmark import checks lighter by avoiding heavy
PIL/numpy imports until image/numeric solvers actually touch them.
"""
import importlib

class LazyModule:
    def __init__(self, module_name: str):
        self.module_name = module_name
        self._module = None

    def _load(self):
        if self._module is None:
            try:
                self._module = importlib.import_module(self.module_name)
            except ImportError as exc:
                raise ImportError(
                    f"CTF SLOPER requires '{self.module_name}' for this action. "
                    "Install dependencies with: pip install -r requirements.txt"
                ) from exc
        return self._module

    def __getattr__(self, name):
        return getattr(self._load(), name)

def install_lazy_imports(g: dict) -> None:
    mapping = {
        "Image": "PIL.Image",
        "ImageOps": "PIL.ImageOps",
        "ImageFilter": "PIL.ImageFilter",
        "ImageEnhance": "PIL.ImageEnhance",
        "ImageChops": "PIL.ImageChops",
        "ImageDraw": "PIL.ImageDraw",
        "np": "numpy",
    }
    for name, module_name in mapping.items():
        if name not in g:
            g[name] = LazyModule(module_name)
