"""Local vendored OWASP modules (A01..A10).
Place original files (A01.py..A10.py, utils.py, wordlists) here if you vendor them.

This package adjusts sys.path so that legacy absolute imports like
`import utils` inside the vendored modules resolve correctly to the
local `utils.py` in the same folder.
"""

import os
import sys

_HERE = os.path.dirname(__file__)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Expose the main scanner functions
try:
    from .OWASP_MASTER_SCANNER import scan_target, get_available_modules, get_module_info
    __all__ = ['scan_target', 'get_available_modules', 'get_module_info']
except ImportError:
    __all__ = []



