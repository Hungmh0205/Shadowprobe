from typing import List, Dict, Any, Callable

class Finding(dict):
    """Lightweight Finding type backed by dict for flexibility."""
    pass

class ModuleSpec(dict):
    pass

REGISTRY: Dict[str, ModuleSpec] = {}

def register(module_id: str, name: str, owasp: str, runner: Callable[[str, Dict[str, Any]], List[Finding]], targets: List[str] = None):
    REGISTRY[module_id] = ModuleSpec({
        'id': module_id,
        'name': name,
        'owasp': owasp,
        'runner': runner,
        'targets': targets or ['web']
    })

def get_registry() -> Dict[str, ModuleSpec]:
    return REGISTRY


