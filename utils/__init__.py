"""
vbascope.utils
~~~~~~~~~~~~~~~

Low level helpers shared across the tool: hashing, file-type
identification, and dependency management.
"""

from .hashing import compute_hashes
from .file_id import identify_file, FileType
from .deps import ensure_dependencies, check_system_tools

__all__ = [
    "compute_hashes",
    "identify_file",
    "FileType",
    "ensure_dependencies",
    "check_system_tools",
]
