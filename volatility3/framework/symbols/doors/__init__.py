"""
Doors OS Symbol Table Package
Provides symbol handling for Doors OS memory analysis
"""

import logging
from volatility3.framework.symbols import intermed

vollog = logging.getLogger(__name__)


class DoorsKernelIntermedSymbols(intermed.IntermediateSymbolTable):
    """
    Symbol table for Doors OS.
    Does not inherit Linux-specific requirements.
    """

    _architecture = "Doors64"
    _symbol_type = "kernel"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        vollog.info("Init DoorsKernelIntermedSymbols")
        # Don't call set_type_class for Linux-specific types
        # Add Doors-specific type extensions if needed
        vollog.debug(f"Initialized Doors symbol table: {self.name}")