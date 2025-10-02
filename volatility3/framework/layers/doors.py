# Doors OS Volatility3 Support
# Copyright 2023 Volatility Foundation
# Licensed under the Volatility Software License 1.0
# https://www.volatilityfoundation.org/license/vsl-v1.0

import collections
import logging
import re
from typing import Optional, Tuple, List, Dict, Any, Iterable

from volatility3.framework import interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear
from volatility3.framework.symbols import intermed

vollog = logging.getLogger(__name__)


class DoorsKernelLayer(linear.LinearlyMappedLayer):
    """Translation layer for Doors OS kernel memory."""

    _direct_metadata = collections.ChainMap(
        {"architecture": "Doors64", "os": "doors", "mapped": True},
        interfaces.layers.TranslationLayerInterface._direct_metadata,
    )

    MAGIC_PATTERN = b"DoorsOsIdentifier"

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context, config_path, name, metadata)
        self._base_layer = self.config["memory_layer"]
        self._base_offset = self.config.get("base_offset", 0)
        self._dtb = self.config.get("dtb", 0)
        self._page_size = 0x1000
        self._mappings: Dict[Tuple[int, int], Tuple[int, str]] = {}

    def add_mapping(self, virtual_addr: int, physical_addr: int, length: int) -> None:
        if isinstance(self._base_layer, str):
            self._mappings[(virtual_addr, length)] = (physical_addr, self._base_layer)
        else:
            raise TypeError(f"Base layer name must be a string, got {type(self._base_layer)}")

    def _initialize_mappings(self) -> None:
        if not self._mappings:
            base_layer = self._context.layers.get(self._base_layer, None)
            if not base_layer:
                raise ValueError(f"Base layer {self._base_layer} not found")
            max_addr = base_layer.maximum_address
            self.add_mapping(0, self._base_offset, max_addr)

    def is_valid(self, offset: int, length: int = 1) -> bool:
        try:
            for _ in self.mapping(offset, length):
                return True
        except Exception:
            pass
        return False

    @property
    def dependencies(self) -> List[str]:
        return [self._base_layer] if isinstance(self._base_layer, str) else []

    def mapping(self, offset: int, length: int,
                ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, int, str]]:
        if not length:
            return []
        if not self._mappings:
            self._initialize_mappings()
        for (map_offset, map_len), (phys_offset, layer_name) in self._mappings.items():
            if map_offset <= offset < map_offset + map_len:
                available = min(map_offset + map_len, offset + length) - offset
                phys_addr = phys_offset + (offset - map_offset)
                yield offset, available, phys_addr, available, layer_name
                if available < length:
                    yield from self.mapping(offset + available, length - available, ignore_errors)
                return
        if not ignore_errors:
            from volatility3.framework import exceptions
            raise exceptions.InvalidAddressException(self.name, offset,
                                                     f"Invalid address at {offset:#x}")

    @property
    def minimum_address(self) -> int:
        if not self._mappings:
            self._initialize_mappings()
        return min((offset for (offset, _) in self._mappings.keys()), default=0)

    @property
    def maximum_address(self) -> int:
        if not self._mappings:
            self._initialize_mappings()
        return max((offset + length for (offset, length) in self._mappings.keys()), default=0)

    @classmethod
    def find_doors_header(cls, context: interfaces.context.ContextInterface,
                          base_layer_name: str) -> Optional[Tuple[int, int]]:
        DOORS_KERNEL_BASE = 0
        layer = context.layers[base_layer_name]
        vollog.info(f"Scanning for Doors OS identifier: {cls.MAGIC_PATTERN}")
        kernel_scan_size = 0x1000000  # 16MB
        chunk_size = 0x100000
        try:
            for chunk_offset in range(0, kernel_scan_size, chunk_size):
                scan_start = DOORS_KERNEL_BASE + chunk_offset
                if scan_start >= layer.maximum_address:
                    break
                actual_chunk_size = min(chunk_size, layer.maximum_address - scan_start)
                if actual_chunk_size <= 0:
                    break
                try:
                    chunk = layer.read(scan_start, actual_chunk_size, pad=True)
                    pos = chunk.find(cls.MAGIC_PATTERN)
                    if pos >= 0:
                        signature_offset = scan_start + pos
                        vollog.info(f"Found Doors OS identifier at offset: {signature_offset:#x}")
                        return DOORS_KERNEL_BASE, 0
                except Exception as e:
                    vollog.debug(f"Error reading chunk at {scan_start:#x}: {e}")
                    continue
        except Exception as e:
            vollog.debug(f"Error in kernel region scan: {e}")
        vollog.info("No Doors OS identifier found")
        return None

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="memory_layer", description="Layer on which this layer is based"),
            requirements.IntRequirement(
                name="base_offset", description="Base offset of the Doors OS image",
                default=0),
            requirements.IntRequirement(
                name="dtb", description="Directory Table Base (if Doors uses paging)",
                default=0),
        ]


class DoorsStacker(interfaces.automagic.StackerLayerInterface):
    """Stack a Doors OS layer on top of a raw memory image."""

    stack_order = 35
    exclusion_list: List[str] = []

    @classmethod
    def stack(cls, context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: constants.ProgressCallback = None) -> Optional[interfaces.layers.DataLayerInterface]:
        vollog.info(f"DoorsStacker.stack: Attempting to stack on layer {layer_name}")
        for existing_layer_name in context.layers:
            if existing_layer_name.startswith("DoorsKernelLayer"):
                vollog.debug(f"Doors layer already exists: {existing_layer_name}")
                return context.layers[existing_layer_name]
        if layer_name not in context.layers:
            vollog.error(f"Cannot stack on {layer_name} as it doesn't exist")
            return None
        if progress_callback:
            progress_callback(0, "Checking for Doors OS memory image")
        doors_header = DoorsKernelLayer.find_doors_header(context, layer_name)
        if not doors_header:
            vollog.debug("No Doors OS signature found, not stacking")
            return None
        base_offset, dtb = doors_header
        if progress_callback:
            progress_callback(50, "Creating Doors OS kernel layer")
        new_layer_name = context.layers.free_layer_name("DoorsKernelLayer")
        config_path = interfaces.configuration.path_join("automagic", "layer_stacker", new_layer_name)
        context.config[interfaces.configuration.path_join(config_path, "memory_layer")] = layer_name
        context.config[interfaces.configuration.path_join(config_path, "base_offset")] = base_offset
        context.config[interfaces.configuration.path_join(config_path, "dtb")] = dtb
        try:
            doors_layer = DoorsKernelLayer(context, config_path, new_layer_name)
            vollog.info(f"Successfully created {new_layer_name}")
            if progress_callback:
                progress_callback(100, "Doors OS kernel layer created")
            return doors_layer
        except Exception as e:
            vollog.error(f"Error creating DoorsKernelLayer: {e}")
            import traceback
            vollog.error(traceback.format_exc())
            return None


### --- SYMBOL HANDLING ---

class DoorsBannerCache:
    """Simple banner → ISF mapping for Doors OS."""

    banner_map = {
        "doors version 2.6.35": "doors/doors_kernel.json",
    }

    @classmethod
    def lookup(cls, banner: str) -> Optional[str]:
        return cls.banner_map.get(banner.lower())

class DoorsSymbolFinder(interfaces.automagic.AutomagicInterface):
    """Automagic to attach the correct Doors OS ISF based on kernel banner."""
    priority = 20  # after stacking, before plugin execution
    
    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 requirement: interfaces.configuration.RequirementInterface,
                 progress_callback: constants.ProgressCallback = None):
        """Try to find and load a Doors ISF based on the kernel banner."""
        
        for layer_name, layer in context.layers.items():
            if layer.metadata.get("os", None) != "doors":
                continue
                
            vollog.info(f"DoorsSymbolFinder: Scanning layer {layer_name} for banner")
            banner = None
            
            try:
                scan_size = min(16 * 1024 * 1024, layer.maximum_address)  # scan first 16 MB
                data = layer.read(0, scan_size, pad=True)
                # Decode UTF-8
                text = data.decode('utf-8', errors='ignore')
                # Look for banner anywhere in the text
                match = re.search(r"doors version \d+\.\d+\.\d+", text, re.IGNORECASE)
                if match:
                    banner = match.group(0)
                    vollog.info(f"Found Doors banner: {banner}")
                else:
                    vollog.warning(f"No Doors banner found in {layer_name}")
            except Exception:
                vollog.error("Exception finding banner")
                continue
                
            if not banner:
                vollog.warning(f"No Doors banner found in {layer_name}")
                continue
                
            vollog.info(f"Found Doors banner: {banner}")
            
            symbol_file = DoorsBannerCache.lookup(banner)
            if not symbol_file:
                vollog.warning(f"No ISF mapping found for banner {banner}")
                continue
                
            vollog.info(f"Mapping banner to ISF: {symbol_file}")
            
            # The correct way to load symbols in Volatility3
            try:
                # Load the ISF file and create the symbol table
                from volatility3.framework.symbols import intermed
                
                # create() returns the actual table name and adds it to symbol_space automatically
                created_table_name = intermed.IntermediateSymbolTable.create(
                    context=context,
                    config_path=config_path,
                    sub_path="doors",  # subdirectory within symbols/
                    filename="doors_kernel",  # just the filename without .json
                    class_types=None
                )
                
                vollog.info(f"Loaded Doors symbols into table {created_table_name}")
                
                # Set all required kernel configuration values
                # The requirement path shows it's looking for plugins.Banners.kernel.*
                # Extract the plugin name from config_path if it exists
                plugin_config_path = "plugins.Banners"

                vollog.info(f"CONFIG PATH IS {config_path} {requirement}")
                
                # Set the symbol table name
                context.config[interfaces.configuration.path_join(plugin_config_path, "kernel", "symbol_table_name")] = created_table_name
                
                # Set the layer name
                context.config[interfaces.configuration.path_join(plugin_config_path, "kernel", "layer_name")] = layer_name
                
                # Set the kernel virtual offset (typically 0 for direct kernel access)
                context.config[interfaces.configuration.path_join(plugin_config_path, "kernel", "layer_name", "kernel_virtual_offset")] = 0
                
                vollog.info(f"Set kernel config at {plugin_config_path}: layer={layer_name}, symbols={created_table_name}")
                
            except Exception as e:
                vollog.error(f"Failed to load symbol table: {e}")
                import traceback
                vollog.error(traceback.format_exc())
                continue
                
        return