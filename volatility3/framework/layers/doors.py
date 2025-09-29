# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections
import logging
from typing import Optional, Tuple, List, Dict, Any, Iterable

from volatility3.framework import interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear

vollog = logging.getLogger(__name__)


class DoorsKernelLayer(linear.LinearlyMappedLayer):
    """Translation layer for Doors OS kernel memory."""

    # Set architecture metadata using ChainMap pattern like Intel layers
    _direct_metadata = collections.ChainMap(
        {"architecture": "Doors64"},
        {"mapped": True},
        interfaces.layers.TranslationLayerInterface._direct_metadata,
    )

    # Also keep _architecture attribute for compatibility with existing DoorsInfo plugin
    _architecture = "Doors64"

    # Magic pattern to identify a Doors OS memory dump
    MAGIC_PATTERN = b"DoorsOsIdentifier"

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(context, config_path, name, metadata)
        self._base_layer = self.config["memory_layer"]
        self._base_offset = self.config.get("base_offset", 0)
        self._dtb = self.config.get("dtb", 0)
        self._page_size = 0x1000  # Default page size (4KB)

        # Initialize mappings
        self._mappings = {}  # Dict[Tuple[int, int], Tuple[int, str]]

        # For now, we assume a simple flat mapping for the entire memory space
        # Delay mapping until we're sure the base layer is available
        # This avoids circular dependencies when adding the layer

    def add_mapping(self, virtual_addr: int, physical_addr: int, length: int) -> None:
        """Adds a mapping from a virtual address to a physical offset in the base layer.

        Args:
            virtual_addr: The virtual address to map from
            physical_addr: The physical offset in the base layer to map to
            length: The length of the mapping
        """
        if isinstance(self._base_layer, str):
            self._mappings[(virtual_addr, length)] = (physical_addr, self._base_layer)
        else:
            raise TypeError(
                f"Base layer name must be a string, got {type(self._base_layer)}"
            )

    def _initialize_mappings(self) -> None:
        """Initialize mappings after the layer has been created and added to the context."""
        # For now, we assume a simple flat mapping for the entire memory space
        if not self._mappings:
            base_layer = self._context.layers.get(self._base_layer, None)
            if not base_layer:
                raise ValueError(f"Base layer {self._base_layer} not found in context")
            max_addr = base_layer.maximum_address

            # Add a single mapping for the whole range
            self.add_mapping(0, self._base_offset, max_addr)

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the specified offset is valid and mapped."""
        try:
            for _, _, _, _, _ in self.mapping(offset, length):
                return True
        except Exception:
            pass
        return False

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of the dependencies of this layer."""
        if isinstance(self._base_layer, str):
            return [self._base_layer]
        else:
            return []  # Empty list as fallback

    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        """Maps a virtual address to a physical layer and offset.

        Args:
            offset: The virtual address to map
            length: The length of the data being mapped
            ignore_errors: Whether to raise exceptions or ignore them

        Returns:
            A tuple of (offset, length, physical_offset, physical_length, layer_name)
        """
        if not length:
            return []

        # Initialize mappings if this is the first access
        if not self._mappings:
            self._initialize_mappings()

        # For now, we assume a single linear mapping (identity mapping)
        for (map_offset, map_len), (phys_offset, layer_name) in self._mappings.items():
            if offset >= map_offset and offset < map_offset + map_len:
                # Calculate how much of the requested region is within this mapping
                available = min(map_offset + map_len, offset + length) - offset
                # Calculate the corresponding physical offset
                phys_addr = phys_offset + (offset - map_offset)

                yield offset, available, phys_addr, available, layer_name

                if available < length:
                    # Continue with the next portion if we haven't mapped all requested bytes
                    yield from self.mapping(
                        offset + available, length - available, ignore_errors
                    )

                return

        if not ignore_errors:
            layer_name = self.name
            from volatility3.framework import exceptions

            raise exceptions.InvalidAddressException(
                layer_name, offset, f"Invalid address at {offset:#x}"
            )

    @property
    def minimum_address(self) -> int:
        """Returns the minimum valid address of the mapping."""
        if not self._mappings:
            return 0
        return min((offset for (offset, _) in self._mappings.keys()), default=0)

    @property
    def maximum_address(self) -> int:
        """Returns the maximum valid address of the mapping."""
        if not self._mappings:
            return 0
        return max(
            (offset + length for (offset, length) in self._mappings.keys()), default=0
        )

    @classmethod
    def _check_header(
        cls, base_layer: interfaces.layers.DataLayerInterface, offset: int = 0
    ) -> bool:
        """Checks for a valid Doors OS memory header signature.

        Args:
            base_layer: Layer to scan for the Doors OS signature
            offset: Offset to start scanning from

        Returns:
            True if the signature was found, False otherwise
        """
        try:
            data = base_layer.read(offset, len(cls.MAGIC_PATTERN) * 2, pad=True)
            return cls.MAGIC_PATTERN in data
        except Exception as e:
            vollog.debug(f"Error checking Doors OS header at {offset:#x}: {e}")
            return False

    @classmethod
    def find_doors_header(
        cls, context: interfaces.context.ContextInterface, base_layer_name: str
    ) -> Optional[Tuple[int, int]]:
        """Determines if this is a Doors OS memory image.

        Doors OS kernel starts at 0x100000 for x86 hardware, and the signature
        is located somewhere within the kernel, not necessarily at the beginning.

        Args:
            context: The context to retrieve required layers
            base_layer_name: The name of the layer to scan

        Returns:
            A tuple of kernel base address (0x100000) and kernel DTB address, or None if signature not found
        """

        # Doors OS kernel base address for x86
        DOORS_KERNEL_BASE = 0x100000

        # Scan for the Doors OS identifier pattern
        layer = context.layers[base_layer_name]

        vollog.info(f"Scanning for Doors OS identifier: {cls.MAGIC_PATTERN}")
        vollog.info(f"Doors OS kernel expected at base address: {DOORS_KERNEL_BASE:#x}")

        # Scan within the kernel region (starting from 0x100000)
        # Look for the signature within the first 16MB of kernel space
        kernel_scan_size = 0x1000000  # 16MB kernel region

        try:
            # Scan in chunks within the kernel region
            chunk_size = 0x100000  # 1MB chunks
            for chunk_offset in range(0, kernel_scan_size, chunk_size):
                scan_start = DOORS_KERNEL_BASE + chunk_offset

                # Make sure we don't exceed the layer's maximum address
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
                        vollog.info(
                            f"Found Doors OS identifier at offset: {signature_offset:#x}"
                        )
                        vollog.info(
                            f"Using kernel base address: {DOORS_KERNEL_BASE:#x}"
                        )
                        # Return kernel base (0x100000), not signature offset
                        return DOORS_KERNEL_BASE, 0
                except Exception as e:
                    vollog.debug(f"Error reading chunk at {scan_start:#x}: {e}")
                    continue

        except Exception as e:
            vollog.debug(f"Error in kernel region scan: {e}")

        # Fall back to scanning the entire memory image
        vollog.info("Signature not found in kernel region, scanning entire image...")
        try:
            # Create a custom scanner that implements __call__
            class BytesScanner(interfaces.layers.ScannerInterface):
                def __init__(self, needle: bytes):
                    super().__init__()
                    self._needle = needle

                def __call__(
                    self,
                    data: bytes,
                    data_offset: int,
                    progress_callback: callable = None,
                ):
                    """Scans a block of data for the pattern."""
                    results = []
                    pos = 0
                    while pos < len(data):
                        found_pos = data.find(self._needle, pos)
                        if found_pos >= 0:
                            results.append((data_offset + found_pos, self._needle))
                            pos = found_pos + 1
                        else:
                            break
                    return results

            scanner = layer.scan(
                context=context,
                scanner=BytesScanner(cls.MAGIC_PATTERN),
                sections=[(0, layer.maximum_address)],
            )

            for offset, _pattern in scanner:
                vollog.info(f"Found Doors OS identifier at offset: {offset:#x}")
                vollog.info(f"Using kernel base address: {DOORS_KERNEL_BASE:#x}")
                # Always return kernel base (0x100000), regardless of where signature was found
                return DOORS_KERNEL_BASE, 0
        except Exception as e:
            vollog.debug(f"Error in fallback scanner: {e}")

        vollog.info("No Doors OS identifier found")
        return None

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of configuration requirements needed to construct this layer."""
        return [
            requirements.TranslationLayerRequirement(
                name="memory_layer", description="Layer on which this layer is based"
            ),
            requirements.IntRequirement(
                name="base_offset",
                description="Base offset of the Doors OS image in the memory layer",
                default=0,
            ),
            requirements.IntRequirement(
                name="dtb",
                description="Directory Table Base (if the OS uses paging)",
                default=0,
            ),
        ]


class DoorsStacker(interfaces.automagic.StackerLayerInterface):
    """Stack a Doors OS layer on top of a raw memory image."""

    stack_order = 5  # Highest priority to run earlier than any other OS stackers
    exclusion_list: List[str] = []  # Don't exclude any plugin types for testing

    @classmethod
    def _fulfill_requirements(
        cls,
        context: interfaces.context.ContextInterface,
        doors_layer: interfaces.layers.DataLayerInterface,
    ) -> None:
        """Fulfill any requirements needing this layer type.

        Args:
            context: The context containing the configuration to modify
            doors_layer: The DoorsKernelLayer to use for requirements
        """
        # Look for any unsatisfied primary requirements and try to fulfill them
        for config_path in list(context.config.keys()):
            if config_path.endswith(".primary"):
                # This is a primary requirement that might need our layer
                vollog.info(
                    f"Found primary requirement at {config_path}, setting to {doors_layer.name}"
                )
                try:
                    context.config[config_path] = doors_layer.name
                    vollog.info(f"Set {config_path} to use {doors_layer.name}")
                except Exception as e:
                    vollog.warning(
                        f"Could not set {config_path} to {doors_layer.name}: {e}"
                    )

        # Specific handling for DoorsInfo plugin requirements
        # The plugin requirement path is constructed using the class name (DoorsInfo)
        # not the full module path (doors.info.DoorsInfo)
        doors_plugin_paths = [
            "plugins.DoorsInfo.primary",
            interfaces.configuration.path_join("plugins", "DoorsInfo", "primary"),
        ]

        for plugin_req_path in doors_plugin_paths:
            try:
                context.config[plugin_req_path] = doors_layer.name
                vollog.info(f"Set {plugin_req_path} to use {doors_layer.name}")
            except Exception as e:
                vollog.debug(f"Could not set {plugin_req_path}: {e}")

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempts to build up a Doors OS layer based on a physical layer.

        Args:
            context: The context to stack the layers on top of
            layer_name: The name of the layer to stack on top of
            progress_callback: A callback function to update progress

        Returns:
            A new layer if successful, otherwise None
        """
        # Make sure we print detailed debug info
        vollog.info(f"DoorsStacker.stack: Attempting to stack on layer {layer_name}")
        # Check if the base layer exists
        if layer_name not in context.layers:
            vollog.error(
                f"Cannot stack on {layer_name} as it doesn't exist in the context"
            )
            return None

        vollog.info(f"Layer {layer_name} is available in context")
        vollog.info(f"Context has layers: {list(context.layers.keys())}")

        if progress_callback is not None:
            progress_callback(0, "Checking for Doors OS memory image")

        # Check for the Doors OS header signature
        doors_header = DoorsKernelLayer.find_doors_header(context, layer_name)
        if not doors_header:
            vollog.debug("No Doors OS signature found, not stacking")
            return None

        vollog.info(f"Found Doors OS header at offset {doors_header[0]:#x}")

        # Create the layer with the returned information
        base_offset, dtb = doors_header

        if progress_callback is not None:
            progress_callback(50, "Creating Doors OS kernel layer")

        vollog.info(
            f"Using kernel_base: {base_offset:#x} (Doors OS kernel base), dtb: {dtb}"
        )

        # Create the configuration
        new_layer_name = context.layers.free_layer_name("DoorsKernelLayer")
        config_path = interfaces.configuration.path_join(
            "DoorsKernelLayer", new_layer_name
        )

        # Set up the config with appropriate values
        context.config[
            interfaces.configuration.path_join(config_path, "memory_layer")
        ] = layer_name
        context.config[
            interfaces.configuration.path_join(config_path, "base_offset")
        ] = base_offset
        context.config[interfaces.configuration.path_join(config_path, "dtb")] = dtb

        # Create the actual layer
        try:
            doors_layer = DoorsKernelLayer(context, config_path, new_layer_name)
            # Add the layer to the context (important!)
            context.add_layer(doors_layer)
            vollog.info(f"Successfully created {new_layer_name}")
            vollog.info(f"Updated context layers: {list(context.layers.keys())}")

            # Set this layer as the primary requirement for any doors plugins
            cls._fulfill_requirements(context, doors_layer)

            # Explicitly set the DoorsInfo.primary requirement using class name
            try:
                plugin_req_path = interfaces.configuration.path_join(
                    "plugins", "DoorsInfo", "primary"
                )
                context.config[plugin_req_path] = doors_layer.name
                vollog.info(f"Explicitly set {plugin_req_path} to {doors_layer.name}")
            except Exception as e:
                vollog.debug(f"Error setting DoorsInfo primary requirement: {e}")

            # Debug: Log context ID and configuration
            vollog.info(f"DoorsStacker context ID: {id(context)}")
            doors_related_config = {
                k: v
                for k, v in context.config.items()
                if "doors" in k.lower() or "DoorsInfo" in k
            }
            vollog.info(
                f"All Doors-related config after layer creation: {doors_related_config}"
            )

            # Debug: Check if the specific requirement path exists
            req_path = "plugins.DoorsInfo.primary"
            if req_path in context.config:
                vollog.info(
                    f"Required config path {req_path} exists with value: {context.config[req_path]}"
                )
            else:
                vollog.warning(
                    f"Required config path {req_path} NOT found in context.config"
                )
                vollog.warning(f"All config keys: {list(context.config.keys())}")

            # Print a message that will be visible to the user
            print(
                f"Created Doors OS layer {new_layer_name} with kernel base at {base_offset:#x}"
            )
        except Exception as e:
            vollog.error(f"Error creating DoorsKernelLayer: {str(e)}")
            import traceback

            vollog.error(traceback.format_exc())

            # Even if we failed to create a DoorsKernelLayer, try to set the plugin requirements
            # to use the base layer directly for plugins that can handle it
            try:
                plugin_req_path = interfaces.configuration.path_join(
                    "plugins", "DoorsInfo", "primary"
                )
                context.config[plugin_req_path] = layer_name
                vollog.info(f"Set {plugin_req_path} to use {layer_name} directly")
            except Exception as req_e:
                vollog.debug(f"Error setting requirements to use base layer: {req_e}")

            return None

        if progress_callback is not None:
            progress_callback(100, "Doors OS kernel layer created")

        vollog.info(f"Returning Doors layer {doors_layer.name}")
        # Add an output message that will be visible in normal mode
        vollog.info(f"DoorsStacker: Created Doors OS layer {doors_layer.name}")
        asdf = [doors_layer] + layer_name
        adisp = str(asdf)
        vollog.info(f"Doors layers are now {adisp}")
        return asdf
