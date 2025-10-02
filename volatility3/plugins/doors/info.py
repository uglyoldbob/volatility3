# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

"""Doors OS information plugin for Volatility 3."""

from typing import List, Optional
import logging

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import doors
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility


vollog = logging.getLogger(__name__)

class Banners(interfaces.plugins.PluginInterface):
    """Attempts to identify the Doors OS banner/version information."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Define the requirements for this plugin."""
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Doors kernel module"
            )
        ]

    def _get_banner_from_symbol(self, kernel):
        """
        Retrieve banner directly from the symbol table.
        This is the preferred method when symbols are available.
        """
        try:
            # Method 1: Direct banner symbol
            banner_symbol = kernel.get_symbol("doors_banner")
            banner_addr = banner_symbol.address
            
            # Read the banner string from memory
            banner_obj = kernel.object(
                object_type="array",
                offset=banner_addr,
                subtype=kernel.get_type("char"),
                count=256
            )
            
            banner_str = utility.array_to_string(banner_obj)
            return banner_str, banner_addr
            
        except exceptions.SymbolError:
            # Symbol not found, try alternative methods
            pass
        
        return None, None

    def _get_banner_from_uts(self, kernel):
        """
        Retrieve banner from UTS namespace structure.
        Similar to how Linux stores uname information.
        """
        try:
            # Get the init_uts_ns symbol
            uts_ns = kernel.object_from_symbol("init_uts_ns")
            
            # Access the utsname structure
            utsname = uts_ns.name
            
            # Extract version information
            sysname = utility.array_to_string(utsname.sysname)
            release = utility.array_to_string(utsname.release)
            version = utility.array_to_string(utsname.version)
            machine = utility.array_to_string(utsname.machine)
            
            # Combine into banner format
            banner = f"{sysname} {release} {version} {machine}"
            return banner, utsname.vol.offset
            
        except (exceptions.SymbolError, AttributeError):
            pass
        
        return None, None

    def _get_banner_from_version_info(self, kernel):
        """
        Retrieve banner from custom version_info structure.
        """
        try:
            version_info = kernel.object_from_symbol("doors_version")
            
            major = version_info.major
            minor = version_info.minor
            patch = version_info.patch
            
            # Read version string if pointer is valid
            if version_info.version_string:
                version_str_obj = kernel.object(
                    object_type="string",
                    offset=version_info.version_string,
                    max_length=256
                )
                full_banner = utility.pointer_to_string(
                    version_str_obj, 
                    256
                )
            else:
                full_banner = f"doors version {major}.{minor}.{patch}"
            
            return full_banner, version_info.vol.offset
            
        except (exceptions.SymbolError, AttributeError):
            pass
        
        return None, None

    def _generator(self):
        """Generate banner information."""
        kernel = self.context.modules[self.config["kernel"]]
        
        # Try different methods to retrieve the banner
        methods = [
            ("Direct Symbol", self._get_banner_from_symbol),
            ("UTS Namespace", self._get_banner_from_uts),
            ("Version Info", self._get_banner_from_version_info)
        ]
        
        for method_name, method_func in methods:
            banner, offset = method_func(kernel)
            
            if banner:
                yield (0, (
                    method_name,
                    format_hints.Hex(offset) if offset else "N/A",
                    banner
                ))

    def run(self):
        """Execute the plugin and return results."""
        return renderers.TreeGrid(
            [
                ("Method", str),
                ("Offset", format_hints.Hex),
                ("Banner", str)
            ],
            self._generator()
        )

class DoorsInfo(plugins.PluginInterface):
    """Displays information about the Doors OS memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of requirements needed for this plugin to execute."""
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Doors kernel module"
            )
        ]

    def _get_doors_layer(self) -> Optional[interfaces.layers.DataLayerInterface]:
        """Finds the Doors OS layer in the memory image."""
        vollog.info(f"Available layers: {list(self.context.layers.keys())}")

        # Make sure FileLayer is properly loaded
        if "FileLayer" in self.context.layers:
            vollog.info("FileLayer is loaded and available")
        else:
            vollog.warning("FileLayer is not available in context!")

        # Check if we have any layers at all
        if not self.context.layers:
            vollog.error("No layers available in the context")
            return None

        # First, try to get the layer from the primary requirement
        try:
            if self.config.get("primary", None):
                primary_layer_name = self.config["primary"]
                if primary_layer_name in self.context.layers:
                    primary_layer = self.context.layers[primary_layer_name]
                    vollog.info(
                        f"Using primary layer from config: {primary_layer_name}"
                    )
                    return primary_layer
        except Exception as e:
            vollog.debug(f"Error accessing primary config: {e}")

        # Look for any DoorsKernelLayer in the context
        for layer_name in self.context.layers:
            layer = self.context.layers[layer_name]
            if isinstance(layer, doors.DoorsKernelLayer):
                vollog.info(f"Found Doors OS layer: {layer_name}")
                # Set this as primary layer in config
                self.config["primary"] = layer_name
                return layer

        # Special case - check if our dump.bin file is available directly
        file_layer_name = "FileLayer"
        if file_layer_name in self.context.layers:
            layer = self.context.layers[file_layer_name]
            vollog.info(f"Using FileLayer directly: {file_layer_name}")
            # Set this as primary layer in config
            self.config["primary"] = file_layer_name
            return layer

        # If no DoorsKernelLayer or FileLayer found, try any layer with "File" in the name
        for layer_name in self.context.layers:
            if "File" in layer_name:
                layer = self.context.layers[layer_name]
                vollog.info(f"Using file-based layer: {layer_name}")
                # Set this as primary layer in config
                self.config["primary"] = layer_name
                return layer

        # If we still have no layer, get the first available layer
        first_layer_name = next(iter(self.context.layers.keys()))
        first_layer = self.context.layers[first_layer_name]
        vollog.info(f"Using first available layer: {first_layer.name}")
        # Set this as primary layer in config
        self.config["primary"] = first_layer_name
        return first_layer

    def _find_doors_identifier(
        self, layer: interfaces.layers.DataLayerInterface
    ) -> Optional[int]:
        """Finds the 'DoorsOsIdentifier' string in the memory image."""
        signature = b"DoorsOsIdentifier"
        vollog.info(f"Scanning for Doors OS identifier in layer: {layer.name}")

        try:

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
                context=self.context,
                scanner=BytesScanner(signature),
                sections=[(0, layer.maximum_address)],
            )
            for offset, _ in scanner:
                vollog.info(f"Found Doors OS identifier at offset: {offset:#x}")
                return offset
        except Exception as e:
            vollog.error(f"Error scanning for Doors OS identifier: {e}")

        vollog.info(f"No Doors OS identifier found in layer: {layer.name}")
        return None

    def _dump_memory_hex(
        self, layer: interfaces.layers.DataLayerInterface, start_addr: int, size: int
    ) -> str:
        """Dumps memory in hexadecimal format."""
        try:
            data = layer.read(start_addr, size, pad=True)
            hex_lines = []

            for i in range(0, len(data), 16):
                offset = start_addr + i
                chunk = data[i : i + 16]

                # Create hex representation
                hex_part = " ".join(f"{b:02x}" for b in chunk[:8])
                if len(chunk) > 8:
                    hex_part += "  " + " ".join(f"{b:02x}" for b in chunk[8:])
                else:
                    hex_part += "   " * (8 - len(chunk)) + "  "

                # Create ASCII representation
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)

                hex_lines.append(f"{offset:08x}  {hex_part:<47} |{ascii_part}|")

            return "\n" + "\n".join(hex_lines)
        except Exception as e:
            vollog.error(f"Error dumping memory at {start_addr:#x}: {e}")
            return f"Error: Could not read memory at {start_addr:#x}"

    def run(self) -> renderers.TreeGrid:
        """Runs the Doors OS Info plugin."""
        vollog.info("Starting DoorsInfo plugin")

        try:
            kernel = self.context.modules[self.config['doors_kernel1']]
            vollog.debug(f"Symbol table loaded: {self.config['doors_kernel1']}")
        except KeyError as e:
            vollog.error(f"Failed to load symbol table: {e}")
            vollog.error(f"Available modules: {list(self.context.modules.keys())}")
            raise

        # Get symbol value for PAGE_TABLE_PDP_BOOT
        page_table_pdp_boot_value = None
        page_table_pdp_boot_address = None
        symbol_table_used = None

        try:
            # Check all available symbol tables for PAGE_TABLE_PDP_BOOT
            for table_name in self.context.symbol_space:
                symbol_table = self.context.symbol_space[table_name]
                vollog.debug(f"Checking symbol table: {table_name}")

                if "PAGE_TABLE_PDP_BOOT" in symbol_table.symbols:
                    symbol = symbol_table.get_symbol("PAGE_TABLE_PDP_BOOT")
                    page_table_pdp_boot_address = symbol.address
                    symbol_table_used = table_name
                    vollog.info(
                        f"Found PAGE_TABLE_PDP_BOOT symbol in table '{table_name}' at address: 0x{page_table_pdp_boot_address:x}"
                    )

                    # Try to read the value at that address
                    doors_layer = self._get_doors_layer()
                    if doors_layer:
                        try:
                            # Read 8 bytes (assuming 64-bit value)
                            page_table_pdp_boot_bytes = doors_layer.read(
                                page_table_pdp_boot_address, 8
                            )
                            page_table_pdp_boot_value = int.from_bytes(
                                page_table_pdp_boot_bytes, byteorder="little"
                            )
                            vollog.info(
                                f"PAGE_TABLE_PDP_BOOT value: 0x{page_table_pdp_boot_value:x}"
                            )
                        except Exception as e:
                            vollog.warning(
                                f"Could not read PAGE_TABLE_PDP_BOOT value: {e}"
                            )
                    break

            if not symbol_table_used:
                vollog.warning(
                    "PAGE_TABLE_PDP_BOOT symbol not found in any symbol table. Make sure symbols are loaded with --symbol-dirs"
                )
                available_tables = list(self.context.symbol_space.keys())
                vollog.info(f"Available symbol tables: {available_tables}")

        except Exception as e:
            vollog.warning(f"Error accessing PAGE_TABLE_PDP_BOOT symbol: {e}")

        # Print available layers for debugging
        vollog.info(f"Available layers: {list(self.context.layers.keys())}")
        vollog.info(f"Configuration: {dict(self.config.data)}")

        # Special case: if no layers, try to use single-location
        if not self.context.layers and "single_location" in self.config:
            vollog.info(
                f"No layers found but single_location exists: {self.config['single_location']}"
            )
            # This would be a good place to manually create a layer if needed

        # Force scan all layers for Doors OS identifiers first
        vollog.info("Pre-scanning all layers for Doors OS identifiers...")
        for layer_name in self.context.layers:
            layer = self.context.layers[layer_name]
            identifier_offset = self._find_doors_identifier(layer)
            if identifier_offset is not None:
                vollog.info(
                    f"Found Doors OS identifier in {layer_name} at offset 0x{identifier_offset:x}"
                )

        # Check if we have a doors layer
        doors_layer = self._get_doors_layer()
        if doors_layer is None:
            vollog.error("Could not find any usable layer in the memory image")
            return renderers.TreeGrid(
                [
                    ("Property", str),
                    ("Value", str),
                ],
                [
                    (
                        0,
                        [
                            "Error",
                            "Could not find any usable layer in the memory image",
                        ],
                    ),
                ],
            )

        vollog.info(f"Selected layer for analysis: {doors_layer.name}")

        # If the layer is not a DoorsKernelLayer, look for the identifier
        if not isinstance(doors_layer, doors.DoorsKernelLayer):
            vollog.info(
                f"Layer {doors_layer.name} is not a DoorsKernelLayer, scanning for identifier"
            )
            identifier_offset = self._find_doors_identifier(doors_layer)
            if identifier_offset is not None:
                # We found an identifier in a non-DoorsKernelLayer
                vollog.info(
                    f"Found DoorsOsIdentifier in layer {doors_layer.name} at offset 0x{identifier_offset:x}"
                )
                return renderers.TreeGrid(
                    [
                        ("Property", str),
                        ("Value", str),
                    ],
                    [
                        (0, ["Layer Name", doors_layer.name]),
                        (0, ["Layer Type", type(doors_layer).__name__]),
                        (0, ["DoorsOsIdentifier Found", "Yes"]),
                        (0, ["Identifier Offset", f"0x{identifier_offset:x}"]),
                        (
                            0,
                            [
                                "Note",
                                "Found Doors OS signature, but using non-DoorsKernelLayer. "
                                "This is expected when analyzing raw memory dumps.",
                            ],
                        ),
                    ],
                )
            else:
                vollog.error("Could not find a Doors OS identifier in any layer")
                return renderers.TreeGrid(
                    [
                        ("Property", str),
                        ("Value", str),
                    ],
                    [
                        (
                            0,
                            [
                                "Error",
                                "Could not find a Doors OS identifier in any layer",
                            ],
                        ),
                        (0, ["Layer Name", doors_layer.name]),
                        (0, ["Layer Type", type(doors_layer).__name__]),
                    ],
                )

        # Get the base offset of the layer
        base_offset = doors_layer.config.get("base_offset", 0)

        # Find the Doors OS identifier in the base layer if this is a DoorsKernelLayer
        doors_identifier_offset = None
        if isinstance(doors_layer, doors.DoorsKernelLayer):
            # For DoorsKernelLayer, look for the identifier in the base layer
            base_layer_name = doors_layer.config.get("memory_layer")
            if base_layer_name and base_layer_name in self.context.layers:
                base_layer = self.context.layers[base_layer_name]
                doors_identifier_offset = self._find_doors_identifier(base_layer)
                vollog.info(
                    f"Found identifier at offset {doors_identifier_offset:#x} in base layer {base_layer_name}"
                )
        else:
            # For other layers, scan directly
            doors_identifier_offset = self._find_doors_identifier(doors_layer)

        # Dump 0x1000 bytes of memory starting at 0x100000
        memory_dump = self._dump_memory_hex(doors_layer, 0x1BB000, 0x1000)

        # Return data as a TreeGrid
        return renderers.TreeGrid(
            [
                ("Property", str),
                ("Value", str),
            ],
            [
                (
                    0,
                    [
                        "Layer Name",
                        doors_layer.name,
                    ],
                ),
                (
                    0,
                    [
                        "Layer Type",
                        "DoorsKernelLayer",
                    ],
                ),
                (
                    0,
                    [
                        "Base Layer",
                        doors_layer.config.get("memory_layer", "Unknown"),
                    ],
                ),
                (
                    0,
                    [
                        "Base Offset",
                        f"0x{base_offset:x}",
                    ],
                ),
                (
                    0,
                    [
                        "DTB",
                        f"0x{doors_layer.config.get('dtb', 0):x}",
                    ],
                ),
                (
                    0,
                    [
                        "Architecture",
                        doors_layer.metadata.get("architecture", "Unknown"),
                    ],
                ),
                (
                    0,
                    [
                        "Doors OS Identifier Offset",
                        f"0x{doors_identifier_offset if doors_identifier_offset is not None else 0:x}",
                    ],
                ),
                (
                    0,
                    [
                        "Memory Dump (0x100000-0x101000)",
                        memory_dump,
                    ],
                ),
                (
                    0,
                    [
                        "Symbol Table Used",
                        symbol_table_used if symbol_table_used else "None",
                    ],
                ),
                (
                    0,
                    [
                        "PAGE_TABLE_PDP_BOOT Address",
                        f"0x{page_table_pdp_boot_address:x}"
                        if page_table_pdp_boot_address
                        else "Not found",
                    ],
                ),
                (
                    0,
                    [
                        "PAGE_TABLE_PDP_BOOT Value",
                        f"0x{page_table_pdp_boot_value:x}"
                        if page_table_pdp_boot_value is not None
                        else "Not available",
                    ],
                ),
            ],
        )


class DoorsKernelInfo(plugins.PluginInterface):
    """Attempts to extract basic kernel information from a Doors OS memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of requirements needed for this plugin to execute."""
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the Doors OS kernel",
                architectures=["Intel64"],
                optional=True,
            )
        ]

    def _scan_kernel_info(
        self, layer: interfaces.layers.DataLayerInterface
    ) -> dict[str, str]:
        """Scans for information strings in the memory image."""
        result = {}

        # This is a placeholder. In a real implementation, you would scan for
        # key kernel strings or structures to extract information about the
        # Doors OS kernel version, build date, etc.

        # For now, we just add the identifier information
        identifier_offset = None
        signature = b"DoorsOsIdentifier"
        scanner = layer.scan(
            context=self.context,
            scanner=interfaces.layers.ScannerInterface(bytearray(signature)),
            sections=[(0, layer.maximum_address)],
        )
        for offset, _ in scanner:
            identifier_offset = offset
            break

        if identifier_offset is not None:
            result["Identifier Found"] = "Yes"
            result["Identifier Offset"] = f"0x{identifier_offset:x}"
            # Try to read surrounding data for more context
            try:
                surrounding_data = layer.read(
                    identifier_offset - 16, len(signature) + 32
                )
                readable_chars = "".join(
                    [chr(b) if 32 <= b <= 126 else "." for b in surrounding_data]
                )
                result["Surrounding Context"] = readable_chars
            except Exception as e:
                result["Error Reading Context"] = str(e)
        else:
            result["Identifier Found"] = "No"

        return result

    def run(self) -> renderers.TreeGrid:
        """Runs the Doors Kernel Info plugin."""

        # Use the _get_doors_layer helper method to find a suitable layer
        doors_layer = self._get_doors_layer()
        if doors_layer is not None:
            vollog.info(f"Using layer for analysis: {doors_layer.name}")

            # If it's not a DoorsKernelLayer, check if it contains the DoorsOsIdentifier
            if not isinstance(doors_layer, doors.DoorsKernelLayer):
                try:
                    identifier_found = False
                    for offset, _ in doors_layer.scan(
                        context=self.context,
                        scanner=interfaces.layers.ScannerInterface(
                            bytearray(b"DoorsOsIdentifier")
                        ),
                        sections=[(0, doors_layer.maximum_address)],
                    ):
                        vollog.info(
                            f"Found Doors OS identifier in {doors_layer.name} at offset 0x{offset:x}"
                        )
                        identifier_found = True
                        break

                    if not identifier_found:
                        vollog.info(
                            f"No Doors OS identifier found in {doors_layer.name}, but using it anyway"
                        )
                except Exception as e:
                    vollog.warning(f"Error scanning layer {doors_layer.name}: {e}")

        if doors_layer is None:
            vollog.error(
                "Could not find a Doors OS layer or identifier in the memory image"
            )
            return renderers.TreeGrid(
                [
                    ("Property", str),
                    ("Value", str),
                ],
                [
                    (
                        0,
                        [
                            "Error",
                            "Could not find a Doors OS layer or identifier in the memory image",
                        ],
                    ),
                ],
            )

        # Scan for kernel info
        kernel_info = self._scan_kernel_info(doors_layer)

        # Return data as a TreeGrid
        result = []
        for key, value in kernel_info.items():
            result.append((0, [key, str(value)]))

        if not result:
            result.append((0, ["Status", "No Doors OS kernel information found"]))

        return renderers.TreeGrid(
            [
                ("Property", str),
                ("Value", str),
            ],
            result,
        )
