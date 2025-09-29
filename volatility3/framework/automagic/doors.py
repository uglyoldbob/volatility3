# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
from typing import Any, List, Optional, Tuple, Type

from volatility3.framework import constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import doors
from volatility3.framework.automagic import symbol_finder

vollog = logging.getLogger(__name__)


class DoorsIdentifier(interfaces.automagic.AutomagicInterface):
    """Automagic class to identify Doors OS memory images based on signature pattern.

    This automagic identifies memory dumps from the Doors OS kernel by scanning for
    the "DoorsOsIdentifier" string, which is embedded in the kernel.
    """

    # The string that identifies a Doors OS kernel
    DOORS_SIGNATURE = b"DoorsOsIdentifier"

    # Set the priority lower than the stacker automagic but higher than the other OS automagics
    priority = 30

    # This automagic is specific to Doors OS and shouldn't be used for Linux/Windows/Mac
    exclusion_list = ["linux", "windows", "mac"]

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        """Identifies and adds Doors OS layers to the context.

        Args:
            context: The context to configure
            config_path: Configuration path for any settings required
            requirement: The requirement that is currently being fulfilled
            progress_callback: A callback function to indicate progress during the run
        """
        if requirement.unsatisfied(context, config_path):
            # Check if we're trying to fulfill TranslationLayerRequirement
            if not self._check_valid_requirement(requirement):
                return

            # Find potential base layers to stack on top of
            base_layers = self._find_base_layers(context)
            for layer_name in base_layers:
                # If we've already stacked a Doors OS layer on this base, skip it
                if self._layer_already_stacked(context, layer_name):
                    continue

                # Try to identify if this is a Doors OS memory image
                header_offset = self._scan_for_doors_signature(context, layer_name)
                if header_offset is not None:
                    # We found a Doors OS signature - create the layer
                    doors_layer = self._build_doors_layer(
                        context, layer_name, header_offset, progress_callback
                    )

                    # If we successfully built a layer, check if we need to fulfill the requirement
                    if doors_layer and isinstance(
                        requirement, requirements.TranslationLayerRequirement
                    ):
                        vollog.info(
                            f"Setting requirement {requirement.name} to layer {doors_layer.name}"
                        )
                        config_path = interfaces.configuration.path_join(
                            config_path, requirement.name
                        )
                        context.config[config_path] = doors_layer.name

                        # Special handling for DoorsInfo plugin
                        if "DoorsInfo.primary" in config_path:
                            # Also set the alternate path for plugins.doors.info.DoorsInfo.primary
                            alternate_path = config_path.replace(
                                "DoorsInfo", "doors.info.DoorsInfo"
                            )
                            context.config[alternate_path] = doors_layer.name
                            vollog.info(
                                f"Also set {alternate_path} to {doors_layer.name}"
                            )

                    # If we successfully created a layer, check if we've satisfied the requirement
                    if doors_layer and isinstance(
                        requirement, requirements.TranslationLayerRequirement
                    ):
                        vollog.info(
                            f"Checking if {doors_layer.name} satisfies {requirement.name} requirement"
                        )
                        if not requirement.unsatisfied(context, config_path):
                            vollog.info(
                                f"Requirement {requirement.name} satisfied by {doors_layer.name}"
                            )

    def _check_valid_requirement(
        self, requirement: interfaces.configuration.RequirementInterface
    ) -> bool:
        """Checks if the requirement can potentially be satisfied by this automagic.

        Args:
            requirement: The requirement to check against

        Returns:
            True if the requirement can be fulfilled by a TranslationLayer, False otherwise
        """
        if isinstance(requirement, requirements.TranslationLayerRequirement):
            return True
        elif isinstance(requirement, requirements.MultiRequirement):
            for req in requirement.requirements:
                if self._check_valid_requirement(req):
                    return True
        return False

    def _find_base_layers(
        self, context: interfaces.context.ContextInterface
    ) -> List[str]:
        """Returns a list of layer names that could support a Doors OS layer.

        Args:
            context: The context to find base layers within

        Returns:
            A list of layer names that could support a Doors OS layer
        """
        base_layers = []
        for layer_name in context.layers:
            if self._is_valid_base_layer(context.layers[layer_name]):
                base_layers.append(layer_name)
        return base_layers

    def _is_valid_base_layer(self, layer: interfaces.layers.DataLayerInterface) -> bool:
        """Checks whether the layer is a suitable base layer for a Doors OS layer.

        Args:
            layer: The layer to check

        Returns:
            True if the layer is a valid base layer, False otherwise
        """
        # Doors OS can be stacked on physical/raw memory layers
        # We don't want to stack on layers that already have meaning
        return (
            not isinstance(layer, doors.DoorsKernelLayer)
            and hasattr(layer, "read")
            and hasattr(layer, "maximum_address")
        )

    def _layer_already_stacked(
        self, context: interfaces.context.ContextInterface, layer_name: str
    ) -> bool:
        """Checks if we've already stacked a Doors OS layer on this base layer.

        Args:
            context: The context containing the layers
            layer_name: The name of the base layer to check

        Returns:
            True if a Doors OS layer has already been stacked on the named layer
        """
        for layer in context.layers.values():
            if isinstance(layer, doors.DoorsKernelLayer):
                if layer.config.get("memory_layer", None) == layer_name:
                    return True
        return False

    def _scan_for_doors_signature(
        self, context: interfaces.context.ContextInterface, layer_name: str
    ) -> Optional[int]:
        """Scans the layer for the Doors OS signature.

        Args:
            context: The context to examine
            layer_name: The name of the layer to scan

        Returns:
            The offset where the signature was found, or None if not found
        """
        layer = context.layers[layer_name]
        vollog.info(f"Scanning for Doors OS signature in layer {layer_name}")

        # Create a scanner for the Doors OS signature
        scanner = layer.scan(
            context=context,
            scanner=interfaces.layers.ScannerInterface(bytearray(self.DOORS_SIGNATURE)),
            sections=[(0, layer.maximum_address)],
        )

        # Look for the first occurrence of the signature
        for offset, _ in scanner:
            vollog.info(f"Found Doors OS signature at offset {offset:#x}")
            return offset

        vollog.info("No Doors OS signature found")
        return None

    def _build_doors_layer(
        self,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        offset: int,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        """Constructs a Doors OS layer on top of the specified layer at the specified offset.

        Args:
            context: The context in which to construct the layer
            layer_name: The name of the base layer
            offset: The offset at which the Doors OS signature was found
            progress_callback: A callback to indicate progress during the process

        Returns:
            The constructed Doors OS layer, or None if unsuccessful
        """
        if progress_callback is not None:
            progress_callback(50, f"Building Doors OS layer on {layer_name}")

        # Create a new configuration path
        new_layer_name = context.layers.free_layer_name("DoorsKernelLayer")
        config_path = interfaces.configuration.path_join(
            "DoorsKernelLayer", new_layer_name
        )

        # Set the configuration
        context.config[
            interfaces.configuration.path_join(config_path, "memory_layer")
        ] = layer_name
        context.config[
            interfaces.configuration.path_join(config_path, "base_offset")
        ] = offset
        context.config[interfaces.configuration.path_join(config_path, "dtb")] = (
            0  # Flat mapped kernel
        )

        try:
            # Create the Doors OS layer
            doors_layer = doors.DoorsKernelLayer(context, config_path, new_layer_name)

            # Add the layer to the context
            context.add_layer(doors_layer)
            vollog.info(f"Built Doors OS layer: {new_layer_name}")

            # Check if the requirement is a TranslationLayerRequirement
            if isinstance(requirement, requirements.TranslationLayerRequirement):
                # Fulfill the requirement with the created layer
                requirement_path = interfaces.configuration.path_join(
                    config_path, requirement.name
                )
                context.config[requirement_path] = new_layer_name
                vollog.info(
                    f"Fulfilled requirement {requirement.name} with layer {new_layer_name}"
                )

            if progress_callback is not None:
                progress_callback(100, f"Built Doors OS layer: {new_layer_name}")

            return doors_layer
        except Exception as e:
            vollog.error(f"Failed to build Doors OS layer: {e}")
            return None


class DoorsSymbolFinder(symbol_finder.SymbolFinder):
    """Doors OS symbol loader that automatically loads symbols from symbol directories."""

    banner_config_key = "doors_banner"
    operating_system = "doors"
    symbol_class = "volatility3.framework.symbols.intermed.IntermediateSymbolTable"
    exclusion_list = ["windows", "mac"]

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        """Automatically load Doors OS symbols when a Doors layer is detected."""

        vollog.debug(
            f"DoorsSymbolFinder called with requirement type: {type(requirement).__name__}"
        )

        # Find SymbolTableRequirements within the requirement
        symbol_requirements = self._find_symbol_requirements(requirement)

        if not symbol_requirements:
            vollog.debug("No SymbolTableRequirements found, skipping")
            return

        # Look for any Doors OS layers in the context
        doors_layers = [
            layer
            for layer in context.layers.values()
            if isinstance(layer, doors.DoorsKernelLayer)
        ]

        vollog.debug(f"Found {len(doors_layers)} Doors OS layers")

        if not doors_layers:
            vollog.debug("No Doors OS layers found, skipping symbol loading")
            return

        vollog.info("Found Doors OS layer, attempting to load symbols automatically")

        # Try to find and load symbols.json from symbol directories
        symbol_paths = []

        # Get symbol paths from volatility3.symbols.__path__ which includes command line --symbol-dirs
        try:
            import volatility3.symbols

            symbol_paths.extend(volatility3.symbols.__path__)
        except (ImportError, AttributeError):
            # Fallback to constants if volatility3.symbols is not available
            symbol_paths.extend(getattr(constants, "SYMBOL_BASEPATHS", []))

        for symbol_dir in symbol_paths:
            if not os.path.isdir(symbol_dir):
                continue

            symbols_file = os.path.join(symbol_dir, "symbols.json")
            if os.path.exists(symbols_file):
                vollog.info(f"Loading Doors OS symbols from: {symbols_file}")

                # Try to satisfy all symbol requirements
                for sub_config_path, symbol_requirement in symbol_requirements:
                    if symbol_requirement.unsatisfied(context, sub_config_path):
                        try:
                            # Set up the symbol table configuration
                            table_name = context.symbol_space.free_table_name(
                                "doors_kernel"
                            )
                            path_join = interfaces.configuration.path_join

                            context.config[
                                path_join(
                                    sub_config_path, symbol_requirement.name, "class"
                                )
                            ] = self.symbol_class
                            context.config[
                                path_join(
                                    sub_config_path, symbol_requirement.name, "isf_url"
                                )
                            ] = f"file://{os.path.abspath(symbols_file)}"

                            # Construct the symbol table
                            symbol_requirement.construct(context, sub_config_path)
                            vollog.info(
                                f"Successfully loaded Doors OS symbol table: {table_name}"
                            )

                        except Exception as e:
                            vollog.warning(
                                f"Failed to load symbols from {symbols_file}: {e}"
                            )
                            continue
                return

        vollog.warning("No Doors OS symbols found in symbol directories")

    def _find_symbol_requirements(
        self, requirement: interfaces.configuration.RequirementInterface
    ) -> list:
        """Find all SymbolTableRequirements within a requirement structure."""
        symbol_requirements = []

        if isinstance(requirement, requirements.SymbolTableRequirement):
            symbol_requirements.append(("", requirement))
        elif isinstance(requirement, requirements.MultiRequirement):
            for sub_path, sub_req in self.find_requirements(
                None,
                "",
                requirement,
                requirements.SymbolTableRequirement,
                shortcut=False,
            ):
                symbol_requirements.append((sub_path, sub_req))

        return symbol_requirements
