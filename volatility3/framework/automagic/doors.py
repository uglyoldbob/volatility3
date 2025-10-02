# Copyright 2023 Volatility Foundation (follow your project's licensing)
# Doors OS automagic: identifier, stacker and symbol finder

import logging
from typing import List, Optional, Tuple

from volatility3.framework import interfaces, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.automagic import symbol_finder
from volatility3.framework.layers import doors
from volatility3.framework.layers import scanners
from volatility3.framework import interfaces as fw_interfaces
from volatility3.framework import symbols as fw_symbols

vollog = logging.getLogger(__name__)


class DoorsIdentifier(interfaces.automagic.AutomagicInterface):
    """Automagic to identify Doors OS memory images via signature or banner.

    - Identifies by embedded signature b"DoorsOsIdentifier"
    - Also accepts banners like "doors version a.b.c" (case-insensitive)
    - Does not run for windows/linux/macos
    """

    # bytes to look for in physical memory for a quick signature match
    DOORS_SIGNATURE = b"DoorsOsIdentifier"

    priority = 30
    # Ensure this automagic is not used for the other OS families
    exclusion_list = ["windows", "linux", "mac"]

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        # Only attempt to satisfy TranslationLayerRequirements (or nested MultiRequirements)
        if not self._check_valid_requirement(requirement):
            return

        # If requirement already satisfied, nothing to do
        if not requirement.unsatisfied(context, config_path):
            return

        # Find candidate base layers (physical/raw-like layers)
        base_layers = self._find_base_layers(context)

        for base_name in base_layers:
            # Skip if we've already stacked Doors against this base
            if self._layer_already_stacked(context, base_name):
                continue

            # Try quick signature scan
            sig_offset = self._scan_for_signature(context, base_name)
            if sig_offset is None:
                # If signature not found, try banner scan
                sig_offset = self._scan_for_banner(context, base_name)

            if sig_offset is None:
                continue

            # Build Doors kernel layer
            doors_layer = self._build_doors_layer(context, base_name, sig_offset, progress_callback)
            if doors_layer is None:
                continue

            # If this automagic is being asked to set a TranslationLayerRequirement,
            # set it to the newly created Doors layer name in config.
            if isinstance(requirement, requirements.TranslationLayerRequirement):
                req_path = interfaces.configuration.path_join(config_path, requirement.name)
                context.config[req_path] = doors_layer.name
                vollog.info("DoorsIdentifier: set %s => %s", req_path, doors_layer.name)

            # Stop once requirement satisfied
            if not requirement.unsatisfied(context, config_path):
                return

    def _check_valid_requirement(self, requirement: interfaces.configuration.RequirementInterface) -> bool:
        if isinstance(requirement, requirements.TranslationLayerRequirement):
            return True
        if isinstance(requirement, requirements.MultiRequirement):
            for r in requirement.requirements:
                if self._check_valid_requirement(r):
                    return True
        return False

    def _find_base_layers(self, context: interfaces.context.ContextInterface) -> List[str]:
        candidates = []
        for lname, layer in context.layers.items():
            # Accept raw/physical-like layers (have read and maximum_address) but don't stack on existing DoorsKernelLayer
            if not isinstance(layer, doors.DoorsKernelLayer) and hasattr(layer, "read") and hasattr(layer, "maximum_address"):
                candidates.append(lname)
        return candidates

    def _layer_already_stacked(self, context: interfaces.context.ContextInterface, base_name: str) -> bool:
        for layer in context.layers.values():
            if isinstance(layer, doors.DoorsKernelLayer):
                if layer.config.get("memory_layer") == base_name:
                    return True
        return False

    def _scan_for_signature(self, context: interfaces.context.ContextInterface, layer_name: str) -> Optional[int]:
        layer = context.layers[layer_name]
        vollog.debug("DoorsIdentifier: scanning %s for signature", layer_name)

        try:
            scanner = scanners.MultiStringScanner([self.DOORS_SIGNATURE])
            # scan entire layer but be mindful of huge layers; the engine will handle iterating efficiently
            for offset, _ in layer.scan(context=context, scanner=scanner, sections=[(0, layer.maximum_address)]):
                vollog.info("DoorsIdentifier: found signature at 0x%X in %s", offset, layer_name)
                return offset
        except exceptions.LayerException as le:
            vollog.debug("DoorsIdentifier: layer scanning exception: %s", le)
        return None

    def _scan_for_banner(self, context: interfaces.context.ContextInterface, layer_name: str) -> Optional[int]:
        layer = context.layers[layer_name]
        vollog.debug("DoorsIdentifier: scanning %s for banner patterns", layer_name)

        # Banner patterns: case-insensitive "doors version x.y.z"
        # Use a short initial scan window (first 128MB) to avoid long scans.
        try:
            max_offset = min(layer.maximum_address, 128 * 1024 * 1024)
        except Exception:
            max_offset = 128 * 1024 * 1024

        patterns = [rb'doors version \d+\.\d+\.\d+']  # regex scanner expects bytes

        for pat in patterns:
            scanner = scanners.RegExScanner(pat, ignorecase=True)
            try:
                for offset in layer.scan(context=context, scanner=scanner, sections=[(0, max_offset)]):
                    # scanner yields offsets (or (offset,) depending on implementation); normalize
                    if isinstance(offset, tuple):
                        found_offset = offset[0]
                    else:
                        found_offset = offset
                    vollog.info("DoorsIdentifier: found banner pattern at 0x%X in %s", found_offset, layer_name)
                    return found_offset
            except exceptions.LayerException as le:
                vollog.debug("DoorsIdentifier: regex scan error: %s", le)
                continue
        return None

    def _build_doors_layer(self, context: interfaces.context.ContextInterface, base_name: str, base_offset: int, progress_callback: constants.ProgressCallback = None) -> Optional[interfaces.layers.DataLayerInterface]:
        if progress_callback:
            progress_callback(10, "Preparing Doors kernel layer")

        new_layer_name = context.layers.free_layer_name("DoorsKernelLayer")
        cfg_path = interfaces.configuration.path_join("DoorsKernelLayer", new_layer_name)

        # Basic DoorsKernelLayer configuration - dtb=0 for flat mapped kernel (adjust if Doors uses a real DTB)
        context.config[interfaces.configuration.path_join(cfg_path, "memory_layer")] = base_name
        context.config[interfaces.configuration.path_join(cfg_path, "base_offset")] = base_offset
        context.config[interfaces.configuration.path_join(cfg_path, "dtb")] = 0

        try:
            doors_layer = doors.DoorsKernelLayer(context, cfg_path, new_layer_name)
            context.add_layer(doors_layer)
            vollog.info("DoorsIdentifier: built DoorsKernelLayer %s (base %s @ 0x%X)", new_layer_name, base_name, base_offset)

            if progress_callback:
                progress_callback(100, f"Built Doors kernel layer: {new_layer_name}")

            return doors_layer
        except Exception as e:
            vollog.error("DoorsIdentifier: failed to construct DoorsKernelLayer: %s", e)
            return None


class DoorsStacker(interfaces.automagic.StackerLayerInterface):
    """Optional stacker: identifies Doors OS and (if needed) stacks intel layers.
    This minimal implementation acts mainly as a marker (no additional stacking here)."""

    stack_order = 35
    exclusion_list = ["windows", "linux", "mac"]

    @classmethod
    def stack(cls, context: interfaces.context.ContextInterface, layer_name: str, progress_callback: constants.ProgressCallback = None) -> Optional[interfaces.layers.DataLayerInterface]:
        # If a DoorsKernelLayer already exists for this base, return it
        for layer in context.layers.values():
            if isinstance(layer, doors.DoorsKernelLayer) and layer.config.get("memory_layer") == layer_name:
                return layer

        # Otherwise, do not stack additional layers here; let DoorsIdentifier handle construction.
        return None


class DoorsSymbolFinder(symbol_finder.SymbolFinder):
    """SymbolFinder automagic specialized for Doors OS.

    It will look for a banner like 'doors version a.b.c' and set operating_system='doors'
    so the SymbolFinder machinery can attach the correct symbol table.
    """

    priority = 40
    operating_system = "doors"
    banner_config_key = "automagic.doors.banner"  # configuration key if you want to expose it

    # Banner regex used by our banner extraction
    BANNER_REGEX = rb'doors version \d+\.\d+\.\d+'  # lower-case; we'll scan case-insensitively

    @classmethod
    def banner_config(cls, context: interfaces.context.ContextInterface, layer_name: str, progress_callback: constants.ProgressCallback = None) -> Tuple[str, Optional[str]]:
        layer = context.layers[layer_name]

        try:
            max_offset = min(layer.maximum_address, 128 * 1024 * 1024)
        except Exception:
            max_offset = 128 * 1024 * 1024

        scanner = scanners.RegExScanner(cls.BANNER_REGEX, ignorecase=True)
        try:
            for match in layer.scan(context=context, scanner=scanner, sections=[(0, max_offset)]):
                # match may be an integer offset or a tuple; normalize
                if isinstance(match, tuple):
                    offset = match[0]
                else:
                    offset = match

                raw = layer.read(offset, 256)
                banner_bytes = raw.split(b'\x00', 1)[0]
                try:
                    banner = banner_bytes.decode("utf-8", errors="ignore")
                    return (cls.operating_system, banner)
                except Exception:
                    continue
        except exceptions.LayerException:
            pass

        return (cls.operating_system, None)
