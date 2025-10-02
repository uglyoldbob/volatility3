# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
from typing import Callable, List, Optional, Tuple

from volatility3.framework import constants, interfaces, layers
from volatility3.framework.automagic import symbol_cache
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners

vollog = logging.getLogger(__name__)


class SymbolFinder(interfaces.automagic.AutomagicInterface):
    """Symbol loader based on signature strings."""

    priority = 40

    banner_config_key: str = "banner"
    operating_system: Optional[str] = None
    symbol_class: Optional[str] = None
    find_aslr: Optional[Callable] = None

    def __init__(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> None:
        super().__init__(context, config_path)
        self._requirements: List[
            Tuple[str, interfaces.configuration.RequirementInterface]
        ] = []
        self._banners: symbol_cache.BannersType = {}

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.VersionRequirement(
                name="SQLiteCache",
                component=symbol_cache.SqliteCache,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="multi_string_scanner",
                component=scanners.MultiStringScanner,
                version=(1, 0, 0),
            ),
        ]
    
    def analyze_requirement(self, req, indent=0):
        """Recursively analyze a requirement and its children"""
        prefix = "  " * indent
        
        vollog.info(f"{prefix}Requirement: {req.name}")
        vollog.info(f"{prefix}  Type: {type(req).__name__}")
        
        if hasattr(req, 'description'):
            vollog.info(f"{prefix}  Description: {req.description}")
        
        # Check for specific attributes
        if isinstance(req, requirements.SymbolTableRequirement):
            vollog.info(f"{prefix}  >>> SYMBOL TABLE REQUIREMENT <<<")
            if hasattr(req, 'architectures'):
                vollog.info(f"{prefix}  Architectures: {req.architectures}")
            if hasattr(req, 'os'):
                vollog.info(f"{prefix}  OS: {req.os}")
        
        elif isinstance(req, requirements.TranslationLayerRequirement):
            vollog.info(f"{prefix}  >>> TRANSLATION LAYER REQUIREMENT <<<")
            if hasattr(req, 'architectures'):
                vollog.info(f"{prefix}  Architectures: {req.architectures}")
        
        elif isinstance(req, requirements.MultiRequirement):
            vollog.info(f"{prefix}  >>> MULTI REQUIREMENT (Container) <<<")
            vollog.info(f"{prefix}  Contains {len(req.requirements)} sub-requirements:")
            
            # Recursively analyze sub-requirements
            for sub_req in req.requirements.values():
                vollog.info(f"{prefix}  ---")
                self.analyze_requirement(sub_req, indent + 1)
        
        # Show optional/required status
        if hasattr(req, 'optional'):
            vollog.info(f"{prefix}  Optional: {req.optional}")

    @property
    def banners(self) -> symbol_cache.BannersType:
        """Creates a cached copy of the results, but only it's been
        requested."""
        if not self._banners:
            vollog.info("Looking for banners definition")
            identifiers_path = os.path.join(
                constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME
            )
            vollog.info(f"Looking in {identifiers_path}")
            cache = symbol_cache.SqliteCache(identifiers_path)
            vollog.info(f"operating system {self.operating_system}")
            self._banners = cache.get_identifier_dictionary(
                operating_system=self.operating_system
            )
        return self._banners

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        """Searches for SymbolTableRequirements and attempt to populate
        them."""

        # Bomb out early if our details haven't been configured
        if self.symbol_class is None:
            return None
        
        vollog.debug(f"SymbolFinder called for requirement: {requirement.name}")
        vollog.debug(f"Config path: {config_path}")
        vollog.debug(f"Requirement type: {type(requirement)}")

        self.analyze_requirement(requirement)
        vollog.debug(f"Processing SymbolTableRequirement: {requirement.name}")

        self._requirements = self.find_requirements(
            context,
            config_path,
            requirement,
            (
                requirements.TranslationLayerRequirement,
                requirements.SymbolTableRequirement,
            ),
            shortcut=False,
        )

        for sub_path, requirement in self._requirements:
            parent_path = interfaces.configuration.parent_path(sub_path)

            if isinstance(
                requirement, requirements.SymbolTableRequirement
            ) and requirement.unsatisfied(context, parent_path):
                for tl_sub_path, tl_requirement in self._requirements:
                    tl_parent_path = interfaces.configuration.parent_path(tl_sub_path)
                    # Find the TranslationLayer sibling to the SymbolTableRequirement
                    if (
                        isinstance(
                            tl_requirement, requirements.TranslationLayerRequirement
                        )
                        and tl_parent_path == parent_path
                    ):
                        if context.config.get(tl_sub_path, None):
                            self._banner_scan(
                                context,
                                parent_path,
                                requirement,
                                context.config[tl_sub_path],
                                progress_callback,
                            )
                            break

    def _banner_scan(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.ConstructableRequirementInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        """Accepts a context, config_path and SymbolTableRequirement, with a
        constructed layer_name and scans the layer for banners."""

        vollog.info("Looking for banners for symbols")
        for a in self.banners:
            vollog.info(f"Looking for banners for symbols {a}")

        # Bomb out early if there's no banners
        if not self.banners:
            return None

        mss = scanners.MultiStringScanner([x for x in self.banners if x is not None])

        layer = context.layers[layer_name]

        # Check if the Stacker has already found what we're looking for
        if layer.config.get(self.banner_config_key, None):
            banner_list = [
                (0, bytes(layer.config[self.banner_config_key], "raw_unicode_escape"))
            ]  # type: Iterable[Any]
        else:
            # Swap to the physical layer for scanning
            # Only traverse down a layer if it's an intel layer
            # TODO: Fix this so it works for layers other than just Intel
            if isinstance(layer, layers.intel.Intel):
                layer = context.layers[layer.config["memory_layer"]]
            banner_list = layer.scan(
                context=context, scanner=mss, progress_callback=progress_callback
            )

        for _, banner in banner_list:
            vollog.debug(f"Identified banner: {banner!r}")
            symbols_file = self.banners.get(banner, None)
            if symbols_file:
                isf_path = symbols_file
                vollog.debug(f"Using symbol library: {symbols_file}")
                clazz = self.symbol_class
                # Set the discovered options
                path_join = interfaces.configuration.path_join
                context.config[path_join(config_path, requirement.name, "class")] = (
                    clazz
                )
                context.config[path_join(config_path, requirement.name, "isf_url")] = (
                    isf_path
                )
                context.config[
                    path_join(config_path, requirement.name, "symbol_mask")
                ] = layer.address_mask

                # Keep track of the existing table names so we know which ones were added
                old_table_names = set(context.symbol_space)

                # Construct the appropriate symbol table
                requirement.construct(context, config_path)

                new_table_names = set(context.symbol_space) - old_table_names
                # It should add only one symbol table. Ignore the next steps if it doesn't
                if len(new_table_names) == 1:
                    new_table_name = new_table_names.pop()
                    symbol_table = context.symbol_space[new_table_name]
                    producer_metadata = symbol_table.producer
                    vollog.debug(
                        f"producer_name: {producer_metadata.name}, producer_version: {producer_metadata.version_string}"
                    )

                    symbol_metadata = symbol_table.metadata
                    vollog.debug("Types:")
                    for types_source_dict in symbol_metadata.get_types_sources():
                        vollog.debug(f"\t{types_source_dict}")

                    vollog.debug("Symbols:")
                    for symbol_source_dict in symbol_metadata.get_symbols_sources():
                        vollog.debug(f"\t{symbol_source_dict}")

                break
            else:
                vollog.debug(f"Symbol library path not found for: {banner}")
                # print("Kernel", banner, hex(banner_offset))
        else:
            vollog.debug("No existing banners found")
            # TODO: Fallback to generic regex search?
