"""
Doors OS Banner Plugin
Scans memory for banner information without requiring symbol tables
"""

from typing import List
from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.layers import scanners


class Banners(interfaces.plugins.PluginInterface):
    """Scans for and retrieves Doors OS banner/version information from memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Define the requirements for this plugin."""
        # Accept both Doors64 and Intel architectures
        # This allows the plugin to work with or without DoorsKernelLayer
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer to scan for banners",
                architectures=["Doors64"]
            )
        ]
    
    def __init__(self, *args, **kwargs):
        """Initialize and log for debugging."""
        super().__init__(*args, **kwargs)
        import logging
        vollog = logging.getLogger(__name__)
        vollog.info(f"Banners plugin initialized")
        vollog.info(f"Available layers: {list(self.context.layers.keys())}")
        vollog.info(f"Config primary: {self.config.get('primary', 'NOT SET')}")

    def _scan_for_banners(self, layer):
        """
        Scan memory for Doors OS banner patterns.
        """
        # Define patterns that match your Doors OS banners
        patterns = [
            rb'doors version \d+\.\d+\.\d+[^\x00]{0,200}',
        ]
        
        found_banners = []
        
        # Scan first 128MB for performance
        max_scan = min(layer.maximum_address, 128 * 1024 * 1024)
        
        for pattern in patterns:
            scanner = scanners.RegExScanner(pattern)
            
            try:
                for offset in layer.scan(
                    context=self.context,
                    scanner=scanner,
                    sections=[(0, max_scan)]
                ):
                    try:
                        # Read up to 512 bytes to get full banner
                        data = layer.read(offset, 512)
                        
                        # Extract null-terminated string
                        banner_bytes = data.split(b'\x00')[0]
                        
                        # Decode to string
                        try:
                            banner_str = banner_bytes.decode('utf-8').strip()
                        except UnicodeDecodeError:
                            banner_str = banner_bytes.decode('latin-1', errors='replace').strip()
                        
                        # Only add if it looks valid
                        if banner_str and len(banner_str) > 5:
                            found_banners.append((offset, banner_str))
                            
                            # Limit results
                            if len(found_banners) >= 5:
                                return found_banners
                                
                    except Exception as e:
                        continue
                        
            except exceptions.LayerException as e:
                continue
        
        return found_banners

    def _generator(self):
        """Generate banner information."""
        layer = self.context.layers[self.config["primary"]]
        
        # Scan for banners
        results = self._scan_for_banners(layer)
        
        if results:
            for offset, banner in results:
                yield (0, (
                    format_hints.Hex(offset),
                    banner
                ))
        else:
            # No banner found
            yield (0, (
                format_hints.Hex(0),
                "No Doors OS banner detected in memory"
            ))

    def run(self):
        """Execute the plugin and return results."""
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Banner", str)
            ],
            self._generator()
        )