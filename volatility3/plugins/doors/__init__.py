"""
Doors OS-specific plugins for Volatility 3
"""

from typing import List

from volatility3.framework import interfaces


def get_requirements() -> List[interfaces.configuration.RequirementInterface]:
    return []
