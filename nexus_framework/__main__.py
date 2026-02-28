"""
Nexus Automation Framework - Entry Point

This module allows the package to be executed directly using 'python -m nexus_framework'.
"""

import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main())
