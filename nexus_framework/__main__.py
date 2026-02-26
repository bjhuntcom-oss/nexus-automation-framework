"""
BJHunt Alpha - Entry Point

This module allows the package to be executed directly using 'python -m bjhunt_alpha'.
"""

import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main())
