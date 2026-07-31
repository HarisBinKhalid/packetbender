"""Convenience launcher: run `python main.py` without installing the package."""

import sys

from sipedit.app import main

if __name__ == "__main__":
    sys.exit(main())
