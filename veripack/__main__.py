"""Entrypoint for `python -m veripack`."""
import sys
from veripack.cli import main

if __name__ == "__main__":
    sys.exit(main())
