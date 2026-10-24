"""Compatibility entry point; legacy unsafe interactive commands are not auto-run."""
from actscope.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
