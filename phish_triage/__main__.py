"""Allow `python -m phish_triage` to start the command-line tool."""
import sys

from .cli import main

sys.exit(main())
