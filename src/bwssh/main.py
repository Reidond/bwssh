"""Legacy entry point — redirects to cli.main."""

import logging

from bwssh.cli import main

__all__ = ["main"]

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    main()
