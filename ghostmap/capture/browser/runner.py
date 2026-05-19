"""Entry point standalone para `python -m browser.runner`."""
import asyncio
from .instrumenter import main

if __name__ == "__main__":
    asyncio.run(main())
