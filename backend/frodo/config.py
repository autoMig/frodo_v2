"""Load application and logging configuration from environment variables."""
import logging
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root (parent of backend)
_env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(_env_path)


def setup_logging() -> None:
    """Configure logging from LOG_LEVEL environment variable."""
    import os
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
