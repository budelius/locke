"""Environment detection.

Determines the current environment (development, staging, production)
by checking environment variables in priority order.
"""

import logging
import os

logger = logging.getLogger(__name__)

ENV_VAR_PRIORITY = [
    "LOCKE_ENV",
    "NODE_ENV",
    "PYTHON_ENV",
    "RAILS_ENV",
    "FLASK_ENV",
    "APP_ENV",
]

DEFAULT_ENVIRONMENT = "development"


def detect_environment() -> str:
    """Determine the current environment.

    Checks environment variables in priority order:
    LOCKE_ENV > NODE_ENV > PYTHON_ENV > RAILS_ENV > FLASK_ENV > APP_ENV > "development"

    Returns the value of the first set variable, or "development" if none are set.
    """
    for var_name in ENV_VAR_PRIORITY:
        value = os.environ.get(var_name)
        if value:
            logger.debug("Environment detected from %s: %s", var_name, value)
            return value.lower().strip()

    logger.debug("No environment variable found, defaulting to '%s'", DEFAULT_ENVIRONMENT)
    return DEFAULT_ENVIRONMENT


def is_production() -> bool:
    return detect_environment() == "production"


def is_development() -> bool:
    return detect_environment() == "development"
