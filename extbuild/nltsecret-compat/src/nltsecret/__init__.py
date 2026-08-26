"""Compatibility namespace for the renamed funsecret package."""

import warnings

warnings.warn("nltsecret was renamed to funsecret", DeprecationWarning, stacklevel=2)

from funsecret import *  # noqa: E402,F401,F403
from funsecret import __all__, __path__  # noqa: E402,F401
