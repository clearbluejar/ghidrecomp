__version__ = '0.5.4'
__author__ = 'clearbluejar'

# Expose API
from .decompile import decompile
from .parser import get_parser

__all__ = ["get_parser", "decompile"]
