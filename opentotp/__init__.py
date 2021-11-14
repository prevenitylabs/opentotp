"""
OpenTOTP is yet another Time-based, One-Time Passwords (TOTPs) generator/verifier.

It generates and verifies OTPs based on shared secret and current UTC time.

Quick CLI usage:
    python3 -m opentotp --help

"""
from .opentotp import OpenTOTP

__version__ = "1.0.0"
__all__ = ["OpenTOTP", "__version__"]
