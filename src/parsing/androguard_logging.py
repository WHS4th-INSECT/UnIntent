"""Logging controls for the Androguard dependency."""

from __future__ import annotations


def disable_androguard_logs() -> None:
    """Disable noisy Androguard Loguru output without affecting UnIntent logs."""
    try:
        from loguru import logger
    except ImportError:
        return
    logger.disable("androguard")
