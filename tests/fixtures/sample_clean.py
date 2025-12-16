"""Sample file with clean, well-written code for testing."""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def get_user(username: str) -> Optional[dict]:
    """Fetch a user by username using parameterized queries."""
    query = "SELECT * FROM users WHERE username = %s"
    result = db.execute(query, (username,))
    return result.fetchone()


def render_page(user_input: str) -> str:
    """Render a page with properly escaped user input."""
    from html import escape
    safe_input = escape(user_input)
    return f"<html><body>{safe_input}</body></html>"


def divide(a: float, b: float) -> Optional[float]:
    """Safe division with zero check."""
    if b == 0:
        logger.warning("Division by zero attempted")
        return None
    return a / b


def get_items(items: list) -> Optional[str]:
    """Safe access with None and empty check."""
    if not items:
        return None
    first = items[0]
    return first.name if first is not None else None


def process_list(items: list) -> list:
    """Efficient deduplication using a set."""
    return list(set(items))
