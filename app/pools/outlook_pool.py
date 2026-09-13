from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class OutlookAccount:
    """The mailbox credentials required by :class:`OutlookMailClient`.

    This intentionally contains no pool or persistence behavior.  The new
    project receives exactly one account from the four-field import format.
    """

    email: str
    password: str
    client_id: str
    refresh_token: str

