from __future__ import annotations

from typing import Protocol


class MailProvider(Protocol):
    """AuthFlow 所需的最小邮箱接口。

    使用 Protocol 而不是复制参考项目的邮箱池实现，令当前项目可以继续
    使用自己的 SQLite OutlookPool 和 OutlookMailClient。
    """

    kind: str
    pooled: bool
    exhausted: bool

    def create_mailbox(self) -> str: ...

    def wait_for_otp(
        self,
        email: str,
        timeout: int = 120,
        issued_after: float | None = None,
    ) -> str: ...

    def mark_dead(self, reason: str = "") -> None: ...
