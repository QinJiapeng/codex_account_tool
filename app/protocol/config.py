from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Config:
    """参考协议状态机需要的最小配置。

    目前状态机只直接读取出口代理。其它运行参数通过 ``env_overrides``
    传给单次实例，避免并发任务修改进程级环境变量。
    """

    proxy: str | None = None
