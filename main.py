"""向后兼容入口：等价于 ``uvicorn app.main:app``。

新代码请从 ``app.main`` 导入；``app.create_app()`` 可用于测试构造隔离实例。
"""

from app.main import app  # noqa: F401

__all__ = ["app"]
