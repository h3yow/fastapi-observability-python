"""Correlation-id resolution rules and concurrent context isolation."""
from __future__ import annotations

import threading

from app import context as ctx
from tests.conftest import check


def test_valid_incoming_id_is_reused_verbatim():
    rid, reused = ctx.resolve_incoming_id("Abc_123.xyz-9")
    check(reused is True and rid == "Abc_123.xyz-9",
          basis="符合 ^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$ 的入站标识必须原样沿用",
          input="Abc_123.xyz-9", request_id=rid, actual=reused)


def test_missing_or_empty_id_is_replaced_by_hex32():
    for raw in (None, "", "   "):
        rid, reused = ctx.resolve_incoming_id(raw)
        check(reused is False and len(rid) == 32 and all(c in "0123456789abcdef" for c in rid),
              basis="缺失/空白入站标识必须替换为 32 位小写十六进制新标识",
              input=raw, request_id=rid, actual=reused)


def test_malformed_id_is_replaced_not_echoed():
    bad_values = ["bad id!!", "1", "a b c d e f g", "<script>", "../etc"]
    for raw in bad_values:
        rid, reused = ctx.resolve_incoming_id(raw)
        check(reused is False and rid != raw and len(rid) == 32,
              basis="不符合字符/长度规则的入站标识必须被替换且不得回显原值",
              input=raw, request_id=rid, actual=reused)


def test_threads_get_isolated_context_values():
    seen: dict[int, str] = {}
    barrier = threading.Barrier(5)

    def worker(rid: str) -> None:
        token = ctx.set_request_id(rid)
        barrier.wait()  # maximize overlap while reading
        seen[rid] = "observed:" + ctx.get_request_id()
        ctx.reset_request_id(token)

    threads = [
        threading.Thread(target=worker, args=(f"rid-{i:02d}",)) for i in range(5)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for i in range(5):
        rid = f"rid-{i:02d}"
        check(seen.get(rid) == f"observed:{rid}",
              basis="不同线程并发持有 ContextVar 时不得串扰，各自只能读到自己绑定的值",
              input=f"5 并发线程 barrier 同时读取, 线程 {rid}",
              request_id=rid, actual=seen.get(rid))

    check(ctx.get_request_id() == "",
          basis="线程结束并 reset 后，调用方上下文不得被污染",
          input="join 后读取主线程 ContextVar",
          request_id="", actual=ctx.get_request_id())
