#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把内置规则中的 IOC 字符串编码为 base64，避免产物被本地文件扫描误判。

背景：主机安全产品自带大量恶意工具名/攻击命令片段，若以明文常量进入二进制，
容易被终端安全软件或组织级文件扫描当成恶意样本隔离，导致构建失败与分发受阻。
这与 internal/ioc 包的设计一致：结构保持可读，IOC 值编码存储、运行时解码。

用法：python scripts/encode_ioc.py [--check]
  --check  只统计将被编码的条件数量，不写文件
"""
import base64
import re
import sys

BACKSLASH = chr(92)
QUOTE = chr(34)

ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    BACKSLASH: BACKSLASH,
    QUOTE: QUOTE,
}


def unescape_go(literal: str) -> str:
    out = []
    i = 0
    while i < len(literal):
        ch = literal[i]
        if ch == BACKSLASH and i + 1 < len(literal):
            nxt = literal[i + 1]
            out.append(ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def b64(plain: str) -> str:
    return base64.b64encode(plain.encode("utf-8")).decode("ascii")


def main() -> int:
    target = "internal/rules/builtin.go"
    check_only = "--check" in sys.argv

    with open(target, encoding="utf-8") as f:
        src = f.read()

    # Go 双引号字符串：内部可有 \\" 与 \\ 转义
    cls = "[^" + QUOTE + BACKSLASH + BACKSLASH + "]"
    quoted = QUOTE + "(?:" + cls + "|" + BACKSLASH + ".)*" + QUOTE
    pattern = re.compile(
        r'c\("([^"]+)",\s*"([^"]+)",\s*(' + quoted + r'|\[\]any\{[^}]*\})\)'
    )

    stats = {"scalar": 0, "list": 0}
    already = 0

    def repl(m):
        field, op, third = m.group(1), m.group(2), m.group(3)
        if third.startswith("ioc."):
            already += 1
            return m.group(0)
        if third.startswith("[]any{"):
            inner = third[len("[]any{"):-1]
            items = re.findall(quoted, inner)
            # items 由带引号的模式匹配得到，需去掉首尾引号再反转义
            vals = [unescape_go(it[1:-1]) for it in items]
            stats["list"] += 1
            args = ", ".join(QUOTE + b64(v) + QUOTE for v in vals)
            return 'c("%s", "%s", ioc.SA(%s))' % (field, op, args)
        raw = unescape_go(third[1:-1])
        stats["scalar"] += 1
        return 'c("%s", "%s", ioc.S("%s"))' % (field, op, b64(raw))

    out = pattern.sub(repl, src)

    print("scalar conditions encoded: %d, list conditions encoded: %d, skipped: %d"
          % (stats["scalar"], stats["list"], already))

    if check_only:
        return 0
    if out != src:
        with open(target, "w", encoding="utf-8") as f:
            f.write(out)
        print("written:", target)
    else:
        print("no change")
    return 0


if __name__ == "__main__":
    sys.exit(main())
