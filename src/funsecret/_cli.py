"""funsecret CLI 入口：把参数直接转发给 Rust 原生 ``funsecret::run``。"""

import sys

from ._funsecret import cli_main


def main() -> None:
    raise SystemExit(cli_main(sys.argv))
