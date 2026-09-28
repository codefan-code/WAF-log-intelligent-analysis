# -*- coding: utf-8 -*-
"""
WAF日志分析系统 - 一键运行脚本

支持两种部署方式, 都能正常运行:
  方式A (包结构):  waf_analyzer/core.py  +  run_analyzer.py
  方式B (单文件):  core.py  +  run_analyzer.py  (直接放同一目录)

用法:
  python run_analyzer.py                    # 使用默认 access.log
  python run_analyzer.py my.log             # 指定日志文件
  python run_analyzer.py --real             # 对接真实WAF API (非dry-run)
"""

import sys
import os

# 把脚本所在目录加入搜索路径, 保证无论在哪运行都能找到模块
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# 兼容两种部署方式:
#   1) 包结构: from waf_analyzer.core import run
#   2) 单文件: core.py 与 run_analyzer.py 同目录, 直接 import core
try:
    from waf_analyzer.core import run
except ImportError:
    import core  # 降级: 单文件部署
    run = core.run


def main():
    log_file = "access.log"
    dry_run = True

    args = sys.argv[1:]
    if args and not args[0].startswith("--"):
        log_file = args[0]

    if "--real" in args:
        dry_run = False

    # 日志文件也按脚本目录解析, 避免在其他目录运行时找不到
    if not os.path.isabs(log_file):
        log_file = os.path.join(_HERE, log_file)

    run(log_file=log_file, dry_run=dry_run)


if __name__ == "__main__":
    main()
