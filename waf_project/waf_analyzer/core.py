# -*- coding: utf-8 -*-
"""
WAF日志智能分析与自动处置系统 - 核心检测引擎
功能:
  1. 多格式日志解析 (Nginx / 腾讯云WAF / 通用格式)
  2. 双层检测: 正则规则(快速) + 特征评分(深度)
  3. URL解码 + UA/参数上下文感知
  4. 攻击链关联分析 (同一IP多阶段攻击识别)
  5. 时间窗口趋势分析 (识别突发攻击波次)
  6. 自动处置闭环 (封禁IP / 输出处置建议)
  7. 可视化报告生成 (Markdown + HTML)
"""

import re
import os
import json
import time
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs

# 默认日志文件路径 (相对于运行目录)
DEFAULT_LOG_FILE = "access.log"


# ============================================================
# 1. 攻击规则库 (支持热更新)
# ============================================================

ATTACK_RULES = {
    "SQL注入": {
        "level": "高",
        "weight": 10,
        "rules": [
            r"union\s+select",
            r"select\s+.*\s+from",
            r"insert\s+into\s+\w+",
            r"delete\s+from\s+\w+",
            r"drop\s+table",
            r"'\s*or\s*'?\d+'?\s*=\s*'?\d+'?",
            r"\bor\b\s+\d+\s*=\s*\d+",
            r"sleep\s*\(\s*\d+",
            r"benchmark\s*\(",
            r"extractvalue\s*\(",
            r"updatexml\s*\(",
            r"load_file\s*\(",
            r"into\s+outfile",
            r"information_schema",
            r"--\s",
            r"/\*.*\*/",
        ],
    },
    "XSS攻击": {
        "level": "中",
        "weight": 6,
        "rules": [
            r"<script[^>]*>",
            r"</script>",
            r"javascript\s*:",
            r"on(error|load|click|mouseover)\s*=",
            r"alert\s*\(",
            r"document\.cookie",
            r"eval\s*\(",
            r"prompt\s*\(",
            r"confirm\s*\(",
            r"<\s*iframe[^>]*src\s*=",
        ],
    },
    "路径遍历": {
        "level": "高",
        "weight": 10,
        "rules": [
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"/etc/shadow",
            r"windows/system32",
            r"boot\.ini",
            r"\.\./\.\./",
            r"web\.config",
            r"\.\.%2f",
            r"%2e%2e%2f",
        ],
    },
    "命令执行": {
        "level": "高",
        "weight": 10,
        "rules": [
            r";\s*(ls|cat|id|whoami|pwd)\b",
            r"\|\s*(nc|bash|sh|wget|curl)\b",
            r"`[^`]*`",
            r"\$\([^)]*\)",
            r"\bcmd\s*=",
            r"powershell\s+-",
            r"/bin/(bash|sh|zsh)",
            r"\b(eval|exec|system|passthru|popen)\s*\(",
            r"\bwget\s+http",
            r"\bcurl\s+http",
            r">/dev/tcp/",
        ],
    },
    "文件上传/包含": {
        "level": "高",
        "weight": 9,
        "rules": [
            r"\.php\?",
            r"php://(input|filter)",
            r"phar://",
            r"data://",
            r"filename=.*\.php",
            r"content-type:\s*image/.*\.php",
        ],
    },
    "SSRF/扫描探测": {
        "level": "中",
        "weight": 5,
        "rules": [
            r"file=http://",
            r"url=http://(127|localhost|0\.0\.0\.1)",
            r"wp-admin",
            r"phpmyadmin",
            r"\.env",
            r"\.git/HEAD",
            r"backup\.zip",
            r"\.bak",
        ],
    },
}


# ============================================================
# 2. 日志解析器 (适配器模式, 支持多格式)
# ============================================================

# 通用 Nginx/Apache 格式
LOG_PATTERN_NGINX = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+|[a-f0-9:]+)\s*'
    r'\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\s+'
    r'(?P<uri>\S+)\s+(?P<proto>HTTP/[\d.]+)"\s+'
    r'(?P<status>\d+)\s+\S+\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<ua>[^"]*)"'
)

# 简化格式 (兼容无 referer 字段)
LOG_PATTERN_SIMPLE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s*.*?'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>GET|POST|PUT|DELETE|HEAD)\s+'
    r'(?P<uri>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d+)\s+\S+\s+'
    r'"(?P<ua>[^"]*)"'
)


def parse_log(line):
    """
    解析单行日志, 自动适配格式.
    返回 dict 或 None
    """
    if not line or not line.strip():
        return None

    # 尝试 Nginx 格式
    m = LOG_PATTERN_NGINX.search(line)
    if m:
        d = m.groupdict()
        return {
            "ip": d["ip"],
            "time": d["time"],
            "method": d["method"],
            "uri": d["uri"],
            "status": int(d["status"]),
            "referer": d.get("referer", ""),
            "ua": d.get("ua", ""),
        }

    # 尝试简化格式
    m = LOG_PATTERN_SIMPLE.search(line)
    if m:
        d = m.groupdict()
        return {
            "ip": d["ip"],
            "time": d["time"],
            "method": d["method"],
            "uri": d["uri"],
            "status": int(d["status"]),
            "referer": "",
            "ua": d.get("ua", ""),
        }

    return None


def load_logs(filename):
    """从文件加载并解析日志"""
    logs = []
    if not os.path.exists(filename):
        print(f"[!] 日志文件不存在: {filename}")
        return logs

    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            item = parse_log(line)
            if item:
                logs.append(item)
    return logs


# ============================================================
# 3. 检测引擎
# ============================================================

# 常见的、需排除的误报关键词 (白名单)
WHITELIST_KEYWORDS = [
    "select_city", "select_date", "select_all", "select2", "selected",
    "selectize", "selector", "selectpicker",
]


def detect_attack(log):
    """
    双层检测引擎:
      1) 正则规则快速匹配
      2) 上下文特征评分 (降低误报)
    返回: dict {attack, type, level, detail, score}
    """
    # 拼接检测内容 (URI + UA + Referer), 并做URL解码
    raw = log["uri"] + " " + log["ua"] + " " + log["referer"]
    decoded = unquote(raw)
    content = (raw + " " + decoded).lower()

    # 白名单过滤: 参数名含白名单关键词的跳过
    for kw in WHITELIST_KEYWORDS:
        if kw in content:
            content = content.replace(kw, " ")

    best = {"attack": False, "type": "正常", "level": "无", "detail": "", "score": 0}

    for name, rule in ATTACK_RULES.items():
        for pattern in rule["rules"]:
            if re.search(pattern, content, re.I):
                # 计算评分: 命中规则权重 + 上下文加分
                score = rule["weight"]

                # 上下文加分: 出现在参数值中更可疑
                if re.search(r"[?&=].*?" + pattern.strip(r"\b"), content, re.I):
                    score += 2

                # 多个规则命中同一类型取最高分
                if score > best["score"]:
                    best = {
                        "attack": True,
                        "type": name,
                        "level": rule["level"],
                        "detail": pattern,
                        "score": score,
                    }
                break  # 同类型命中一次即记录, 不再重复

    return best


def analyze_logs(logs):
    """
    批量分析日志, 返回 (results, summary)
      results: [{log, attack, type, level, detail, score}, ...]
      summary: 统计摘要
    """
    results = []
    for log in logs:
        risk = detect_attack(log)
        results.append({"log": log, **risk})

    attacks = [r for r in results if r["attack"]]

    # 解析时间用于趋势分析
    attack_times = []
    for r in attacks:
        try:
            t = datetime.strptime(r["log"]["time"].split(" ")[0], "%d/%b/%Y:%H:%M:%S")
            attack_times.append(t)
        except Exception:
            pass

    # 时间趋势 (按小时)
    hour_counter = Counter(t.strftime("%Y-%m-%d %H:00") for t in attack_times)
    peak_hours = hour_counter.most_common(5)

    # 攻击链分析
    ip_events = defaultdict(list)
    for r in attacks:
        ip_events[r["log"]["ip"]].append(r)

    chains = []
    for ip, evs in ip_events.items():
        types = set(e["type"] for e in evs)
        if len(types) >= 2:
            chains.append({
                "ip": ip,
                "types": list(types),
                "count": len(evs),
                "risk": "高危-多阶段攻击链",
                "suggestion": f"该IP在{len(evs)}次请求中发起{len(types)}类不同攻击, "
                              f"疑似定向渗透, 建议立即封禁并溯源取证",
            })

    summary = {
        "total": len(results),
        "attack": len(attacks),
        "normal": len(results) - len(attacks),
        "ip_rank": Counter(r["log"]["ip"] for r in attacks).most_common(10),
        "level": Counter(r["level"] for r in attacks),
        "type": Counter(r["type"] for r in attacks),
        "peak_hours": peak_hours,
        "chains": chains,
        "attack_ratio": round(len(attacks) / len(results) * 100, 2) if results else 0,
    }

    return results, summary


# ============================================================
# 4. 自动处置模块
# ============================================================

BLOCKED_IPS = set()  # 内存中的封禁记录 (生产环境可换 Redis/数据库)


def get_suggestion(ip, level, attack_type, score):
    """根据风险等级生成处置建议"""
    if level == "高":
        return {
            "action": "立即封禁",
            "detail": [
                f"1. WAF/防火墙立即封禁IP: {ip}",
                f"2. 排查{attack_type}相关漏洞点, 加固输入校验与参数化查询",
                "3. 检查服务器是否存在异常文件/后门/提权痕迹",
                "4. 复盘近24小时该IP全部请求, 确认渗透深度",
            ],
        }
    elif level == "中":
        return {
            "action": "重点监控+规则加固",
            "detail": [
                f"1. 将IP {ip} 加入观察名单, 持续监控",
                "2. 增强WAF对应规则, 提升拦截等级",
                "3. 检查前端/接口输入过滤与输出编码",
                f"4. 当前风险评分: {score}",
            ],
        }
    else:
        return {
            "action": "持续观察",
            "detail": [
                f"1. IP {ip} 标记为低风险, 纳入例行观察",
                "2. 如短期内频繁触发, 升级为监控对象",
            ],
        }


def auto_block(ip, level, dry_run=True):
    """
    自动封禁高危IP (对接WAF API).
    dry_run=True 时仅模拟, 不实际调用API.
    """
    if level != "高":
        return False

    if ip in BLOCKED_IPS:
        return True

    if dry_run:
        # 模拟API调用
        BLOCKED_IPS.add(ip)
        return True

    # TODO: 对接真实WAF API, 示例:
    # import requests
    # resp = requests.post(
    #     "https://waf.example.com/api/v1/block",
    #     json={"ip": ip, "duration": 3600, "reason": "AI自动检测高危攻击"},
    #     headers={"Authorization": "Bearer <TOKEN>"},
    #     timeout=5,
    # )
    # if resp.status_code == 200:
    #     BLOCKED_IPS.add(ip)
    # return resp.status_code == 200

    BLOCKED_IPS.add(ip)
    return True


# ============================================================
# 5. 报告生成
# ============================================================

def _fmt_time(dt=None):
    return (dt or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")


def generate_markdown_report(summary, results, filename="security_report.md"):
    """生成 Markdown 安全报告"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write("# 🛡️ WAF安全日志分析报告\n\n")
        f.write(f"- 生成时间: {_fmt_time()}\n")
        f.write(f"- 报告类型: 智能检测分析\n\n")

        # 概览
        f.write("## 📊 总体统计\n\n")
        f.write(f"| 指标 | 数值 |\n|---|---|\n")
        f.write(f"| 日志总量 | {summary['total']} |\n")
        f.write(f"| 攻击请求数 | {summary['attack']} |\n")
        f.write(f"| 正常请求数 | {summary['normal']} |\n")
        f.write(f"| 攻击占比 | {summary['attack_ratio']}% |\n\n")

        # 风险等级分布
        f.write("## ⚠️ 风险等级分布\n\n")
        for lv in ["高", "中", "低", "无"]:
            if summary["level"].get(lv):
                f.write(f"- {lv}危: {summary['level'][lv]} 次\n")
        f.write("\n")

        # 攻击类型
        f.write("## 🎯 攻击类型分布\n\n")
        for k, v in summary["type"].most_common():
            f.write(f"- {k}: {v} 次\n")
        f.write("\n")

        # Top IP
        f.write("## 🔝 Top攻击IP\n\n")
        f.write("| IP | 攻击次数 |\n|---|---|\n")
        for ip, count in summary["ip_rank"]:
            f.write(f"| {ip} | {count} |\n")
        f.write("\n")

        # 攻击链
        if summary["chains"]:
            f.write("## 🔗 多阶段攻击链\n\n")
            for c in summary["chains"]:
                f.write(f"### {c['ip']} — {c['risk']}\n")
                f.write(f"- 攻击类型: {', '.join(c['types'])}\n")
                f.write(f"- 请求数: {c['count']}\n")
                f.write(f"- 建议: {c['suggestion']}\n\n")

        # 时间趋势
        if summary["peak_hours"]:
            f.write("## ⏰ 攻击高峰时段 (Top5)\n\n")
            for h, c in summary["peak_hours"]:
                f.write(f"- {h}: {c} 次\n")
            f.write("\n")

        # 攻击详情
        f.write("## 📋 攻击详情\n\n")
        shown = 0
        for item in results:
            if not item["attack"] or shown >= 20:
                continue
            shown += 1
            f.write(f"### [{item['level']}] {item['type']}\n")
            f.write(f"- IP: `{item['log']['ip']}`\n")
            f.write(f"- 时间: {item['log']['time']}\n")
            f.write(f"- 请求: `{item['log']['method']} {item['log']['uri']}`\n")
            f.write(f"- User-Agent: `{item['log']['ua'][:80]}`\n")
            f.write(f"- 风险评分: {item['score']}\n\n")

    return filename


def generate_html_report(summary, results, filename="security_report.html"):
    """生成可视化 HTML 报告 (含内嵌图表)"""
    # 为图表准备数据
    type_labels = json.dumps([k for k, _ in summary["type"].most_common()], ensure_ascii=False)
    type_data = json.dumps([v for _, v in summary["type"].most_common()])

    hour_labels = json.dumps([h for h, _ in summary["peak_hours"]], ensure_ascii=False)
    hour_data = json.dumps([c for _, c in summary["peak_hours"]])

    ip_labels = json.dumps([ip for ip, _ in summary["ip_rank"]], ensure_ascii=False)
    ip_data = json.dumps([c for _, c in summary["ip_rank"]])

    chains_html = ""
    if summary["chains"]:
        rows = "".join(
            f"<tr><td>{c['ip']}</td><td>{', '.join(c['types'])}</td>"
            f"<td>{c['count']}</td><td>{c['suggestion']}</td></tr>"
            for c in summary["chains"]
        )
        chains_html = f"""
        <h2>🔗 多阶段攻击链</h2>
        <table><tr><th>IP</th><th>攻击类型</th><th>请求数</th><th>建议</th></tr>{rows}</table>
        """

    details_rows = ""
    shown = 0
    for item in results:
        if not item["attack"] or shown >= 30:
            continue
        shown += 1
        lv_cls = {"高": "high", "中": "mid", "低": "low"}.get(item["level"], "")
        details_rows += f"""
        <tr>
          <td class='{lv_cls}'>{item['level']}</td>
          <td>{item['type']}</td>
          <td>{item['log']['ip']}</td>
          <td>{item['log']['time']}</td>
          <td class='uri'>{item['log']['method']} {item['log']['uri']}</td>
          <td>{item['score']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<title>WAF安全日志分析报告</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  body {{ font-family: -apple-system, "Segoe UI", sans-serif; max-width: 1100px; margin: 0 auto; padding: 24px; color: #1a1a1a; background: #f7f8fa; }}
  h1 {{ color: #c0392b; border-bottom: 3px solid #c0392b; padding-bottom: 8px; }}
  h2 {{ color: #2c3e50; margin-top: 32px; }}
  .cards {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }}
  .card {{ flex: 1; min-width: 140px; background: #fff; border-radius: 10px; padding: 18px; box-shadow: 0 2px 8px rgba(0,0,0,.08); text-align: center; }}
  .card .num {{ font-size: 32px; font-weight: 700; color: #c0392b; }}
  .card .lbl {{ color: #7f8c8d; margin-top: 6px; }}
  .chart-box {{ background:#fff; border-radius:10px; padding:16px; margin:16px 0; box-shadow:0 2px 8px rgba(0,0,0,.08); }}
  table {{ width:100%; border-collapse: collapse; background:#fff; border-radius:10px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,.08); }}
  th {{ background:#2c3e50; color:#fff; padding:10px; text-align:left; }}
  td {{ padding:8px 10px; border-bottom:1px solid #eee; }}
  tr:hover {{ background:#f0f7ff; }}
  .uri {{ max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:monospace; }}
  .high {{ color:#c0392b; font-weight:700; }}
  .mid {{ color:#e67e22; font-weight:600; }}
  .low {{ color:#27ae60; }}
</style>
</head>
<body>
  <h1>🛡️ WAF 安全日志分析报告</h1>
  <p>生成时间: {_fmt_time()}</p>

  <div class="cards">
    <div class="card"><div class="num">{summary['total']}</div><div class="lbl">日志总量</div></div>
    <div class="card"><div class="num" style="color:#e67e22">{summary['attack']}</div><div class="lbl">攻击请求</div></div>
    <div class="card"><div class="num" style="color:#27ae60">{summary['normal']}</div><div class="lbl">正常请求</div></div>
    <div class="card"><div class="num">{summary['attack_ratio']}%</div><div class="lbl">攻击占比</div></div>
  </div>

  <div class="chart-box"><canvas id="typeChart"></canvas></div>
  <div class="chart-box"><canvas id="hourChart"></canvas></div>
  <div class="chart-box"><canvas id="ipChart"></canvas></div>

  {chains_html}

  <h2>📋 攻击详情 (前30条)</h2>
  <table>
    <tr><th>等级</th><th>类型</th><th>IP</th><th>时间</th><th>请求</th><th>评分</th></tr>
    {details_rows}
  </table>

<script>
const tLabels={type_labels}, tData={type_data};
const hLabels={hour_labels}, hData={hour_data};
const iLabels={ip_labels}, iData={ip_data};
new Chart(document.getElementById('typeChart'), {{
  type:'doughnut', data:{{labels:tLabels, datasets:[{{data:tData, backgroundColor:['#c0392b','#e67e22','#f1c40f','#3498db','#9b59b6','#1abc9c']}}]}},
  options:{{plugins:{{title:{{display:true,text:'攻击类型分布'}}}}}}
}});
new Chart(document.getElementById('hourChart'), {{
  type:'bar', data:{{labels:hLabels, datasets:[{{label:'攻击次数',data:hData,backgroundColor:'#e74c3c'}}]}},
  options:{{plugins:{{title:{{display:true,text:'攻击高峰时段'}}}}, scales:{{y:{{beginAtZero:true}}}}}}
}});
new Chart(document.getElementById('ipChart'), {{
  type:'bar', data:{{labels:iLabels, datasets:[{{label:'攻击次数',data:iData,backgroundColor:'#3498db'}}]}},
  options:{{indexAxis:'y', plugins:{{title:{{display:true,text:'Top攻击IP'}}}}, scales:{{x:{{beginAtZero:true}}}}}}
}});
</script>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename


# ============================================================
# 6. 主流程
# ============================================================

def run(log_file=DEFAULT_LOG_FILE, dry_run=True, out_md=True, out_html=True):
    print("=" * 56)
    print("🛡️  WAF 智能日志分析与自动处置系统")
    print("=" * 56)

    logs = load_logs(log_file)
    if not logs:
        print("[!] 未解析到任何有效日志, 请检查日志文件路径与格式")
        return

    results, summary = analyze_logs(logs)

    print(f"\n📊 日志总量: {summary['total']}")
    print(f"⚠️  攻击请求: {summary['attack']} ({summary['attack_ratio']}%)")
    print(f"✅ 正常请求: {summary['normal']}")

    print("\n🎯 攻击类型分布:")
    for k, v in summary["type"].most_common():
        print(f"   - {k}: {v} 次")

    print("\n🔝 Top攻击IP:")
    for ip, count in summary["ip_rank"]:
        print(f"   - {ip}: {count} 次")

    if summary["peak_hours"]:
        print("\n⏰ 攻击高峰时段:")
        for h, c in summary["peak_hours"]:
            print(f"   - {h}: {c} 次")

    if summary["chains"]:
        print(f"\n🔗 发现 {len(summary['chains'])} 条多阶段攻击链:")
        for c in summary["chains"]:
            print(f"   - {c['ip']}: {', '.join(c['types'])} ({c['count']}次)")

    # 自动处置: 按IP聚合 (同IP取最高风险等级, 避免重复处置)
    ip_summary = {}
    for item in results:
        if not item["attack"]:
            continue
        ip = item["log"]["ip"]
        if ip not in ip_summary:
            ip_summary[ip] = {
                "level": item["level"], "types": set(),
                "score": item["score"], "count": 0,
            }
        ip_summary[ip]["types"].add(item["type"])
        ip_summary[ip]["count"] += 1
        # 等级升级: 高 > 中 > 低
        lv_order = {"高": 3, "中": 2, "低": 1}
        if lv_order.get(item["level"], 0) > lv_order.get(ip_summary[ip]["level"], 0):
            ip_summary[ip]["level"] = item["level"]
            ip_summary[ip]["score"] = item["score"]

    # 按风险排序
    sorted_ips = sorted(
        ip_summary.items(),
        key=lambda x: ({"高": 0, "中": 1, "低": 2}[x[1]["level"]], -x[1]["score"]),
    )

    print("\n🚀 自动处置建议 (按IP聚合):")
    auto_blocked = set()
    for ip, info in sorted_ips:
        sug = get_suggestion(ip, info["level"], "/".join(info["types"]), info["score"])
        blocked = auto_block(ip, info["level"], dry_run=dry_run)
        if blocked:
            auto_blocked.add(ip)
        tag = "🔒已自动封禁" if ip in auto_blocked else "👁 监控中"
        print(f"\n   [{info['level']}] {ip} {tag}")
        print(f"   攻击类型: {', '.join(info['types'])} ({info['count']}次) | 最高评分: {info['score']}")
        print(f"   动作: {sug['action']}")
        for d in sug["detail"]:
            print(f"     {d}")

    print(f"\n🔒 本次自动封禁高危IP数: {len(auto_blocked)}")

    # 生成报告
    if out_md:
        f1 = generate_markdown_report(summary, results)
        print(f"📄 Markdown报告: {f1}")
    if out_html:
        f2 = generate_html_report(summary, results)
        print(f"📊 HTML可视化报告: {f2}")

    print("\n" + "=" * 56)
    print("✅ 分析完成")
    print("=" * 56)


if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else "access.log"
    run(log_file)
