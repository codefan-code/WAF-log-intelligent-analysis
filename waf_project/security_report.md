# 🛡️ WAF安全日志分析报告

- 生成时间: 2026-09-28 15:33:43
- 报告类型: 智能检测分析

## 📊 总体统计

| 指标 | 数值 |
|---|---|
| 日志总量 | 441 |
| 攻击请求数 | 35 |
| 正常请求数 | 406 |
| 攻击占比 | 7.94% |

## ⚠️ 风险等级分布

- 高危: 25 次
- 中危: 10 次

## 🎯 攻击类型分布

- 路径遍历: 9 次
- 文件上传/包含: 8 次
- SSRF/扫描探测: 7 次
- SQL注入: 5 次
- 命令执行: 3 次
- XSS攻击: 3 次

## 🔝 Top攻击IP

| IP | 攻击次数 |
|---|---|
| 10.0.0.199 | 11 |
| 203.0.113.45 | 10 |
| 192.0.2.88 | 8 |
| 198.51.100.23 | 6 |

## 🔗 多阶段攻击链

### 10.0.0.199 — 高危-多阶段攻击链
- 攻击类型: SSRF/扫描探测, SQL注入, XSS攻击, 路径遍历, 文件上传/包含
- 请求数: 11
- 建议: 该IP在11次请求中发起5类不同攻击, 疑似定向渗透, 建议立即封禁并溯源取证

### 192.0.2.88 — 高危-多阶段攻击链
- 攻击类型: SQL注入, 路径遍历, 文件上传/包含
- 请求数: 8
- 建议: 该IP在8次请求中发起3类不同攻击, 疑似定向渗透, 建议立即封禁并溯源取证

### 203.0.113.45 — 高危-多阶段攻击链
- 攻击类型: SSRF/扫描探测, 路径遍历, XSS攻击, 命令执行
- 请求数: 10
- 建议: 该IP在10次请求中发起4类不同攻击, 疑似定向渗透, 建议立即封禁并溯源取证

### 198.51.100.23 — 高危-多阶段攻击链
- 攻击类型: SQL注入, 文件上传/包含, SSRF/扫描探测, 命令执行
- 请求数: 6
- 建议: 该IP在6次请求中发起4类不同攻击, 疑似定向渗透, 建议立即封禁并溯源取证

## ⏰ 攻击高峰时段 (Top5)

- 2026-09-28 12:00: 6 次
- 2026-09-28 18:00: 6 次
- 2026-09-28 16:00: 5 次
- 2026-09-28 10:00: 4 次
- 2026-09-28 13:00: 4 次

## 📋 攻击详情

### [中] SSRF/扫描探测
- IP: `10.0.0.199`
- 时间: 28/Sep/2026:10:18:00 +0800
- 请求: `POST /proxy?url=http://127.0.0.1/admin`
- User-Agent: `Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0`
- 风险评分: 7

### [高] SQL注入
- IP: `192.0.2.88`
- 时间: 28/Sep/2026:10:39:00 +0800
- 请求: `GET /index.php?id=1/**/AND/**/1=1`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0`
- 风险评分: 12

### [高] 命令执行
- IP: `203.0.113.45`
- 时间: 28/Sep/2026:10:44:00 +0800
- 请求: `GET /api/v1/util?cmd=whoami`
- User-Agent: `Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148`
- 风险评分: 12

### [高] 路径遍历
- IP: `10.0.0.199`
- 时间: 28/Sep/2026:10:53:00 +0800
- 请求: `GET /backup/../config/web.config`
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0`
- 风险评分: 10

### [高] SQL注入
- IP: `192.0.2.88`
- 时间: 28/Sep/2026:11:35:00 +0800
- 请求: `GET /index.php?id=1/**/AND/**/1=1`
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0`
- 风险评分: 12

### [高] 文件上传/包含
- IP: `10.0.0.199`
- 时间: 28/Sep/2026:11:53:00 +0800
- 请求: `POST /upload?filename=shell.php`
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0`
- 风险评分: 11

### [高] 路径遍历
- IP: `203.0.113.45`
- 时间: 28/Sep/2026:12:07:00 +0800
- 请求: `GET /backup/../config/web.config`
- User-Agent: `Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0`
- 风险评分: 10

### [高] 路径遍历
- IP: `192.0.2.88`
- 时间: 28/Sep/2026:12:12:00 +0800
- 请求: `GET /api/v1/file?path=../windows/system32/config`
- User-Agent: `Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148`
- 风险评分: 12

### [高] 路径遍历
- IP: `203.0.113.45`
- 时间: 28/Sep/2026:12:14:00 +0800
- 请求: `GET /backup/../config/web.config`
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0`
- 风险评分: 10

### [中] SSRF/扫描探测
- IP: `203.0.113.45`
- 时间: 28/Sep/2026:12:16:00 +0800
- 请求: `GET /phpmyadmin/index.php`
- User-Agent: `Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0`
- 风险评分: 5

### [中] XSS攻击
- IP: `10.0.0.199`
- 时间: 28/Sep/2026:12:21:00 +0800
- 请求: `GET /comment?msg=<script>alert(document.cookie)</script>`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0`
- 风险评分: 8

### [高] 路径遍历
- IP: `10.0.0.199`
- 时间: 28/Sep/2026:12:33:00 +0800
- 请求: `GET /api/v1/file?path=../windows/system32/config`
- User-Agent: `Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0`
- 风险评分: 12

### [高] SQL注入
- IP: `10.0.0.199`
- 时间: 28/Sep/2026:13:05:00 +0800
- 请求: `GET /index.php?id=1/**/AND/**/1=1`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0`
- 风险评分: 12

### [高] 文件上传/包含
- IP: `198.51.100.23`
- 时间: 28/Sep/2026:13:06:00 +0800
- 请求: `POST /upload?filename=shell.php`
- User-Agent: `Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148`
- 风险评分: 11

### [高] 路径遍历
- IP: `192.0.2.88`
- 时间: 28/Sep/2026:13:39:00 +0800
- 请求: `GET /api/v1/file?path=../windows/system32/config`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0`
- 风险评分: 12

### [高] 文件上传/包含
- IP: `192.0.2.88`
- 时间: 28/Sep/2026:13:51:00 +0800
- 请求: `GET /include.php?file=php://input`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0`
- 风险评分: 11

### [中] SSRF/扫描探测
- IP: `10.0.0.199`
- 时间: 28/Sep/2026:14:19:00 +0800
- 请求: `GET /.env`
- User-Agent: `Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148`
- 风险评分: 5

### [中] SSRF/扫描探测
- IP: `203.0.113.45`
- 时间: 28/Sep/2026:14:51:00 +0800
- 请求: `POST /proxy?url=http://127.0.0.1/admin`
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0`
- 风险评分: 7

### [高] SQL注入
- IP: `198.51.100.23`
- 时间: 28/Sep/2026:15:02:00 +0800
- 请求: `GET /index.php?id=1/**/AND/**/1=1`
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0`
- 风险评分: 12

### [中] SSRF/扫描探测
- IP: `198.51.100.23`
- 时间: 28/Sep/2026:15:28:00 +0800
- 请求: `GET /.env`
- User-Agent: `Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0`
- 风险评分: 5

