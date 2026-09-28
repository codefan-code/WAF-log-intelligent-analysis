# 🛡️ WAF日志智能分析与自动处置系统

面向企业Web安全的日志分析工具：智能检测、攻击链关联、自动处置、可视化报告。
可独立运行，无需研发支援即可现场部署。

## 功能特性
- 多格式解析：自动适配 Nginx/Apache 通用日志
- 双层检测：正则规则(快) + 上下文特征评分(降误报) + 白名单去误报
- 6类攻击：SQL注入 / XSS / 路径遍历 / 命令执行 / 文件上传包含 / SSRF扫描
- 攻击链分析：识别同一IP的多阶段定向渗透
- 时间趋势：按小时聚合攻击高峰
- 自动处置：高危IP自动封禁（API接口已预留）
- 双格式报告：Markdown + HTML可视化（内嵌Chart.js）

## 快速开始
```bash
python3 gen_sample_logs.py          # 生成模拟日志（或替换为你的 access.log）
python3 run_analyzer.py             # 运行分析（默认 dry-run 演示）
python3 run_analyzer.py my.log      # 指定日志文件
python3 run_analyzer.py --real      # 对接真实WAF API
```

## 两种部署方式（任选其一）
```
方式A - 包结构（推荐）:            方式B - 单文件（最简单）:
waf_project/                        waf_project/
├── waf_analyzer/                   ├── core.py
│   ├── __init__.py                 ├── run_analyzer.py
│   └── core.py                     └── gen_sample_logs.py
├── run_analyzer.py
└── gen_sample_logs.py
```
脚本已做兼容，两种方式都能直接 `python3 run_analyzer.py` 运行。

## 扩展
- 加规则：编辑 core.py 的 ATTACK_RULES 字典
- 对接真实WAF：在 auto_block() 中取消 requests 调用注释，配API地址与Token
