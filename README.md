# sentinelforge — 主权自主网络防御引擎

> 一个零依赖的**网络安全 / 自主防御参考实现**，把「开源权重大模型做网络防御」这件事，拆成四个能落地的工程问题：**威胁检测 → 分诊 → 攻击链关联 → 修复**，全程离线、数据不出域。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![zero dependencies](https://img.shields.io/badge/deps-zero-brightgreen.svg)](#为什么零依赖)

---

## 一句话讲清楚

Mistral 开源了 **Mistral Large 4（"Le Chonk"）** 的权重——一个约 1 万亿参数、520 亿激活的 MoE 模型，主攻**网络安全与自主网络防御**，强调三件事：**① 主权**（权重开放，自己部署、数据不出域）；**② 三种推理模式**（low/medium/high，用预算调深度、不改提示词）；**③ token 效率**（同等工作比 GLM-5.3 少用约 47% token）。

sentinelforge 不是再复述这条新闻，而是把这三件事背后的**技术原理**拆出来，做成一个能直接跑、能照着改的完整项目：

- **怎么实现"检测"**：静态规则引擎（SQL 注入 / XSS / 命令注入 / 硬编码密钥 / 路径穿越 / 弱加密 / SSRF / 反序列化 / 开放重定向）+ CVE 依赖匹配 + IoC 提取。
- **怎么实现"深度可调"**：三档推理模式 = 同一个信号 + 不同预算，而不是三套提示词。
- **怎么实现"主权"**：管线里**零网络调用**，每次扫描都带审计（`network_egress: 0`）。

## 核心能力

| 阶段 | 模块 | 做什么 |
|---|---|---|
| 检测 | `detect/` | 9 类静态规则 + 8 条 CVE + IoC 提取 |
| 打分 | `core/model.py` | skill 参数化的置信度模型（可训练、单调） |
| 分诊 | `analyze/` | CVSS 式严重度 + 置信度 + 攻击链关联 |
| 修复 | `respond/` | 修复建议 + 最小 patch 生成 |
| 报告 | `report/` | Markdown / JSON / SARIF 三种导出 |

## 快速开始

```bash
# 零依赖，直接跑（Python 3.9+）
python -m sentinelforge doctor          # 端到端冒烟
python -m sentinelforge bench           # 五项单调基准
python -m sentinelforge scan examples/vulnerable
python -m sentinelforge --mode high scan examples/vulnerable
python -m sentinelforge train --epochs 10
python -m sentinelforge serve --port 8420   # HTTP API
```

## 基准（实测）

`bench` 把模型 skill 从 0.5（随机）扫到 1.0（专家），五项指标全部单调：

| 指标 | skill=0.5 | skill=1.0 | 方向 |
|---|---|---|---|
| 检测召回 detect_recall | 0.333 | 1.000 | ↑ |
| 检测精确 detect_precision | 0.400 | 1.000 | ↑ |
| 误报率 false_positive_rate | 0.480 | 0.000 | ↓ |
| 分诊准确 triage_accuracy | 0.458 | 1.000 | ↑ |
| 修复质量 remediation_quality | 0.523 | 1.000 | ↑ |

（完整 6 档曲线见 `python -m sentinelforge bench`，单调无回退。）

## 可复用的干货块

### 1. 置信度公式（"去噪信号"的通用写法）

```python
boost = (skill - 0.5) * 2                # -1..+1，随机处为 0
conf  = 0.5 + boost*(signal-0.5) + (1-abs(boost))*(noise-0.5)
```

- skill=0.5 → `conf=noise`（掷硬币）；skill=1.0 → `conf=signal`（精确）。
- **要点**：信号与噪声要**同尺度**，且噪声在 skill 两端要收敛，否则弱信号被噪声淹没（本仓库 `core/model.py` 直接可抄）。

### 2. 推理深度 = 预算参数，不是提示词

| 模式 | 深度 | 预算 | 关联 | patch |
|---|---|---|---|---|
| low | 1 | 0.4x | ✗ | ✗ |
| medium | 2 | 1.0x | ✓ | ✓ |
| high | 3 | 2.5x | ✓ | ✓ |

信号（提示词 + 代码）完全不变，只动预算。`core/modes.py` + `core/token_budget.py`。

### 3. 检测规则要"无歧义、可回退"

规则只抓**经典无歧义反模式**（字符串拼接进 SQL、`innerHTML`、硬编码 `ghp_`/`AKIA` 等），宁精勿全。完整规则与写法见 `docs/rules_reference.md`。

### 4. 修复要输出 diff，不要输出散文

`prompts/remediate_prompt.md` 的模板要求"最小 diff + 一行说明"，让修复机械可应用。配套的可复用提示词在 `prompts/`，配置配方在 `recipes/`。

## 项目结构

```
sentinelforge/
├── sentinelforge/        # 主包（detect/analyze/respond/report/core/world/training/serving）
├── tests/                # 22 个单测文件（stdlib unittest）
├── examples/             # 有漏洞 vs 安全的两套扫描目标
├── docs/                 # 架构 / 威胁模型 / 推理模式 / 规则 / 主权 / 预算 / API
├── prompts/              # 5 组可复用提示词模板 + few-shot
├── recipes/              # 5 份 YAML 配置配方
├── deploy/               # Docker / docker-compose / k8s / Helm
└── .github/workflows/ci.yml
```

## 为什么零依赖

主权防御的核心是**自己不带供应链攻击面**：纯标准库意味着没有要 `pip install` 的东西、没有传递性 CVE、Python 3.9+ 到处能跑。代价是不用 numpy/torch——但这是"参考实现"，讲清架构即可，生产再替换。

## License

MIT — 详见 [LICENSE](LICENSE)。
