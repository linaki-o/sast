# CodeShield 代码卫士

> 面向 C/C++ 的静态分析、单元测试与需求追踪一体化平台
> A self-hosted C/C++ quality platform: static analysis, unit testing with coverage, and requirements traceability.

CodeShield 是一套用 Python 实现的开源 C/C++ 代码质量平台，覆盖企业级代码安全治理的完整闭环：

| 能力 | 说明 |
| --- | --- |
| **静态分析 (SAST)** | 自研 C/C++ 词法/语法分析前端 + 77 条内置规则，覆盖 CWE 安全缺陷、MISRA C:2012 编码规范与代码质量 |
| **单元测试** | 双引擎：`gcc/clang + gcov` 原生流水线，以及**纯 Python C 解释器**（无需任何编译器即可运行真实单元测试） |
| **覆盖率** | 语句 / 分支 / 条件 / **MC/DC** 四维覆盖率，支持条件独立性与覆盖率合并 |
| **需求追踪** | 需求导入（YAML/JSON/CSV/Excel/Markdown/Word）、需求↔测试↔代码↔缺陷追踪矩阵、覆盖缺口分析 |
| **变更影响分析** | 基于 Git 的增量分析，��� `#include` 依赖图计算受影响文件集合 |
| **质量门禁** | 基线（baseline）机制、严重度阈值、CI 退出码，SARIF 输出可直接对接 GitHub/GitLab 代码扫描 |
| **多形态界面** | CLI、Web 看板（FastAPI）、桌面客户端（PySide6）、HTML/JSON/XML/SARIF 报告 |

---

## 基准测试

仓库自带一套可复现的基准体系（`benchmarks/`），用于量化分析质量与性能。

```bash
sast bench --mode all          # 全部基准
sast bench --mode accuracy     # 准确率
sast bench --mode speed        # 吞吐
sast bench --mode scale        # 规模伸缩性
sast bench --mode size         # 单文件体积对吞吐的影响
sast bench --mode compare      # 与 Cppcheck / Clang-Tidy 的横向对比
sast bench --json out.json     # 导出测量数据
```

### 与 Cppcheck / Clang-Tidy 的横向对比

同一份语料、同一套真值，可以直接驱动外部工具做对比：

```bash
pip install cppcheck clang-tidy      # 两个工具都有 PyPI wheel
sast bench --mode compare
```

```
tool        version                                    recall   defects  findings  unmapped  time
---------- -----------------------------------------  -------  -------  --------  --------  ------
CodeShield  0.1.0                                      100.0 %  33/33    92        19        63 ms
Cppcheck    Cppcheck 2.22.0 from cppcheck-wheel 1.5.3    42.1 %  8/19     81        9         139 ms
Clang-Tidy  LLVM version 23.1.4                         32.0 %  8/25     99        11        922 ms
```

**对比是公平的**，靠三层机制保证：

1. **规范缺陷分类法**（`benchmarks/mapping.py`）—— 每个植入缺陷映射到一个中立 ID（如 `DEFECT-UNBOUNDED-COPY`），并列出各工具对应的检查 ID：

   | 规范缺陷 | CodeShield | Cppcheck | Clang-Tidy |
   | --- | --- | --- | --- |
   | `DEFECT-UNBOUNDED-COPY` | `SEC-BUF-001` | `bufferAccessOutOfBounds` | `clang-analyzer-security.insecureAPI.*` |
   | `DEFECT-USE-AFTER-FREE` | `SEC-USE-001` | `deallocuse` | `clang-analyzer-use-after-free` |
   | `DEFECT-UNUSED-VARIABLE` | `QLT-UNUSED-001` | `unreadVariable` | `clang-diagnostic-unused-variable` |
   | `DEFECT-NON-TERMINATING-LOOP` | `QLT-LOOP-001` | `knownConditionTrueFalse` | `bugprone-infinite-loop` |

2. **适用性裁剪** —— 某个工具无法表达的缺陷（主要是 MISRA 专属）不计入它的分母，所以 19 / 25 / 33 三个分母不同是合理的。

3. **位置匹配** —— 工具报告的行号可能落在函数内任意位置，匹配时按函数作用域判定，与 CodeShield 自身的召回率口径一致。

> 只有**召回率**可以横向比较：三个工具的发现集合差异巨大，精度不可比。表中额外给出 `findings`（发现总数）与 `unmapped`（在分类法中无对应项的发现）作为噪声参考。

工具缺失时该行会被跳过并注明原因，不会中断基准。

### 语料与真值

`benchmarks/corpus/` 是一组刻意植入缺陷的 C/C++ 文件：

| 文件 | 内容 |
| --- | --- |
| `security.c` | 缓冲区溢出、格式化字符串、命令注入、释放后使用、硬编码凭据等 |
| `quality.c` | 未使用变量/参数、变量遮蔽、`goto`、缺大括号、魔法数字等 |
| `standards.c` | MISRA C:2012 条款违规（无 default 标签、逗号运算符等） |
| `cxx.cpp` | C++ 专有构造（命名空间、类、range-for、异常、`std::` 限定名） |
| `clean.c` | **对照组**：完全符合规范，任何发现都算误报 |

真值有两层：

- **内联标注** `/* sast:expect RULE-ID */` —— 刻意植入的缺陷，用于测量**召回率**
- **`manifest.yaml`** —— 语料上全部预期发现的冻结基线，用于测量**符合度**并作为回归护栏

规则行为变化时用 `python -m benchmarks.generate_manifest --write` 重新生成基线并人工复核差异。

### 当前测量结果

```
准确率
  planted defects      : 33        召回率        : 100.0 %
  detected             : 33        F1            : 100.0 %
  missed               : 0
  manifest findings    : 92        基线符合度    : 100.0 %
  manifest detected    : 92
  unexpected findings  : 0

吞吐（Intel Core Ultra 7 / CPython 3.13）
  11,644 行/秒 · 80 文件/秒
  阶段占比：规则 75% / 词法 15% / 语法 7% / 度量 1% / 符号表 1%

规模伸缩性
  代码量增长 9.7x，耗时增长 9.9x  →  伸缩因子 1.01（理想值 1.00）

单文件体积
  翻译单元增长 15.9x，吞吐变化 0.89x  →  单位行成本稳定，无平方级规则
```

### 基准揭示并修复的缺陷

基准不是装饰，它在建立过程中暴露了 **7 个真实缺陷**：

| 缺陷 | 影响 |
| --- | --- |
| 解析器遇到未知类型名（`uint32_t`）时**静默丢弃整个声明** | 大量使用标准库类型的代码完全不被分析 |
| `Project.relative()` 用未解析的 root 做比较 | 相对路径工程的所有发现路径变成绝对路径 |
| `Node.end_location` 返回最后一个子节点的**起始**行 | 函数范围、代码片段截断都算错 |
| `Call.callee_name` 不剥离命名空间限定 | `std::strcpy` / `std::printf` 全部漏报 |
| `nullptr` / `true` / `false` 是 C++ 关键字但表达式解析器只认标识符 | 使用它们的代码整段解析失败 |
| `delete[] p` 被误判为 lambda | 数组释放不可见，双重释放漏报 |
| C++ 成员初始化列表被整体跳过 | 构造函数参数被误报为未使用 |

---

## 目录

- [快速开始](#快速开始)
- [命令一览](#命令一览)
- [项目配置](#项目配置)
- [规则体系](#规则体系)
- [单元测试与覆盖率](#单元测试与覆盖率)
- [需求追踪](#需求追踪)
- [报告与集成](#报告与集成)
- [Web 看板与桌面端](#web-看板与桌面端)
- [基准测试](#基准测试)
- [架构说明](#架构说明)
- [开发与扩展](#开发与扩展)

---

## 快速开始

### 安装

```bash
git clone <your-repo> codeshield
cd codeshield
pip install -e .            # 核心功能
pip install -e ".[web]"     # + Web 看板 (FastAPI/uvicorn/jinja2)
pip install -e ".[gui]"     # + 桌面客户端 (PySide6)
pip install -e ".[dev]"     # + 测试工具链
```

> 核心分析链路仅依赖 `PyYAML` 与 `pydantic`；Web/GUI/报告均为可选依赖。

### 分析一个工程

```bash
cd examples/sample_project
sast analyze .
```

输出：

```
CodeShield 0.1.0 - sample_project
------------------------------------------------------------------------
scanned 3 files / 272 lines with 49 rules in 0.02s

findings: 2  critical=0  high=0  medium=1  low=0  info=1

  MEDIUM QLT-DEPRECATED-001 src\utils.c:43
      'strcpy' is deprecated; use strncpy or memcpy with an explicit size instead
      -> Use the modern replacement of the function.
  INFO SEC-LEAK-001 src\utils.c:49
      the return value of snprintf() is ignored; the output may have been truncated

quality gate: PASS

reports:
  D:\...\sast-report\index.html
  D:\...\sast-report\report.json
```

### 运行单元测试

```bash
sast test examples/sample_project
```

```
utils
  PASS compute adds two positive numbers (7.3 ms)
  PASS compute rejects a null output pointer (6.0 ms)
  ...
  coverage: statement 71.1%  branch 100.0%  condition 76.9%  MC/DC 76.9%

16/16 tests passed in 0.13s
```

### 启动 Web 看板

```bash
sast serve examples/sample_project --port 8765
# 浏览器打开 http://127.0.0.1:8765
```

### 启动桌面客户端

```bash
sast gui examples/sample_project
```

---

## 命令一览

```
sast analyze [path]     运行静态分析并生成报告
sast test    [path]     运行单元测试并采集覆盖率
sast trace   [path]     构建需求追踪矩阵
sast rules              列出全部规则（支持 --json）
sast bench              运行基准测试（accuracy/speed/scale/size）
sast baseline create    生成基线（记录已知问题）
sast baseline diff      对比基线，输出新增/已修复问题
sast changes            展示变更影响范围
sast config             打印生效配置
sast serve              启动 Web 看板
sast gui                启动桌面客户端
```

常用参数：

```bash
sast analyze . -e SEC-BUF-001          # 只启用指定规则
sast analyze . -d QLT-MAGIC-001        # 禁用指定规则
sast analyze . -C security             # 只跑某一类规则
sast analyze . -s high                 # 只报告 high 及以上
sast analyze . -f html -f sarif        # 指定报告格式
sast analyze . --baseline              # 抑制基线中已接受的问题
sast analyze . --incremental           # 只分析 Git 变更影响到的文件
sast analyze . --json                  # 机器可读输出
```

退出码遵循质量门禁：存在达到 `fail_on` 阈值的问题时返回 `1`，便于 CI 拦截。

---

## 项目配置

在工程根目录放置 `sast.yaml`（也支持 `sast.yml` / `.sast.yaml`）：

```yaml
analysis:
  source_dirs: [src, include]
  excludes:
    - "**/build/**"
    - "**/third_party/**"

  categories: [security, quality]
  severity_threshold: info
  disabled_rules: [QLT-MAGIC-001]

  max_cyclomatic_complexity: 10
  max_function_lines: 60
  max_nesting_depth: 4
  max_parameters: 5

  report_formats: [html, json, sarif]
  report_dir: sast-report

  test_dirs: [tests]
  requirements_files: [requirements/requirements.yaml]

  fail_on: high
```

所有键都有默认值，**不写任何配置也能直接开跑**。用 `sast config` 查看生效配置。

### 行内抑制

```c
void f(void) {
    int legacy = 1;          // sast:ignore QLT-UNUSED-001  历史遗留，暂不清理
}
```

支持 `// sast:ignore <规则ID>`，抑制规则作用于注释所在行或下一行。

---

## 规则体系

当前内置 **77 条规则**（`sast rules` 可查看完整清单与 CWE 映射），分属三个规则包：

| 规则包 | 数量 | 前缀 | 说明 |
| --- | --- | --- | --- |
| 安全 | 27 | `SEC-*` | CWE 映射的内存安全、注入、加密、凭据类缺陷 |
| 质量 | 26 | `QLT-*` | 可维护性、复杂度、风格、循环终止与可疑代码模式 |
| 规范 | 24 | `MISRA-*` | MISRA C:2012 条款实现 |

### 安全类 `SEC-*`（27 条）

| 规则 | 等级 | 说明 | CWE |
| --- | --- | --- | --- |
| `SEC-BUF-001` | HIGH | `strcpy`/`strcat` 写入固定长度缓冲区 | 120, 787 |
| `SEC-BUF-002` | CRITICAL | `gets`/`fgets` 不安全使用 | 120, 242 |
| `SEC-BUF-003` | HIGH | `sprintf` 写入固定缓冲区（应改用 `snprintf`） | 120, 121 |
| `SEC-BUF-004` | HIGH | `memcpy` 拷贝长度超过目标容量 | 120, 787 |
| `SEC-BUF-005` | MEDIUM | `strncpy` 结果可能未以 NUL 结尾 | 170, 120 |
| `SEC-CMD-001` | CRITICAL | 命令注入（非字面量传入 `system`/`exec*`/`popen`） | 78 |
| `SEC-FMT-001` | HIGH | 格式化字符串漏洞 | 134 |
| `SEC-FMT-002` | MEDIUM | 格式串占位符与实参数量不匹配 | 685 |
| `SEC-NULL-001` | HIGH | 空指针解引用 | 476 |
| `SEC-NULL-003` | MEDIUM | `malloc`/`fopen` 等返回值未判空 | 252, 476 |
| `SEC-USE-001` | HIGH | 释放后使用 (use-after-free) | 416 |
| `SEC-USE-002` | HIGH | 重复释放 (double free) | 415 |
| `SEC-MEM-001` | HIGH | 内存泄漏 | 401 |
| `SEC-INT-001` | HIGH | 整数溢出 | 190 |
| `SEC-INT-002` | MEDIUM | 有符号/无符号比较失配 | 195 |
| `SEC-CRED-001` | HIGH | 硬编码口令/密钥 | 798, 259 |
| `SEC-RAND-001` | MEDIUM | 安全场景使用 `rand()` | 338 |
| `SEC-CRYPTO-001` | MEDIUM | 使用 MD5/SHA1 等弱哈希 | 327 |
| `SEC-CRYPTO-002` | MEDIUM | 使用 ECB 模式 | 327 |
| `SEC-PATH-001` | HIGH | 路径穿越 | 22 |
| `SEC-SQLE-001` | HIGH | SQL 注入 | 89 |
| `SEC-ENV-001` | MEDIUM | 从环境变量读取敏感数据 | 526 |

### 规范类 `MISRA-*`（24 条）

完整实现 MISRA C:2012 的 24 条条款，包括：

| 条款 | 检查内容 |
| --- | --- |
| 8.7 / 8.9 / 8.13 | 外部/内部链接定义唯一性、定义先于使用、指针应指向 const |
| 10.1 / 10.3 / 10.4 / 10.6 | 隐式类型转换、有符号转无符号、指针复合赋值 |
| 11.3 / 11.4 / 11.5 | 指针与整型互转、不兼容对象指针转换 |
| 12.1 / 12.3 / 13.5 | 逻辑运算符、逗号运算符、基本类型 |
| 14.4 | `if` 控制表达式须为本质布尔类型 |
| 15.5 / 15.6 / 15.7 | 单出口、循环/分支体须为复合语句 |
| 16.4 / 16.5 | `switch` 须有 `default` 且位于首尾 |
| 17.7 | 有返回值函数的返回值必须被使用 |
| 18.1 | 指针算术不得越界 |
| 21.6 / 21.10 / 21.12 | 禁用标准库内存分配、时间函数与异常处理 |

### 质量类 `QLT-*`（26 条）

覆盖未使用变量/参数/函数、变量遮蔽、圈复杂度与嵌套深度、魔法数字、`goto`、缺失大括号、隐式类型转换、缺失返回值、废弃函数调用等，多数规则可映射到 **MISRA C:2012** 具体条款。

其中 3 条为循环终止分析（`sast/analysis/values.py` 提供值域分析支撑）：

| 规则 | 等级 | 说明 |
| --- | --- | --- |
| `QLT-LOOP-001` | HIGH | 循环条件恒为真（无符号值与 0 比较等），循环可能永不退出 |
| `QLT-LOOP-002` | CRITICAL | 条件恒为真且循环体无 `break`/`return`/`goto`，必然死循环 |
| `QLT-LOOP-003` | MEDIUM | 循环递减无符号计数器，会回绕而非归零 |

规则定义在 `sast/rules/builtin/` 下，每个类即一条规则（`security.py` / `quality.py` / `standards.py` / `loops.py`）：

```python
from sast.core.models import Severity
from sast.rules.base import Rule, register

@register
class MyRule(Rule):
    id = "SEC-MY-001"
    name = "示例规则"
    category = "security"
    severity = Severity.HIGH
    description = "..."
    recommendation = "..."
    cwe = (120,)

    def check(self, ctx):
        for call in ctx.find_calls("strcpy"):
            yield ctx.report(self, call, "发现问题")
```

---

## 单元测试与覆盖率

### 双引擎

| 引擎 | 触发条件 | 说明 |
| --- | --- | --- |
| `native` | 系统存在 `gcc`/`clang` + `gcov` | 生成 C harness，编译运行，解析 `.gcov` |
| `interpreter` | 无编译器时自动降级 | 内置 C 解释器，直接执行 AST |

`--engine auto|native|interpreter` 可显式指定。**解释器引擎无需任何外部工具链**，在没有编译器的评审机上也能跑真实单元测试并产出真实覆盖率。

解释器支持：完整表达式优先级、指针/数组/结构体/枚举/typedef、`malloc/free/memcpy/strcpy/strlen` 等常用内建函数、`switch`/`goto`、递归、内存越界检测与执行步数上限保护。

### 编写测试套件

```python
# tests/test_utils.py
from sast.testing import TestCase, TestSuite

SUITE = TestSuite(
    name="utils",
    source_files=["src/utils.c"],
    tests=[
        TestCase(
            id="TC-001",
            name="compute adds two numbers",
            target="compute",
            params=[2, 3, "&out"],
            setup=["int out;"],
            expected=5,
            assert_expr="out == 5",
            requirement_ids=["REQ-001"],
        ),
    ],
)
SUITES = [SUITE]
```

参数约定：

| 写法 | 含义 |
| --- | --- |
| `5` | 普通值 |
| `"&name"` | 传入变量 `name` 的**地址** |
| `"$name"` | 传入变量 `name` 的**值** |
| `"abc"` | 字符串字面量（以 `char*` 传入） |

套件也可用 JSON/YAML 描述（文件名需以 `_test.json` / `_test.yaml` 结尾）。

### 覆盖率模型

- **语句覆盖**：每个可执行语句
- **分支覆盖**：`if/else`、循环、`switch` 各分支、`&&`/`||` 短路
- **条件覆盖**：每个原子条件的真/假取值
- **MC/DC 覆盖**：按标准独立性判据校验每个条件是否被证明可独立影响决策

---

## 需求追踪

### 需求导入

支持 `YAML` / `JSON` / `CSV` / `Excel(.xlsx)` / `Markdown` / `Word(.docx)`，字段别名自动识别（`id`/`requirement_id`/`req_id`、`title`/`summary`/`name` 等）。

```yaml
requirements:
  - id: REQ-001
    title: "compute must reject a null output pointer"
    description: "The compute function validates the output pointer."
    priority: high
    status: approved
    tags: [compute, pointer]
    metadata:
      function: compute
```

### 追踪矩阵

自动建立四类关联：

- **测试 ↔ 需求**：显式 `requirement_ids`、被测函数名与需求标题/标签的词元匹配、需求描述中提及测试名
- **代码 ↔ 需求**：函数名/文件名匹配（支持命名空间与类方法）
- **缺陷 ↔ 需求**：缺陷所在函数与需求匹配

```bash
sast trace examples/sample_project
```

```
traceability matrix
  requirements : 6
  coverage     : 83.3%
  uncovered    : 1
    REQ-006 greet must report failures instead of throwing
```

输出 `traceability.csv` / `traceability.html` / `traceability.json`。

---

## 报告与集成

| 格式 | 说明 |
| --- | --- |
| `html` | 自包含交互式看板（严重度筛选、类别/规则过滤、代码片段、数据流路径） |
| `json` | 结构化结果 + 摘要 + 健康分 |
| `sarif` | SARIF 2.1.0，可直接被 GitHub Code Scanning / GitLab 导入 |
| `xml` | 供外部平台消费 |

### 基线与增量

```bash
sast baseline create          # 记录当前全部问题为基线
sast analyze . --baseline     # 之后只报新增问题
sast baseline diff            # 查看新增/已修复
sast changes                  # 展示 Git 变更影响范围
```

增量分析结合 `git diff` 与 `#include` 依赖图，计算真正需要重新分析的最小文件集合。

### CI 集成

```yaml
# .github/workflows/sast.yml
name: codeshield
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e .
      - run: sast analyze . -f sarif -f html
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sast-report/report.sarif
```

退出码遵循 `fail_on` 配置，可直接作为流水线门禁。

---

## Web 看板与桌面端

### Web（FastAPI）

`sast serve <project>` 后可用接口：

```
GET  /                      看板首页
GET  /api/rules             规则清单
POST /api/analyze           执行分析
POST /api/test              执行单元测试
GET  /api/results/{id}      分析结果
GET  /api/results/{id}/violations?severity=&category=&rule=&q=
GET  /api/test/{id}         测试结果
GET  /api/coverage/{id}     覆盖率报告
GET  /api/traceability      追踪矩阵
GET  /api/report/{id}/{fmt} 报告下载
```

### 桌面端（PySide6）

`sast gui <project>` 提供：工程路径选择、规则树（可勾选启停）、违规列表（按严重度着色、支持排序）、详情面板、覆盖率仪表盘、状态栏质量门禁提示。

---

## 架构说明

```
sast/
├── core/           领域模型、配置、基线
│   ├── models.py      Severity / Violation / AnalysisResult
│   ├── config.py      AnalysisConfig / Project
│   └── baseline.py    基线（已知问题接受机制）
├── lexer/          C/C++ 词法分析（预处理指令感知）
├── ast/            AST 定义 + 递归下降语法分析
├── analysis/       语义层：符号表、作用域、度量、值域分析、包含图
├── rules/          规则引擎 + 内置规则包
│   ├── base.py        Rule 基类与全局注册表
│   ├── engine.py      规则调度、抑制、质量门禁
│   └── builtin/       security.py / quality.py / standards.py / loops.py
├── testing/        单元测试与覆盖率
│   ├── interpreter.py 纯 Python C 解释器
│   ├── native.py      gcc/clang + gcov 流水线
│   ├── coverage.py    语句/分支/条件/MC-DC 覆盖率模型
│   └── runtime.py     测试运行器
├── traceability/   需求导入、追踪矩阵、矩阵报告
├── report/         HTML / JSON / SARIF / XML 渲染器
├── server/         FastAPI Web 服务
├── gui/            PySide6 桌面客户端
├── cli.py          命令行入口
└── benchmarks/     基准语料与测量工具
```

**分析链路**：`Lexer → Parser → AST → SymbolTable → FileContext → RuleEngine → AnalysisResult → Report`

前端完全自研，不依赖任何第三方 C/C++ 解析库。

---

## 开发与扩展

```bash
pip install -e ".[dev]"
python -m pytest -q          # 110+ 用例
```

新增规则只需继承 `Rule` 并用 `@register` 注册，规则引擎会自动发现并纳入报告、规则清单与 Web 界面。

### 测试覆盖范围

```
tests/test_lexer.py         词法分析：注释、宏、字面量、运算符、行列号
tests/test_parser.py        语法分析：声明、类、枚举、模板、控制流、C++ 特性
tests/test_scope.py         符号表：作用域嵌套、遮蔽、数组长度、类型尺寸
tests/test_rules.py         规则：注册表完整性、触发、阈值配置、行内抑制
tests/test_loop_rules.py    循环终止：值域分析、恒真条件、死循环、无符号回绕
tests/test_standards.py     MISRA C:2012：条款实现与误报检查
tests/test_reports.py       报告：JSON/SARIF/XML 合法性与 HTML 内容
tests/test_testing.py       测试：解释器执行、断言、覆盖率、套件发现
tests/test_traceability.py  追踪：多格式导入、矩阵、缺口、报告
tests/test_cli.py           CLI：各子命令、基线、增量、配置
tests/test_benchmarks.py    基准：召回率不下降、基线稳定、吞吐不退化
tests/test_benchmark_tools.py 横向对比：分类法一致性、各引擎可用性
tests/test_fixtures.py      夹具完整性：示例工程与语料的校验和
```

---

## 许可证

Apache License 2.0
