# RISC-V嵌入式固件资源画像与版本差异分析软件 V1.0

RVFPA（RISC-V Firmware Portrait Analyzer）是一套本地运行的RISC-V ELF固件静态分析软件。它面向嵌入式固件研发、版本交付和资源预算复核场景，将ELF、GNU链接MAP和链接脚本中的信息整理为资源画像，并对两个或多个固件版本进行可追溯的差异分析。

本项目不上传固件，不依赖云服务。后端和Web服务使用Python标准库，前端使用原生HTML、CSS和JavaScript。若系统安装了RISC-V `objdump`和`readelf`，软件会优先使用工具链结果；工具不可用时，内置机器码解码器仍可完成RV32/RV64基础指令与压缩指令画像。

## 主要功能

- 解析RISC-V ELF32/ELF64文件头、程序头、段、符号、Build ID、ABI和编译器注释。
- 解析GNU链接MAP中的内存区域、输入段、输出段、目标文件贡献、符号和警告。
- 解析GNU链接脚本的`MEMORY`、`ENTRY`、`OUTPUT_ARCH`、`REGION_ALIAS`和`PROVIDE`。
- 统计代码、只读数据、已初始化数据、BSS、调试信息、加载体积和运行时占用。
- 识别I/M/A/F/D/C/V/B/K等RISC-V指令扩展，并统计类别、助记符和压缩指令比例。
- 生成函数级指令量、分支数、调用关系、叶函数和估算复杂度画像。
- 提取ASCII与UTF-16固件字符串，识别诊断文本、路径、版本和敏感关键词线索。
- 分析段熵、零字节比例、可打印字符比例和异常高熵数据。
- 检查入口地址、段越界、区域重叠、RWX段、内存余量和反汇编覆盖情况。
- 对比版本间段、符号、区域、指令、扩展、文件体积和运行时内存变化。
- 批量发现目录中的ELF/MAP配对，并自动生成连续版本差异。
- 使用JSON发布策略验证体积预算、ABI、扩展、段、诊断、复杂度和字符串规则。
- 汇总RISC-V CSR访问、特权级、陷阱返回、栅栏和原子指令使用情况。
- 分析批量版本的资源增长方向、波动率、异常值和最新版本突变。
- 解析GCC `-fstack-usage`生成的`.su`文件并检查单函数栈预算。
- 生成包含输入哈希、构建身份、资源摘要和分析指纹的固件清单。
- 使用SQLite保存项目、固件版本、原始文件和压缩后的分析快照。
- 导出HTML、JSON以及段、符号、指令、函数和字符串CSV报告。

## 环境要求

- Linux，推荐Ubuntu 22.04或更高版本。
- Python 3.10或更高版本，当前开发验证环境为Python 3.12。
- 可选：GNU RISC-V交叉工具链，例如`riscv64-linux-gnu-objdump`。
- 构建仓库内示例固件时需要`riscv64-linux-gnu-gcc`。

软件本身没有第三方Python运行依赖。

## 快速开始

在项目根目录运行：

```bash
python3 run.py serve --host 127.0.0.1 --port 8765 --workspace workspace
```

浏览器打开：

```text
http://127.0.0.1:8765
```

首次进入后创建项目，再导入自己的RISC-V ELF和可选MAP文件。也可以点击界面中的示例导入功能，一次导入仓库内置的V1、V2固件。

## 构建示例固件

```bash
python3 examples/build_examples.py
```

输出文件位于`examples/build/`：

- `firmware_v1.elf`与`firmware_v1.map`
- `firmware_v2.elf`与`firmware_v2.map`

## 命令行用法

分析单个固件：

```bash
python3 run.py analyze examples/build/firmware_v1.elf \
  --map examples/build/firmware_v1.map
```

导出HTML报告：

```bash
python3 run.py analyze examples/build/firmware_v1.elf \
  --map examples/build/firmware_v1.map \
  --format html \
  --output workspace/firmware_v1.html
```

对比两个版本：

```bash
python3 run.py compare \
  examples/build/firmware_v1.elf \
  examples/build/firmware_v2.elf \
  --baseline-map examples/build/firmware_v1.map \
  --target-map examples/build/firmware_v2.map \
  --output workspace/version_diff.json
```

批量分析目录：

```bash
python3 run.py batch examples/build --output workspace/batch_result.json
```

解析链接脚本：

```bash
python3 run.py linker examples/linker.ld --output workspace/linker_memory.json
```

执行发布准入策略：

```bash
python3 run.py policy examples/build/firmware_v1.elf \
  --map examples/build/firmware_v1.map \
  --policy examples/release_policy.json \
  --output workspace/policy_result.json
```

策略全部通过时命令退出码为0，存在任一失败规则时退出码为1，输入或解析错误时退出码为2，便于接入构建脚本。

生成固件追溯清单：

```bash
python3 run.py manifest examples/build/firmware_v1.elf \
  --map examples/build/firmware_v1.map \
  --output workspace/firmware_manifest.json
```

分析GCC栈使用文件：

```bash
python3 run.py stack examples/stack_usage \
  --limit 256 \
  --output workspace/stack_usage.json
```

## 内存配置

界面创建项目时可以配置FLASH和RAM。命令行也可以通过`--memory`传入JSON：

```json
{
  "architecture": "auto",
  "regions": [
    {
      "name": "FLASH",
      "origin": "0x20000000",
      "length": "512K",
      "permissions": "rx",
      "description": "代码与只读数据"
    },
    {
      "name": "RAM",
      "origin": "0x80000000",
      "length": "256K",
      "permissions": "rwx",
      "description": "运行时数据与栈"
    }
  ]
}
```

如果提供的MAP文件包含`Memory Configuration`，且没有显式传入内存配置，软件默认优先采用MAP区域。

## 发布策略字段

示例见`examples/release_policy.json`。支持字段如下：

- `limits`：文件、加载、运行时、代码、只读数据、初始化数据、BSS、调试和元数据体积上限。
- `region_usage_percent`：按内存区域名称配置占用率上限。
- `allowed_abis`：允许的ABI，例如`lp64`、`ilp32d`。
- `required_extensions`与`forbidden_extensions`：必需或禁止的指令扩展。
- `required_sections`与`forbidden_sections`：支持通配符的段名规则。
- `max_diagnostics`：`error`、`warning`、`info`诊断数量上限。
- `max_decode_failure_percent`：指令分类失败率上限。
- `max_function_complexity`：函数估算复杂度上限。
- `forbidden_string_patterns`：不区分大小写的正则表达式列表。

## 测试

```bash
python3 -m compileall -q rvfpa tests
python3 -m unittest discover -v
find rvfpa/web -name '*.js' -print0 | xargs -0 -n1 node --check
```

当前仓库包含单元测试，覆盖ELF、MAP、链接脚本、原始机器码、资源分析、内容分析、发布检查、策略评估、系统指令、趋势、清单、栈使用、差异分析、批量分析和持久化。

## 目录结构

```text
RVFPA/
├── rvfpa/
│   ├── analyzers/       资源、指令、函数、内容、发布和策略分析
│   ├── parsers/         ELF、MAP、链接脚本和objdump文本解析
│   ├── services/        分析编排、版本差异、批处理、报告和存储
│   ├── web/             本地Web界面
│   ├── cli.py           命令行入口
│   ├── models.py        领域数据模型
│   └── webapi.py        HTTP接口与静态资源服务
├── examples/            两版真实可编译示例固件和发布策略
├── tests/               单元测试
├── docs/                架构、运行和软著整理说明
├── run.py               开发运行入口
└── pyproject.toml        Python项目配置
```

## 数据与安全边界

- Web服务默认仅监听`127.0.0.1`，不向局域网公开。
- 上传文件、SQLite数据库和报告均保存在指定工作区。
- 固件分析属于静态分析，不执行导入的ELF文件。
- 敏感关键词和高熵结果只是人工复核线索，不等同于漏洞结论。
- 函数复杂度是基于反汇编分支估算，不等同于源代码圈复杂度。


