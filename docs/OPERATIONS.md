# 安装与运行说明

## 1. 启动Web软件

```bash
cd /home/zyrv/RVFPA
python3 run.py serve --host 127.0.0.1 --port 8765 --workspace workspace
```

服务启动后访问`http://127.0.0.1:8765`。首次启动会在工作区创建SQLite数据库和项目文件目录。

不要将工作区指向源码目录外无法长期保存的位置。需要迁移时，应完整复制数据库和项目文件目录。

## 2. 使用流程

1. 新建固件分析项目并填写项目说明。
2. 设置FLASH、RAM或其他内存区域。
3. 导入一个RISC-V ELF，可同时导入同名GNU MAP。
4. 查看资源、段、符号、指令、函数和发布检查结果。
5. 导入后续版本，在版本对比页选择基线和目标版本。
6. 从报告中心导出HTML、JSON或CSV材料。

界面中的“导入示例”会导入仓库自带的两个演示固件，适合验证软件是否正常工作。

## 3. 工具链发现

软件依次尝试常见的RISC-V objdump命令，并记录最终使用的工具和版本。可在系统`PATH`中配置交叉工具链。未发现兼容工具时，软件使用内置解码器，分析结果中会保留对应诊断。

检查本机工具：

```bash
which riscv64-linux-gnu-gcc
which riscv64-linux-gnu-objdump
which readelf
```

## 4. 常见问题

### 提示不是RISC-V ELF

确认输入是完成链接的RISC-V ELF，而不是目标文件列表、HEX、BIN或主机架构程序。ELF扩展名不是必要条件，机器类型才是判断依据。

### 没有函数画像

固件可能已经删除符号表，或函数符号大小为零。建议保留一个带符号的内部分析版本，另行生成交付用strip镜像。

### 区域占用不正确

优先提供与ELF同次链接生成的MAP文件，并检查MAP中的Memory Configuration。也可以在项目设置中填写与链接脚本一致的区域。

### 指令数量为零

检查ELF是否有带执行属性且非空的节区。如果外部objdump不可用，查看发布检查和诊断中是否记录了解码问题。

### 版本对比结果过多

编译选项、链接顺序或LTO可能造成大量符号变化。应保持两版工具链和构建参数一致，再判断业务代码的真实变化。

## 5. 备份

停止服务后复制整个工作区即可完成一致性备份。默认工作区为项目根目录下的`workspace/`，该目录已加入Git忽略规则，不应提交真实固件。

## 6. 验收命令

```bash
python3 examples/build_examples.py
python3 -m compileall -q rvfpa tests
python3 -m unittest discover -v
python3 run.py analyze examples/build/firmware_v1.elf --map examples/build/firmware_v1.map
python3 run.py batch examples/build
python3 run.py policy examples/build/firmware_v1.elf --map examples/build/firmware_v1.map --policy examples/release_policy.json
```

全部测试通过、批量分析无失败项、示例策略状态为`pass`时，说明核心分析路径可用。

