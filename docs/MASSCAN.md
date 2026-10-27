# masscan 标准输出适配与迁移

[返回使用指南](USAGE.md) · [文档索引](README.md)

扫描端直接调用官方 masscan，逐行读取机器可读的 list 输出，转换为现有端口 observation。
服务识别继续由 zgrab2 执行，上传协议和数据库结构不变。默认兼容旧二进制的启动参数；
切换官方二进制时显式启用 `standard_list`。

## 配置与启动参数

在现有配置的 `[scanner]` 中调整下列字段，保留已有身份、服务端和上传配置：

```toml
[scanner]
scanner_path = "/usr/bin/masscan"
masscan_output_mode = "standard_list"
masscan_wait_seconds = 10
masscan_max_runtime_seconds = 86400
```

此片段不能单独作为完整配置使用。二进制路径也可填写 `PATH` 中的命令名。
旧配置缺省路径仍是 `./a`；不会因升级自动切换二进制。

| 字段 | 默认值 | 行为 |
| --- | --- | --- |
| `masscan_output_mode` | `compatible` | 兼容旧格式；`standard_list` 启用严格官方格式 |
| `masscan_wait_seconds` | `10` | 范围 0-300 秒，仅标准模式传给 masscan 的 `--wait` |
| `masscan_max_runtime_seconds` | `86400` | 每次进程调用的总时限，范围 1-604800 秒，必须大于收包等待 |

上述字段是本地部署配置，远程运行配置只调整 masscan 速率。修改后重启扫描端生效。
24 小时以上的扫描需要提前增大总时限；该时限也包括读取输出和等待进程退出。
兼容模式保留旧二进制参数，因此其收包等待由旧二进制自身决定。

标准模式启动参数：

```text
masscan <targets> -p <ports> --rate <rate>
  --output-format list --output-filename -
  --nointeractive --open-only --wait <masscan_wait_seconds>
```

兼容模式仅传入目标、端口、速率及 `--output-format list --output-filename -`。
两种模式都不启用 banner 探测，不会因解析失败换格式重新发起扫描。

## 启动竞争处理

Linux 并行创建子进程时，暂时继承的写描述符可能引起 `Text file busy`（`ETXTBSY`）。
扫描器仅对此启动错误进行最多约 250 毫秒的异步重试；进程成功启动后不重跑扫描。
文件不存在、权限错误及持续占用仍返回错误；重试不会把损坏输出、非零退出或超时转成成功。
该启动策略与 Worker、zgrab2、Nuclei 共用。

## 输出契约

官方 list 示例：

```text
#masscan
open tcp 80 192.0.2.10 1720000000
open tcp 443 2001:db8::10 1720000001
# end
```

状态记录必须有五个字段。IP 必须是 IPv4 或 IPv6，端口必须能表示为 `u16`，
协议必须是已知 masscan 协议；开放 TCP/UDP 记录写入 observation，其余合法状态/协议过滤。
时间戳必须是非负 Unix 秒，转换为毫秒时检查溢出，不能缺省或回退成接收时间。
IP 规范化后，按 IP/协议/端口去重，并保留第一条标准记录的时间戳。

空行、空白和 `#` 注释正常忽略。允许 CRLF 和末尾没有换行的记录。
零结果时官方 masscan 可能不写头尾注释，所以空 stdout 配合正常退出也是合法结果。

兼容模式还接受：

```text
Discovered open port 80/tcp on 192.0.2.10
Discovered 80 tcp 192.0.2.10
COMPLETE
DONE_OK
```

这些端口记录使用接收时间；同一端点又出现标准记录时，标准时间戳优先。
完成标记仅作为提示，不停止读取、不直接决定成功。
其他兼容日志计入 `unknown_count` 并警告；已识别的数据行损坏、`ERROR`、JSON/XML 输出
在两种模式下都报错。标准模式拒绝控制台记录、旧标记及其他非预期 stdout。

成功需要 stdout/stderr 正常读完、进程退出码为 0，且没有解析错误、读取错误、取消或超时。
发现部分端口后失败不会把部分记录上传为完整任务；诊断保留已发现数量。
每行 stdout 最多 4096 字节；stderr 按块排空，诊断最多保留前 4096 字节并标记截断。
取消和总超时会终止并回收进程，没有结果行不会触发空闲超时。

格式依据：[官方 list 实现](https://github.com/robertdavidgraham/masscan/blob/master/src/out-text.c)、
[输出通道实现](https://github.com/robertdavidgraham/masscan/blob/master/src/output.c)及
[参数实现](https://github.com/robertdavidgraham/masscan/blob/master/src/main-conf.c)。
官方 `--version` 可能输出版本后以非零码退出，版本查询退出码不能用于判断扫描成功。

## 迁移验证与回滚

1. 记录现有扫描端提交、旧二进制路径，以及官方 masscan 的版本/来源提交和 SHA-256。
   保留旧二进制，核对新二进制的执行权限、发包权限、接口和路由配置。
2. 先升级扫描端，继续使用旧路径和 `compatible`。确认领取任务、取消、检查点恢复和上传正常。
3. 在受控目标验证官方二进制：已知开放/关闭端口、合法零结果、IPv4/IPv6（节点支持时）、
   权限失败，以及扫描取消。先比较规范化的端口集合，再检查观察时间，不能按发现顺序比较。
4. 等待当前任务和上传批次处理完，再在单个节点改路径和 `standard_list`，重启后检查
   `port_only`、服务识别流程和服务端入库展示。确认没有解析错误、异常超时或残留扫描进程。
5. 小批节点通过后再逐批切换。回滚时在任务边界恢复旧路径与 `compatible`，重启扫描端；
   保留 SQLite、身份和上传缓存，不重新注册或清空状态。

变更 masscan 非默认配置会改变扫描检查点标识，未完成扫描会重新执行；已生成上传批次保持原样。
因此应在任务边界切换。迁移不要求变更服务端/前端版本，也不涉及发布标签。

## 开发验证

从 `Network-Mapping-Scanner/` 执行：

```bash
cargo fmt --check
cargo clippy --all-targets
cargo test --locked -- --test-threads=4
cargo build --locked
```

单元测试和模拟子进程覆盖标准/旧格式、字段校验、去重、时间戳、零结果、尾部结果、
大 stderr、分段输出、非零退出、取消和 EOF 后进程不退出。
模拟程序不执行网络扫描，不能代替目标部署环境中的真实官方 masscan 联调。

测试限制并发为 4，避免同时创建和执行大量模拟脚本时出现临时文件占用及文件锁冲突。
