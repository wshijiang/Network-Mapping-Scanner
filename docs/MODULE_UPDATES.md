# 模块化执行与热更新

本指南描述当前扫描端实现。设计演进与控制端规划见 [详细设计](MODULAR_HOT_UPDATE_DESIGN.md)。

## 实现范围

启用后，masscan、zgrab2、DNS 和 Nuclei 阶段通过独立 `scanner-worker` 进程执行。Agent 继续独占身份、租约、检查点和结果上传。模块通信采用继承的 stdin/stdout 管道，4 字节大端长度 + JSON；日志只写 stderr，不开放本地监听端口。

同一 Worker 可实现四种 stage，但每个发布包可只更新一个 stage。内容寻址包可以包含不同构建版本的 Worker 与外部引擎；后续任务按该 stage 的映射使用新构建，因此升级解析器、探测策略和 DNS 实现不需要重启 Agent。

保持单活动任务、plan v1、现有四类 observation、结果上传协议 3 及 500 条/8 MiB 的批次限制。模块状态位于独立 schema 1 数据库，当前主状态库为 schema 4（含注册凭据摘要）；Worker 升级不迁移主状态库。

## IPC 3 兼容边界

DNS、加密 DNS、工业主动/UDP 被动服务识别将任务参数传递给 Worker，本版本使用 IPC 3，旧 IPC 1/2 Worker 与 manifest 会被拒绝，避免报告成功却未执行所选协议。TCP plan 保持 v1，显式 UDP profile 使用 v2，结果上传仍为协议 3，SQLite schema 不变。

已启用模块的部署应暂停新任务分配、排空旧 generation 的活动任务/检查点，再升级 Agent、Worker 和完整 IPC 3 模块包，确认活动环境预检成功后恢复。不要混用 IPC 1/2/3 或删除旧 pin、状态库、待上传数据来完成升级；需要回退时也应先排空并恢复完整配套版本。仅上传已归档结果不需要重跑 Worker。

## 构建与启用

```sh
cargo build --locked --release --bins
```

会生成 `scanner-rs`、`scanner-worker` 和用于离线制品制作的 `scanner-package`。发布压缩包包含这三个程序。

首次启用前排空旧任务与检查点。在原配置增加：

```toml
[modules]
enabled = true
directory = "/var/lib/network-mapping-scanner/modules"
state_database = "/var/lib/network-mapping-scanner/modules.sqlite3"
worker_path = "/opt/network-mapping-scanner/scanner-worker"
trusted_keys = "/etc/network-mapping-scanner/trusted-update-keys.json"
cancel_grace_seconds = 5
stage_timeout_seconds = 86400
auto_rollback = true
```

默认 `enabled=false`，旧配置继续使用原有执行方式。首次启用自动把本地 Worker、启用的引擎和模板复制到不可变初始版本；此操作信任管理员配置的本地文件。端口引擎为必需，启用其他阶段时必须已安装相应依赖。模板目录拒绝符号链接和特殊文件。

masscan 所需权限由节点部署决定。复制文件不会保留原文件的 capabilities；如果原部署仅依赖引擎文件 capabilities，应为受控 Worker/服务重新安排相应权限后启用。当前进程隔离提供故障隔离；它不是隔离恶意签名插件的安全沙箱。

Agent 和维护命令必须使用相同配置、工作目录和文件账号。Worker 的环境变量被清理，并使用独立临时 HOME/TMPDIR；它不接收节点运行令牌。引擎路径固定为版本目录中的绝对路径。

## 制作签名发布包

在可信构建机器生成签名密钥，私钥不放到扫描节点，不提交到 Git：

```sh
scanner-package keygen --private release.pkcs8 --public trusted-update-keys.json --key-id release-2026
```

将公钥 JSON 部署到扫描端配置的 `trusted_keys`。已有密钥文件不会被覆盖；公钥 JSON 为 `key_id -> 32 字节公钥十六进制`，可由管理员维护多把可信公钥。

目录发布包示例：

```text
service-release/
  manifest.json
  manifest.sig
  bin/scanner-worker
  bin/zgrab2
```

先构建新的 Worker，复制新的引擎，再编写 manifest。`files` 的摘要和大小可以先使用占位值，签名工具会根据真实文件更新。

```json
{
  "schema": 1,
  "ipc_version": 3,
  "release_id": "service-2026-10-13-01",
  "revision": 2,
  "target": "x86_64-unknown-linux-gnu",
  "files": [
    {"path": "bin/scanner-worker", "sha256": "", "size": 0, "executable": true},
    {"path": "bin/zgrab2", "sha256": "", "size": 0, "executable": true}
  ],
  "modules": {
    "service_detection": {
      "worker": "bin/scanner-worker",
      "engine": "bin/zgrab2",
      "templates": null
    }
  }
}
```

```sh
scanner-package sign --bundle service-release --private release.pkcs8 --key-id release-2026
```

revision 必须大于节点当前 revision；初始环境为 1。手动回滚也会递增 revision，后续发布需要继续使用更大的 revision。相同 manifest 的重复激活是幂等操作，不重复生成环境。

合法模块键为 `port_discovery`、`service_detection`、`dns_lookup`、`vulnerability_detection`。非 DNS 模块需要引擎路径；漏洞模块需要模板目录，该目录下所有文件必须列入 `files`。Nuclei 仍启用 unsigned-template 禁用、更新检查禁用和现有模板筛选约束；包签名不能替代 Nuclei 模板签名。

单包上限为 512 MiB、10000 个文件、2 MiB 原始 manifest。路径必须为包内相对路径；拒绝目录逃逸、链接、重复与冲突路径。引擎和 Worker 必须标记 executable。target 与当前节点架构匹配，激活前执行 Worker 握手预检；真实引擎及模板的功能兼容性还应在构建环境中验证。

## 在线激活、状态、回滚与清理

Agent 运行时：

```sh
scanner-rs --config /etc/network-mapping-scanner/config.toml module apply --bundle /srv/service-release
scanner-rs --config /etc/network-mapping-scanner/config.toml module status
scanner-rs --config /etc/network-mapping-scanner/config.toml module rollback --generation 1
scanner-rs --config /etc/network-mapping-scanner/config.toml module gc
```

写操作返回 request_id，表示已进入本地管理 inbox。**排队成功不等于激活成功**。后台 Agent 验签、复制、预检并处理命令，在 `modules/requests/<request_id>.result` 写入 success/error 和当前环境。Agent 不在线时命令保持排队，下次启动后处理。`status` 在线读取状态文件；文件可能反映最近一次更新周期，离线时可读取持久化当前环境。

文件准备和哈希在 blocking pool 执行，下载和更新使用独立后台任务，不在心跳请求链路执行。环境激活通过 SQLite 事务提交完整映射。进程在提交后退出，下次启动按数据库指针恢复。

每个任务保存其环境、真实有效配置及参数摘要；重试和重启继续使用该绑定。发布期间远程参数变化只影响新任务。服务识别块结果由 Agent 落盘后 ACK；Worker 未获 ACK 不继续下一块。租约丢失或取消会停止 Worker 和它的引擎进程组。

已进入上传队列的结果不经过新 Worker，不重新解析、去重或重排。任务 pin 在上传终态/归档后释放；失败扫描 pin 保守保留，避免服务端恢复任务时丢版本。GC 保留每个服务端最近两个环境、当前环境以及全部任务 pin 引用的包。旧失败任务 pin 尚无自动服务端对账回收，可能占用磁盘；不要手动删除其版本目录。

回滚生成新的 generation，后续任务使用历史映射；正在运行或恢复的任务继续原映射。原签名键被移除或包内容变更时，回滚预检会拒绝。

auto_rollback 启用时，同一 generation/stage 连续三次 Worker 传输、协议、启动或硬容量故障触发向前一环境回滚；成功的同阶段执行重置计数。正常目标失败、Worker 结构化业务失败、partial、服务端取消和租约丢失不计入该阈值。新环境的既有任务仍使用其 pin；故障任务受现有三次恢复上限约束，自动回滚不混合检查点。无历史环境或历史预检失败时保留当前状态并报告错误。

## 可选远程发布 feed

无需修改现有服务端即可通过独立 HTTPS 制品服务分发：

```toml
desired_url = "https://updates.example.com/scanner/desired.json"
```

每 60 秒读取以下 JSON：

```json
{
  "manifest": "<manifest.json 完整原始文本>",
  "signature": {"key_id": "release-2026", "signature": "<64字节签名十六进制>"},
  "artifact_base_url": "https://updates.example.com/releases/service-2026-10-13-01/"
}
```

制品按 manifest 中的路径下载，例如 `bin/scanner-worker`。下载源必须与配置 feed 相同 HTTPS origin；禁用重定向、不附加 scanner runtime_token，逐文件限制大小并核对最终摘要。网络失败保持当前可用环境，下一周期重试。

心跳增加可选 module_state，包含发布、generation、模块摘要和活动任务 generation。原 scan_capabilities 根据当前运行配置与可用模块生成，字段值仍使用现有四类 stage/profile，旧服务端可以继续接收。控制台发布管理、服务端专用制品 API、任意新扫描阶段及跨节点灰度尚属于后续配套工作；本次扫描端提供本地管理及 HTTPS feed。

## Agent 升级与验证

热更新对象为 Worker、外部引擎和模板；Agent 本身仍需排空任务后由部署工具受控重启。首次从旧版迁移，以及回退到不理解模块 pin 的旧扫描端，均应排空任务；主 DB schema 相同也不代表可任意回退。Agent 的 schema 兼容性与完整备份要求见[部署指南](DEPLOYMENT.md#升级与恢复)。

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --locked --release --bins
```

测试使用固定假引擎与临时 SQLite。新增检查涵盖签名、路径与帧限制、任务绑定跨配置/发布/重启、回滚、GC、真实 Worker 管道、分块 ACK 和运行中取消，无需扫描真实目标。

## 与主分支配置检查和 Masscan 参数的整合

共享库声明配置检查模块，Agent 将启动时的配置检查快照附带到心跳的
`local_config_check` 字段。公开配置字段清单由
`python3 scripts/update-config-fields.py` 更新，必须与配置模板一起维护。

原生扫描和 Worker 均使用任务运行快照中的 Masscan 输出模式、等待时间和
最长运行时间。模块任务的持久化 pin 同时保存这些参数；重启和后续配置变化
不会改变既有任务。旧快照缺少该字段时使用默认参数，默认参数不增加快照
序列化字段，保持旧任务的指纹。非模块任务仅在非默认参数时扩展缓存键。
Worker 请求缺少 Masscan 配置时仍使用默认值；使用非默认参数时应部署本次
更新后的 Worker。

Docker 构建上下文包含真实进程集成测试，并构建和安装 `scanner-rs`、
`scanner-worker`、`scanner-package` 三个程序。Worker 位于 Agent 同目录，
可由默认的相邻程序查找逻辑定位。

本次本地验证：全目标编译、格式检查、严格 Clippy、164 项 Rust 测试、
28 项 Docker 发布契约测试及 Cargo Chef 0.1.78 的规划/虚拟工程生成均通过。
完整多架构 Docker 镜像构建由 GitHub Actions 验证。
