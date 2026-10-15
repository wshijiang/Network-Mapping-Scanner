# 扫描端部署指南

[项目首页](../README.md) · [文档中心](README.md) · [Docker 部署](DOCKER.md) · [配置与使用](USAGE.md)

本文面向 Linux，覆盖部署选型、原生安装、首次注册、systemd 托管、升级与验收。先按[服务端部署指南](https://github.com/wshijiang/network-mapping/blob/main/docs/DEPLOYMENT.md)完成 PG、ES、服务端和控制台，再部署扫描节点。

[部署方式](#部署方式) · [准备网络与工具](#准备网络与工具) · [原生安装](#原生安装) · [配置](#配置) · [注册与首次运行](#注册与首次运行) · [systemd 托管](#systemd-托管) · [升级与恢复](#升级与恢复) · [验收与排障](#验收与排障)

## 部署方式

| 方式 | 适用场景 | 注意事项 |
| --- | --- | --- |
| 已发布镜像 + Compose | Linux Docker Engine，AMD64/ARM64 | 已包含 masscan、zgrab2、Nuclei 和官方模板；使用 host 网络及 NET_RAW，见 [Docker 指南](DOCKER.md) |
| 发布归档 + systemd | 直接运行二进制、独立维护引擎 | 归档包含三个 Rust 程序和配置文档，**不包含** masscan、zgrab2、Nuclei 或模板 |
| 源码构建 + systemd | 开发或自定义构建 | Rust edition 2024；构建后仍需安装引擎和配置服务 |

生产固定镜像 digest 或归档校验和，记录扫描端、服务端及引擎/模板版本。两端版本号独立，不要求相同；结果协议、SQLite schema 和模块包需要兼容。

## 准备网络与工具

1. 在节点使用实际域名访问服务端，例如 `https://server.example.com:9999/login`，确认 DNS、路由、证书链和主机名校验通过。`scanner.c_server` 只填主机名/IP，不填 `https://`、端口或路径。
2. 扫描端主动连接服务端 HTTPS API，无需直接访问 PG/ES，也无需为扫描端发布入站 API 端口。代理需保留 `/api/` 路径并允许 8 MiB 结果批次和 4 MiB 诊断分块；服务端通用请求上限默认 64 MiB。
3. 确认到授权目标网段的接口、路由和地址族可用。host 网络不自动提供 IPv6 路由；公网出口探测成功也不保证目标网段可达。
4. 原生端口扫描节点安装官方 masscan，填写绝对路径并使用 `standard_list`；服务识别需 zgrab2。Nuclei 默认关闭，启用前准备工具与经审核的签名模板，见 [Nuclei 指南](NUCLEI.md)。Docker 固定的工具提交可参考[第三方工具说明](../docker/THIRD_PARTY.md)。

私有 CA 在 Debian/Ubuntu 节点可由管理员安装：

```sh
sudo install -m 0644 /path/to/private-root-ca.crt /usr/local/share/ca-certificates/network-mapping-ca.crt
sudo update-ca-certificates
curl --fail --show-error --silent https://server.example.com:9999/login -o /dev/null
```

将示例 CA 来源、域名和端口替换为实际值。客户端只需要 CA 证书，不需要服务端私钥。保留 `verify_tls = true`；Docker 的信任链需要按其指南挂载到容器，宿主机安装 CA 不会自动进入容器。

## 原生安装

### 获取二进制

发布归档与同名 `.tar.gz.sha256` 放在同一目录，先执行 `sha256sum --check <归档文件名>.sha256`，再解压并检查 `BUILD-INFO`。GNU/musl 和 AMD64/ARM64 目标按实际系统选择；GNU 归档在 Debian 12 构建并检查 GLIBC ≤ 2.36，仍需目标系统提供匹配的运行库和可信 CA。musl 扫描程序不替代外部引擎的运行依赖。

源码构建在扫描端仓库运行：

```sh
cargo build --locked --release --bins
```

编译依赖以所选版本 Dockerfile/CI 为准，包括 C/C++ 工具、CMake、OpenSSL 开发库和 pkg-config。源码产物位于 `target/release/`；归档产物位于解压目录根部。

### 安装与目录

示例采用与容器一致的 root + NET_RAW 运行方式，以便 masscan 子进程使用原始套接字。限制在可信、专用扫描节点使用；仅给主程序 `setcap` 再改为普通用户并不能保证权限传给 masscan，应单独验证整个子进程链路。

```sh
sudo install -d -o root -g root -m 0755 /opt/network-mapping-scanner
sudo install -d -o root -g root -m 0700 /etc/network-mapping-scanner /var/lib/network-mapping-scanner
sudo install -d -o root -g root -m 0750 /var/log/network-mapping-scanner
```

从源码仓库安装：

```sh
sudo install -m 0755 target/release/scanner-rs target/release/scanner-worker target/release/scanner-package /opt/network-mapping-scanner/
sudo install -m 0600 config.toml /etc/network-mapping-scanner/config.toml
```

使用发布归档时，源文件分别换成解压目录中的 `scanner-rs`、`scanner-worker`、`scanner-package`、`config.example.toml`。仅首次安装复制配置，升级时保留已配置文件。

```text
/opt/network-mapping-scanner/          程序与受控引擎，可按实际路径配置
/etc/network-mapping-scanner/
└── config.toml                      本地部署参数
/var/lib/network-mapping-scanner/
├── scanner-state.sqlite3            身份、运行令牌、任务与上传状态
├── scanner-state.sqlite3-wal/-shm    SQLite 运行时辅助文件（若存在）
├── scanner-state.diagnostics.sqlite3 诊断队列及关联锁文件
├── scanner-state.diagnostics-spool/ 诊断快照
└── scanner-state.json               仅作为旧 JSON 状态的导入来源
/var/log/network-mapping-scanner/    每日 JSON 日志
```

**每个节点使用独立的数据目录与身份。** 保留整个状态目录，不要只挂载/复制单个 SQLite 文件，不要将同一份已注册数据库克隆给多个节点。模块模式另有版本目录、状态库和可信更新公钥，需要按[模块操作指南](MODULE_UPDATES.md)安装与备份。

## 配置

编辑已复制的完整 TOML，替换相应字段，不要把下列片段作为完整配置或重复添加同名段：

```toml
[scanner]
c_server = "server.example.com"
c_port = 9999
rate = 1000
verify_tls = true
scanner_path = "/usr/local/bin/masscan"
masscan_output_mode = "standard_list"
masscan_wait_seconds = 10
masscan_max_runtime_seconds = 86400
scanner_id = ""
runtime_token = ""

[upload]
endpoint = "https://server.example.com:9999/api/scanner/result"

[service_detection]
enabled = true
required = false
zgrab_path = "/usr/local/bin/zgrab2"
senders = 20
server_rate_limit = 10

[nuclei]
enabled = false
```

仓库/归档模板中的 `scanner_path = "./a"`、高发包速率、示例服务端和上传 URL 不适合直接上线。使用官方 masscan 时必须显式选择 `standard_list`，否则保留旧兼容模式。先以低速验收，再按带宽、目标承受能力和节点资源调整速率及并发。

| 项目 | 当前行为 |
| --- | --- |
| 文件配置 | 默认 `--config-source file`；`--config` 只选择文件，不改变工作目录，也不合并 `NM__…` |
| 上传地址 | **文件模式必须单独填写** `upload.endpoint`，修改 `c_server/c_port` 不会同步修改它；env 模式留空时才自动生成 |
| 相对路径 | 引擎、模板、模块及 CLI 数据/日志路径按进程工作目录解析；建议使用绝对路径 |
| 身份 | 新注册写入 SQLite；TOML 中的 `scanner_id/runtime_token` 只用于旧身份迁移，首次安装保持空值 |
| 远程配置 | 按任务边界应用；不能开启本地禁用的引擎，不能突破本地 `scanner.rate` 上限 |

首次升级若 TOML 含旧身份，程序先写入 SQLite，再尝试清除旧字段；只读文件无法改写时会警告，需管理员清除明文旧值。配置检查、字段类型与缺省提示见[启动配置检查](CONFIG_CHECK.md)。

## 注册与首次运行

1. 在服务端控制台创建扫描器，取得扫描器 ID 和一次性注册 Token。
2. 确认该节点没有正在运行的进程，使用将来相同的配置、数据库和日志路径注册：

```sh
sudo /opt/network-mapping-scanner/scanner-rs \
  --config /etc/network-mapping-scanner/config.toml \
  --database /var/lib/network-mapping-scanner/scanner-state.sqlite3 \
  --state-file /var/lib/network-mapping-scanner/scanner-state.json \
  --log-directory /var/log/network-mapping-scanner \
  --id '<控制台返回的ID>' --token '<一次性注册Token>'
```

**显式 `--id/--token` 注册成功后退出，不会进入扫描循环。** 凭据保存后，用相同路径去掉这两个参数启动：

```sh
cd /var/lib/network-mapping-scanner
sudo /opt/network-mapping-scanner/scanner-rs \
  --config /etc/network-mapping-scanner/config.toml \
  --database /var/lib/network-mapping-scanner/scanner-state.sqlite3 \
  --state-file /var/lib/network-mapping-scanner/scanner-state.json \
  --log-directory /var/log/network-mapping-scanner
```

注册 Token 仅在首次注册或重新签发后使用，避免留在脚本、unit 或长期命令历史中。若服务端已消耗 Token 而响应/本地保存失败，需要重新签发；删除 SQLite 不会恢复一次性 Token。

控制台确认心跳和引擎能力正常后，对一个已授权目标执行任务。前台使用 Ctrl+C 正常退出，再启用 systemd，避免两个进程同时使用状态库。环境模式自动注册后会继续运行，详见 [Docker 注册流程](DOCKER.md#首次注册与运行)。

## systemd 托管

下面 unit 与前述目录对应。默认未启用模块模式；若启用，`modules.worker_path` 等字段也须改为正确绝对路径。

```ini
# /etc/systemd/system/network-mapping-scanner.service
[Unit]
Description=Network Mapping Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/var/lib/network-mapping-scanner
ExecStart=/opt/network-mapping-scanner/scanner-rs --config /etc/network-mapping-scanner/config.toml --database /var/lib/network-mapping-scanner/scanner-state.sqlite3 --state-file /var/lib/network-mapping-scanner/scanner-state.json --log-directory /var/log/network-mapping-scanner
Environment=XDG_CONFIG_HOME=/var/lib/network-mapping-scanner/config
Environment=XDG_CACHE_HOME=/var/lib/network-mapping-scanner/cache
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
NoNewPrivileges=true
UMask=0077
KillSignal=SIGINT
KillMode=mixed
TimeoutStopSec=90
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

当前程序处理 SIGINT，systemd 默认 SIGTERM 不会进入相同退出流程，因此必须配置 `KillSignal=SIGINT`。`KillMode=mixed` 先通知主进程取消并回收子进程，超过停止时限才终止整个进程组。90 秒是初始停止预算，应观察现场停止时长。

将上述内容保存为 `/etc/systemd/system/network-mapping-scanner.service` 后执行：

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now network-mapping-scanner
sudo systemctl status network-mapping-scanner
sudo journalctl -u network-mapping-scanner -n 100 --no-pager
```

`network-online.target` 不保证远端 API 已就绪，短暂网络故障由重连逻辑处理。NET_RAW 是否足够还需对实际接口、引擎和任务验证；不要直接增加 privileged 或全部能力排障。引擎验证失败可能保持进程和心跳在线，但 `accepting_tasks=false`，不能只以 systemd 的 active 状态验收。

## 升级与恢复

1. 记录二进制、引擎、模板版本和当前配置；确认目标版本的结果协议及 SQLite 迁移。先升级并验收服务端，再对一个扫描节点试升级，通过后逐批扩展。
2. 暂停分配新任务，等待当前任务和上传完成；必要中断时保留检查点，下一次恢复仍需服务端确认租约/执行归属。
3. 执行 `sudo systemctl stop network-mapping-scanner` 并确认进程与引擎退出。**停机后**备份整个 `/var/lib/network-mapping-scanner`、配置、日志及启用的模块资源；运行中直接复制 SQLite 主文件不能保证与 WAL 一致。
4. 替换程序和计划升级的引擎，保留配置与数据目录。原生与 Docker 互迁也要先停止原进程，再迁移完整目录，并将 `--database` 指向原来的身份库；容器路径/权限按 [Docker 指南](DOCKER.md)调整。
5. 启动并检查身份恢复、心跳、引擎、能力、任务和上传。正常升级不重新注册，不清空缓存。任务完成后还应确认 `ResultUploadCompleted` 和服务端可查询结果。

当前 SQLite schema 为 4，旧库会自动升级；旧程序可能无法打开升级后的库。回滚必须核对兼容性，必要时停机恢复升级前完整备份；恢复旧状态可能重放上传或重做扫描，以服务端任务状态和幂等确认结果为准。[扫描恢复](recovery.md)与[缓存管理](CACHE_MANAGEMENT.md)说明了恢复边界。

身份按服务端 origin（主机/端口）隔离。更换入口、丢失数据目录或运行令牌失效时，先核对配置及旧身份，再由管理员签发新注册凭据。不要复制其他节点身份或反复使用已消费 Token。

## 验收与排障

### 上线验收

- 服务端 TLS 链与主机名可信，注册、心跳、任务领取和结果上传使用正确入口。
- 节点 `accepting_tasks=true`，所需地址族和 profile 可用；检查引擎版本及实际 raw-socket 权限。
- 对已知开放/关闭端口的授权目标完成一次端口任务，再按需验证服务识别、DNS、Nuclei。
- 日志出现 `ResultUploadCompleted`，控制台任务及资产搜索结果一致；后台投影尚未完成时继续观察发布状态。
- 正常停止并重启后沿用身份，待上传状态可恢复，未触发重复注册；验证受控断线后的续租/恢复行为。
- 数据、诊断与日志目录有持续写入空间；配置和状态备份可恢复，跨节点不共享身份。

### 常见问题

| 现象 | 检查与处理 |
| --- | --- |
| 注册成功后进程退出 | 显式 CLI 注册的正常行为；去掉 `--id/--token`，用相同数据库启动 |
| 重新启动要求注册 | 核对工作目录、`--database`、卷和服务端主机/端口，避免误用新空库 |
| 401 或 Token 已使用 | 核对运行身份；由管理员重新签发一次性注册 Token，保留原数据 |
| 注册/心跳正常但上传失败 | 文件模式单独核对 `upload.endpoint`，再检查代理请求体上限、TLS 和服务端日志 |
| 在线但无法领取任务 | 查看 `accepting_tasks`、启动引擎检查、维护状态、地址族/profile 与任务授权 |
| masscan 权限错误或零结果 | 检查 NET_RAW、实际引擎路径、标准输出模式、接口/路由和目标端口；版本命令可能非零退出，不能单凭其退出码判断工具损坏 |
| 状态库被锁定 | 检查另一进程/容器/维护命令是否仍使用同一目录，停止冲突进程后重试 |
| 重启后速率与文件不同 | 远程运行策略已缓存，按任务边界应用，受本地上限约束 |
| IPv6 不接任务 | 检查宿主机 IPv6 地址、路由和心跳能力，不靠关闭 TLS 校验处理 |
| 健康命令返回 0 但连接失败 | 当前 `--health-check` 可能记录远端错误后正常退出；结合输出与控制台心跳判断，不作为自动重启依据 |

优先查看本机 JSON 日志和 `journalctl`；身份确定前的配置/数据库错误不能可靠远程上报。远程日志与诊断队列的范围、容量和保留规则见[诊断指南](DIAGNOSTICS.md)。
