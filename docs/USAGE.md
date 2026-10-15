# 扫描器配置与使用指南

[返回项目首页](../README.md) · [文档索引](README.md)

容器镜像、首次注册与持久化见 [Docker 部署指南](DOCKER.md)。

本指南说明扫描引擎、运行配置、重连与网络探测。安装、首次注册与服务托管见[部署指南](DEPLOYMENT.md)，完整模块与参数参考见[维护文档](MAINTENANCE.md)。

[masscan 迁移](MASSCAN.md) · [服务识别](#服务识别) · [漏洞扫描](#漏洞扫描) · [扫描模式与目标](#扫描模式与目标) · [日志与诊断](#日志与诊断) · [远程运行配置](#远程运行配置) · [服务端自动重连](#服务端自动重连) · [IPv4/IPv6 自动探测](#ipv4ipv6-自动探测)

标准 masscan 的输出模式、参数与切换步骤见[masscan 标准输出适配与迁移](MASSCAN.md)。旧配置默认使用兼容模式，迁移时显式设置 `scanner.masscan_output_mode = "standard_list"`。

## 服务识别

普通扫描需要安装 `masscan`；服务识别还需要 `zgrab2`。masscan 只负责发现开放端口，zgrab2
按端口映射执行 SSH、HTTP(S)、TLS、邮件、数据库等应用层握手。可在配置中关闭服务识别，
以兼容只部署 masscan 的节点：

```toml
[service_detection]
enabled = true
required = false
strategy = "adaptive"
max_probes_per_endpoint = 8
confidence_threshold = 80
zgrab_path = "zgrab2"
senders = 200
server_rate_limit = 20
connect_timeout_seconds = 5
target_timeout_seconds = 15
max_result_bytes = 65536
```

- `required = false` 时，zgrab2 整体失败仍会上报 masscan 已发现的开放端口。
- `strategy = "standard"` 保持按端口选择单个协议的旧行为；`adaptive` 先执行
  Banner、TLS 和 HTTP(S) 探测，再为未识别端点执行预算内的协议回退；`exhaustive`
  会对每个 TCP 端点执行全部受支持模块。
- 465、990、993、995 和 8883 分别使用 SMTPS、FTPS、IMAPS、POP3S 和 MQTTS
  应用握手，不会只识别成通用 TLS；非标准端口确认存在 TLS 后会优先尝试这些安全协议。
- `max_probes_per_endpoint` 限制 `adaptive` 模式对每个端点建立的探测连接数；
  `confidence_threshold` 控制写入 `service` 字段所需的最低置信度。
- service observation 只保留最终服务关联的应用握手；应用模块已经包含 TLS 时不重复保存，
  HTTPS 则额外关联一份独立 TLS 握手。未识别端点不保存全部失败详情。
- 上传批次同时限制为最多 500 条 observation 和最多 8 MiB JSON，避免少量大握手产生超大请求。
- 未配置 `[service_detection]` 的旧配置默认关闭该功能。
- zgrab2 使用系统 TCP 栈，`senders` 和 `server_rate_limit` 应从较低值开始压测，不能照搬
  masscan 的发包速率。

## 漏洞扫描

漏洞扫描默认关闭。节点安装 Nuclei 后，应将 `templates_path` 指向经过审核并固定版本的模板
目录，再显式启用；扫描器禁用 Interactsh、未签名模板和自动更新，并限制并发、速率、运行时间
与结果数量。仅在已授权的资产范围内启用：

```toml
[nuclei]
enabled = true
path = "nuclei"
templates_path = "/opt/nuclei-templates/safe"
severities = ["medium", "high", "critical"]
rate_limit = 20
bulk_size = 5
concurrency = 5
timeout_seconds = 10
retries = 1
max_runtime_seconds = 1800
max_findings = 10000
max_result_bytes = 262144
port_fallback = true
```

Nuclei 按开放 TCP 端点分组串行扫描：已识别的 HTTP/HTTPS 使用 `-as -pt http`，
其他支持的服务按内置服务标签映射使用 `-tags`，并限定 TCP/JavaScript 模板；TLS 服务使用
`-tags ssl,tls -pt ssl`，不会当作 HTTPS。相同选择策略的目标合批，不同服务不会共享标签。
已识别服务优先于端口推测；`port_fallback = true` 允许服务未知时按常见非 Web 端口选择
SSH、FTP、SMTP、POP3、IMAP、SMB、MSSQL、MQTT、MySQL、RDP、PostgreSQL、VNC、Redis、MongoDB
模板，设为 `false` 则只扫描已识别的服务。隐式 TLS 应用目前仅覆盖 TLS 检查。
未知 Web 端口需要服务识别成功后才扫描；不支持的服务、UDP 和未知端口跳过并记录原因，
不会回退为全模板扫描。跳过或未识别 Web 技术不代表没有漏洞。

已在 Nuclei v3.11.1 核对参数。`templates_path` 同时作为 active template root 和显式模板目录，
防止 `-as` 额外加载用户默认模板库。该目录需包含自动扫描使用的 `tech`/`detect`/`favicon`
检测模板及所需服务标签。Web 批次使用模板条件保留这些指纹模板及配置严重级别的漏洞模板，
避免 `-severity medium,high,critical` 排除 info 指纹模板导致 `-as` 启动失败；上传结果仍严格
按 `severities` 筛选。裁剪模板时需验证自动识别覆盖。
没有匹配模板时不取消过滤重试；引擎错误按任务失败处理。总超时与结果上限覆盖所有批次，
结果按端点、模板、matcher 和匹配位置去重。映射集中在 `src/scan/engines/nuclei_selection.rs`。

Nuclei 只接收端口发现阶段产生的目标。上传结果不包含原始 HTTP 请求或响应，避免把敏感内容
写入扫描缓存和服务端。启用节点会在心跳中声明 `vulnerability_scan` 能力，只有这类节点会领取
漏洞扫描任务。

## 扫描模式与目标

控制端创建页提供“全部”“仅端口”“服务识别”“仅 DNS”四种模式。IP/CIDR 任务直接映射为
`vulnerability_scan`、`port_only` 或 `service_inventory`；域名的前三种模式由 DNS 节点先执行
`dns_records`，服务端再将授权的 A/AAAA 地址按 IPv4/IPv6 拆成对应 profile 的子任务。
“仅 DNS”只运行 DNS engine，不启动 masscan、zgrab2 或 Nuclei。
域名扫描目标必须至少包含两个由 `.` 分隔的标签，仅允许 ASCII 字母、数字和非首尾连字符；
每个标签最多 63 octets，完整 wire name 最多 255 octets（无末尾根点的点分形式最多 253 octets）。

完整的模板治理、参数语义、上线顺序和故障排查参见
[Nuclei 漏洞扫描部署与运维](NUCLEI.md)。

## 日志与诊断

运行时会将结构化 JSON 日志按天写入 `./logs/scanner.log.YYYY-MM-DD`，同时保留终端输出。可以使用 `--log-directory` 指定其他目录，使用 `--debug` 将终端和文件日志级别切换为 debug：

```sh
cargo run -- --config config.toml --log-directory /var/log/network-mapping-scanner --debug
```

相对日志目录以启动扫描器时的当前工作目录为基准。日志按 UTC 天轮转并保留最近 14 份，程序退出时会刷新尚未写入磁盘的日志。

升级后支持服务端从该固定目录远程采集快照、分块续传，并主动上报结构化错误。引擎启动检查失败时保留诊断通道而暂停领取任务。部署路径、独立持久化队列、容量限制和故障排查参见[扫描端远程诊断](DIAGNOSTICS.md)。

如需在扫描器停止后丢弃尚未上传的任务 ID、批次进度和本地扫描结果，使用 `cache clear`
维护命令；身份凭据默认保留。完整说明参见[扫描缓存管理](CACHE_MANAGEMENT.md)。

## 远程运行配置

管理员可从控制端扫描器配置页发布扫描速率和引擎运行参数；扫描器通过心跳获知版本并拉取，在任务边界应用，已执行的扫描保持原参数。本地禁用的引擎不能被远程开启，masscan 速率不超过本地 `scanner.rate`；二进制和模板路径仍由本地配置决定。合法远程配置按服务端缓存到 SQLite，重启后会恢复并重新套用本地限制。详细规则见[本地部署配置与远程运行配置](MAINTENANCE.md#本地部署配置与远程运行配置)。

## 服务端自动重连

扫描器启动后会先通过心跳确认服务端可用，再开始领取任务。DNS、建连、请求超时、HTTP
408/429 和 5xx 会触发带抖动的指数退避；连接恢复并成功发送心跳后会自动恢复领取任务和
结果上传。401 表示运行令牌失效，需要重新注册；403 或其他协议错误不会无限重试。

```toml
[scanner]
connect_timeout_seconds = 5
request_timeout_seconds = 15
reconnect_initial_delay_seconds = 1
reconnect_max_delay_seconds = 60
active_task_reconnect_max_delay_seconds = 10
lease_safety_margin_seconds = 10
```

活动任务通过心跳续租。短暂断线期间本地扫描可以继续，心跳会以较短退避间隔恢复；如果
服务端明确返回租约已丢失，或扫描端在租约到期前的安全窗口仍无法确认续租，当前
masscan/zgrab2 进程会被取消，过期结果不会上传。已经生成的上传批次在租约仍有效时使用
原有 `upload_id` 和 `batch_index` 重试，因此响应丢失不会造成重复入库。

扫描器身份、运行令牌、任务身份、观察、真实观察时间和下一批序号会持久化到
`./scanner-state.sqlite3`；可用 `--database` 指定其他路径。身份按目标服务端隔离，任务结果和
上传进度使用 SQLite 事务原子更新。进程或主机重启后会先恢复并上传待处理状态，再领取新任务。

升级时如果 TOML 中已有 `scanner_id` / `runtime_token`，扫描器会先导入数据库，再将旧字段
清空；如果存在旧的 `./scanner-state.json`，也会自动导入并改名为
`scanner-state.json.migrated`。`--state-file` 仅用于指定这一旧 JSON 的迁移来源。数据库文件
包含运行令牌，应位于持久化本地磁盘并限制访问权限；程序在 Unix 上会将其设置为 `0600`。

## IPv4/IPv6 自动探测

扫描器启动时会分别检查 IPv4 和 IPv6 路由，并绑定对应地址族查询公网 IP，此后按配置周期
刷新。路由状态、公网出口地址和失败原因通过心跳发送给服务端，服务端只会分配当前协议
可用的任务。

```toml
[network]
ipv4_enabled = true
ipv6_enabled = true
ipv4_probe_url = "https://api.ipify.org?format=json"
ipv6_probe_url = "https://api6.ipify.org?format=json"
probe_interval_seconds = 300
probe_timeout_seconds = 5
```

- `ipv4_enabled` / `ipv6_enabled` 可显式禁用某种协议。
- 扫描器优先访问服务端鉴权接口 `/api/scanner/network/public-ip`，请求携带运行 Token。
- 服务端接口不可用时回退到 `ipv4_probe_url` / `ipv6_probe_url`；备用接口不会收到运行 Token。
- 公网 IP 接口可以返回 `{"ip":"..."}`，也可以直接返回纯文本 IP。
- IPv4 探测必须返回 IPv4 地址，IPv6 探测必须返回 IPv6 地址。
- 本机无可用路由时会立即反映为该协议不可用，下个周期恢复路由后自动恢复。
- 公网 IP 接口查询失败只会使 `public_ip` 为空并记录原因，不会阻止扫描任务；该接口不是扫描链路的可用性依赖。
- 默认备用接口是第三方服务，回退时会获知扫描器出口 IP；有隐私或网络边界要求时应替换为自建接口或留空。
- 路由检查只证明操作系统能为该地址族选择源地址和路由，不代表任意私有网段都可达。

服务端下发的任务包含 `address_family`。扫描器执行前会再次检查本地最新状态；如果协议已
不可用，会先刷新心跳再拒绝任务，使服务端可以重新调度。

完整心跳格式、实现约束和故障排查参见
[系统维护文档](MAINTENANCE.md#网络协议自动探测)。
