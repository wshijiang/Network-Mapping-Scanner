# 扫描器配置与使用指南

[返回项目首页](../README.md) · [文档索引](README.md)

容器镜像、首次注册与持久化见 [Docker 部署指南](DOCKER.md)。

本指南说明扫描引擎、运行配置、重连与网络探测。安装、首次注册与服务托管见[部署指南](DEPLOYMENT.md)，完整模块与参数参考见[维护文档](MAINTENANCE.md)。

[masscan 迁移](MASSCAN.md) · [服务识别](#服务识别) · [漏洞扫描](#漏洞扫描) · [扫描模式与目标](#扫描模式与目标) · [日志与诊断](#日志与诊断) · [远程运行配置](#远程运行配置) · [服务端自动重连](#服务端自动重连) · [IPv4/IPv6 自动探测](#ipv4ipv6-自动探测)

标准 masscan 的输出模式、参数与切换步骤见[masscan 标准输出适配与迁移](MASSCAN.md)。旧配置默认使用兼容模式，迁移时显式设置 `scanner.masscan_output_mode = "standard_list"`。

## UDP 扩展状态

本批新增 DNS/NTP/STUN 库内核，但尚未开放 UDP 任务或 CLI 配置，现有服务任务仍只识别 TCP。服务端端点身份与能力协商完成后再接入，详见 [UDP 探测](UDP_DETECTION.md)。不要使用 U: 前缀绕过当前任务端口校验。

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
- `strategy = "standard"` 按端口选择应用握手，HTTPS 端口同时尝试 DoH；默认 `adaptive` 结合端口线索、
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

### DNS、加密 DNS、VNC 与工业协议

原生 TCP 识别支持 `dns`、`vnc`、`dot`、`doh`、`enip`、`s7`、`opcua`、`mqtt`、`mqtts`；`modbus` 使用固定版 zgrab2 模块。所有已实现 TCP 协议均属于自动识别候选，无需在创建页选择。端口映射覆盖 TCP/53、853、5900–5909、502、44818、102、4840、1883、8883 等；HTTPS 端口追加 DoH 确认。工业协议参与标准端口、adaptive 回退及 exhaustive 探测。Modbus 沿用指定 Unit ID 和有界响应校验，每个 zgrab2 进程使用随机请求 ID；关联的合法异常仍确认协议。MQTT/MQTTS 使用原生有界 CONNECT/CONNACK，支持 3.1.1/5.0 及合法认证拒绝。

Modbus 改由 zgrab2 执行后会遵守其 blocklist；旧版原生 Modbus 不受该列表约束。镜像包含上游默认列表，其中屏蔽 RFC 1918 私有地址，因此内网节点需要部署方按实际授权配置 zgrab2 blocklist。被阻止的目标不会识别为 Modbus，扫描器会记录 `ModbusTargetsBlocklisted` 警告。

TCP 默认省略或留空 `scan_plan.required_services`，使用完整自动识别策略；旧 API 的非空列表仍可限制探测范围。`service_probe_options` 无需选择协议即可提供 TLS 服务名、DoH 单一路径、额外公开 CA、Modbus Unit ID、S7 TSAP 和 MQTT 版本。TLS 默认验证证书并固定连接目标 IP，不重定向或绕过验证。非标准端口可能受节点探测预算和超时限制，自动识别不保证每次执行都尝试所有协议；HTTPS 成功后会在剩余预算内细分 DoH，合法 RFB 问候也可直接确认非标准端口的 VNC。

UDP 使用 plan v2 的 `udp_inventory`（DNS、EtherNet/IP UDP/44818、经典 BACnet/IP 单播），无需 masscan 命中。无有效响应不判定开放或关闭。当前每任务仅一种传输，不支持 UDP 域名后续任务。旧版本的 `udp_passive` 被动接收模式已移除，节点不再声明 `opcua_pubsub` / `enip_io` 协议能力。

节点声明协议能力及 `max_service_probes`；所选协议数不得超过节点预算。原生引擎共用累计期限、取消、限速及 ACK 检查点；UDP 限制最多 256 个地址、最多 32 个明确端口。

完整支持矩阵、任务示例、参数边界和配套服务端投影迁移见[服务协议识别与部署](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md)。Worker 必须配套 [IPC 3 模块包](MODULE_UPDATES.md)。

## RDP 识别与故障排查

服务识别使用固定的 zgrab2 最新主分支快照 `835aa53808aed88b4c3e017d623b374fb26dca95`（2026-10-22 UTC）。
截至 2026-10-27，官方最新 Release 仍为 v1.0.0；该旧版不包含 RDP，不能作为本版本的替代依赖。
镜像已固定完整 SHA；独立安装和模块包也应使用同一提交，并配套升级 Agent、Worker 和引擎。

RDP 交给 zgrab2 的 `rdp` 模块，默认端口 TCP/3389；显式选择 `rdp` 可探测自定义端口。
模块进行 X.224/RDP 协商，按服务端选择继续 TLS 证书采集及 CredSSP/NTLM Challenge 指纹采集，
不提交用户登录凭据、不建立桌面会话。证据 `source=zgrab2`，`selected_protocol`、`failure_code`
为上游字符串枚举，`negotiation_flags` 为对象，可选的 `tls`、`ntlm` 保留上游结构。
证书采集不代表证书可信；NTLM 系统版本字段不保证已被服务端投影为操作系统标签。

协商拒绝仍能确认 RDP；已协商 `ssl`/`hybrid`/`hybrid_ex` 后 TLS 或 NTLM 失败时，
节点仍保留 RDP 服务类型，同时在 `evidence[].status` 保留原始失败状态。
无协商证据的失败不识别为 RDP。旧式 Standard RDP 的识别遵循上游模块行为。
阶段期限、连接/目标超时、取消与限速继续生效；默认 adaptive 的 8 次预算不保证未知
非标准端口会尝试 RDP，需要确定执行时显式选择该协议。

出现 `could not find option group` 且涉及 `rdp`，先核对正在运行的 zgrab2 是否为上述提交。
外部引擎配置只包含本批使用的模块；升级时需同时替换模块包中的引擎，不能只替换 Agent。

原生 TCP 与主动 UDP 握手继续应用 `max_result_bytes`，清理 NUL 并标记截断。
超大 RDP 握手尽量保留协商字段及 `ntlm` 名称/版本字段；TLS 大字段可能被裁剪。
截断后仍可保留服务名，但详情可能缺失；需要完整证据时可提高允许的预算后重扫。

### 独立安装与兼容性验证

使用 Go 1.27.2（至少满足上游 go.mod 的 Go 1.26 要求）从固定提交构建：

```sh
git clone https://github.com/zmap/zgrab2.git
cd zgrab2
git checkout --detach 835aa53808aed88b4c3e017d623b374fb26dca95
go build -mod=readonly -trimpath -o zgrab2 ./cmd/zgrab2
./zgrab2 rdp --help
```

按照上游安装说明配置 blocklist，并将扫描器 `zgrab_path` 指向安装后的绝对路径。
源码维护者可从扫描器仓库执行下面的真实引擎测试；仅测试本机回环夹具，测试内部使用空 blocklist：

```sh
ZGRAB2_TEST_BINARY=/absolute/path/to/zgrab2 cargo test --locked --lib real_zgrab -- --ignored
```

测试验证所有外部模块的实际 INI 解析，以及自定义端口 RDP 协商拒绝、TLS 后续失败和结果保留。

## 操作系统特征采集

操作系统推断由服务端完成，节点继续使用已有原生/zgrab2 服务识别阶段，不增加扫描端口或探测
连接。选中的握手信息随 `ServiceObservation.data` 上传；普通 OpenSSH、nginx、SMB/RDP
连接成功等信息不足时，服务端会保留未知。

当证书或其他扩展使握手超出 `max_result_bytes` 时，节点会在同一 JSON 大小预算内尽量
保留 SSH 标识、HTTP Server 头和明确的系统字段，并标记 `evidence[].truncated`。
HTTP 仅裁剪正文而保留其余握手时，同样标记为截断。
截断记录不能代替完整证据；历史字段缺失时需重新执行服务识别。
查看结果、置信度及边界见服务端[操作系统识别说明](https://github.com/wshijiang/network-mapping/blob/main/docs/OS_DETECTION.md)。

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

扫描器启动后会先通过心跳确认服务端可用，再开始领取任务。DNS、建连、请求超时、心跳或任务
响应体传输中断、HTTP 408/429 和 5xx 会触发带抖动的指数退避；连接恢复并成功发送心跳后会
自动恢复领取任务和结果上传。完整但无法解析的响应属于协议错误，不按传输中断重试。401 表示
运行令牌失效，需要重新注册；403 或其他协议错误不会无限重试。

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

## 服务产品识别

扫描器继续上传 `http`、`https`、`tls`、`ssh` 等既有 `service` 协议结果及其原始观察。已有 Web 技术栈和旧 C2 指纹结果继续由配套服务端处理；本次为同一端点的已执行探测保留有预算的补充观察，供服务端生成通用的 `products[]` 与 `product_identification`。

当前产品规则支持 nginx、Apache HTTP Server、OpenSSH 的软件声明，以及 Cobalt Strike、AsyncRAT / DcRAT、Sliver Multiplayer 管理端和 QakBot 历史证书候选。扫描器负责采集与上传，产品匹配由服务端完成。基础补充证据保留和服务端本地规则分析不新增探测请求；另行启用 JARM 时才会增加后文说明的额外连接。

扫描器在选中服务握手之后，按 TLS、HTTP、HTTPS 顺序尽量保留每个模块的一份成功补充观察。补充证据总量最多两倍 `service_detection.max_result_bytes`，仍受既有 64 MiB 结果块限制；超预算省略的补充观察通过 `data.product_evidence_truncated=true` 标记。已自包含 TLS 日志的应用握手不重复保存独立 TLS 观察。失败 TLS 中可用的公开证书沿用原有保留策略。原协议名、置信度、探测计划、取消恢复及网页内容富化开关保持原义。

控制台「服务」列同时显示协议与产品。证书规则只形成疑似产品，不确认 C2 服务角色或恶意用途，不自动生成整个 IP 的恶意标签。这些本地证书与声明规则无需新增节点配置；旧扫描器保留的原始证据仍可使用，具体覆盖范围取决于当时保存的字段。产品查询、存量回填与 API 见[服务端使用说明](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md#服务产品识别)。

### Sliver 与 QakBot 产品候选

Sliver 与 QakBot 候选从服务端产品规则 v2 起支持（当前规则修订见配套服务端文档），复用本节描述的 TLS/HTTPS 公开证书，不需要增加节点参数、端口选择或请求。Sliver 的首批范围是默认 Multiplayer 多人管理端证书，不等于通用 mTLS 或植入体监听器识别。握手后续失败时，可用的叶证书字段沿用原有保留链路，协议选择仍可保持未知，不能把证书候选当作成功应用握手。

QakBot 基于公开研究中的历史证书主体/颁发者组合，结果为需复核的历史启发式候选。字段缺失、被裁剪、出现在证书链或 HTTPS 跳转目的站时不能据此归属源端口；不发送家族专属通信，也不依据端口号或空响应猜测家族。旧扫描器只要保存了所需字段即可使用新版服务端规则；已有数据进入产品搜索的方法见[服务端使用说明](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md#sliver-与-qakbot-的候选边界)。


## 检测方式与 JARM 主动采集

| 检测方式 | 是否主动探测 | 基本原理 | 当前用途 |
| --- | --- | --- | --- |
| JARM | 是，显式启用后额外最多 10 次 TCP 连接与 ClientHello 探测 | 对 10 组不同 ClientHello 的服务端密码套件、TLS 版本、ALPN 与扩展响应生成 62 个十六进制字符的指纹 | 保存 TLS 配置指纹；当前没有以 JARM 单独归属 C2 家族的规则 |
| TLS Certificate | 证书采集是；分析复用已有观察，无额外连接 | 分析叶证书主题、颁发者、有效期、公钥等元数据 | Cobalt Strike、AsyncRAT / DcRAT、Sliver、QakBot 候选，适用[服务端规则边界](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md#sliver-与-qakbot-的候选边界) |
| HTTP Fingerprint | HTTP 采集是；产品规则复用已有响应 | 分析 HTTP 状态、响应头和内容特征 | 当前产品规则采用 nginx / Apache 的 Server 声明；网页技术识别仍走现有流程 |
| Protocol Fingerprint | 通常是；已有工业被动接收方式除外，识别复用已有握手 | 根据应用层握手和协议响应识别服务 | 既有协议识别及 OpenSSH 软件声明；不表示已实现各 C2 的私有协议规则 |

在扫描器本地 `config.toml` 中明确允许 JARM：

```toml
[service_detection.jarm]
enabled = true
concurrency = 4
probe_timeout_seconds = 3
max_stage_seconds = 60
```

再在控制台「扫描器 → 配置 → JARM 主动采集」启用该扫描器的远程开关。服务识别本身也需启用。JARM 本地和服务端默认均为关闭，远程开启不能覆盖本地禁用；旧服务端未下发该段时保留本地配置。配置在下一任务快照生效。模块模式需要同步更新 service-detection worker，旧 worker 不具备 JARM 采集能力。

参数范围：`concurrency` 1–32、`probe_timeout_seconds` 1–30 秒、`max_stage_seconds` 1–3600 秒。并发以端点计，完整指纹需要 10 个按原始顺序的探测槽；每槽新建 TCP 连接并发送一组 ClientHello，最多尝试一次，不完成应用会话，无重试。预算或取消可使实际执行少于 10 槽；沿用 `server_rate_limit` 的每 IP 连接间隔。每连接最多读取 64 KiB，仅解析 ServerHello/拒绝响应，不发送应用层请求；同时受块级总预算、任务剩余预算、取消信号及 64 MiB 结果上限约束。

只对本次已有 TLS ServerHello 或证书证据的 TCP 端点采集（包括保留服务端证书的失败 mTLS 握手），不按端口号猜测，不跟随 HTTPS 跳转目的站。连接固定到扫描 IP 与端口；任务 `probe_options.server_name` 仅作为经过校验的 SNI，无此项时使用扫描 IP 文本，不执行额外 DNS 解析。

成功指纹要求 10 个槽都取得可判定结果，且至少一个槽取得 ServerHello；这不要求 10 次成功或完整的 TLS 握手。显式 TLS 拒绝或尚未收到任何字节时的正常关闭记为空槽；超时、连接异常、截断、畸形或超限响应标为不完整，不生成有效哈希。全部拒绝显示 `no_response`，不发布全零指纹。块级超时或取消会丢弃尚在执行的端点采集，保留基础服务证据和已完成端点；采集失败不会使基础扫描失败。JARM 与单次 ServerHello 的 JA3S 不同，共享指纹只说明 TLS 配置相似，不能单独确认家族或恶意用途。

API 字段位置如下：

- `product_identification.detection_methods[]`：`id`（`jarm` / `tls_certificate` / `http_fingerprint` / `protocol_fingerprint`）、`name`、`active_probe`（采集是否需要主动网络交互）、`additional_probe`（该方式是否需要额外连接）、`observed`（该次观察是否有此类记录；仅被动协议证据时 `active_probe=false`）、`principle`（稳定原理键）。`active_probe` / `additional_probe` 描述采集方式，不代表本次已实际执行。`observed=true` 表示有相应记录，JARM 记录可能只有部分结果；是否得到指纹仍需看 `jarm.status` 与 `fingerprint`。方式清单不代表四类方式均有 C2 产品规则或均已采集成功。
- `product_identification.jarm`：没有可展示记录时为 `null`，可能是未启用、没有符合条件的端点、取消/预算不足导致记录未保留，或记录未通过格式校验；不能仅凭 `null` 判断从未尝试过连接。存在记录时包含 `status`（`success` / `partial` / `no_response`）、`fingerprint`（不完整或全部拒绝为 `null`）、`expected_probes`、`attempted_probes`、`completed_probes`、`sni`、`field_path`。`attempted_probes` 是已尝试槽数，`completed_probes` 是可判定槽数，包括 ServerHello、明确 TLS 拒绝及未收到任何字节时的正常关闭，不等同于成功 ServerHello 数或完成 TLS 会话数。
- `products[].evidence[].detection_method` 标明产品规则使用的方式。新字段缺省兼容旧数据，不把历史观察标成已完成 JARM。

搜索、端口当前与历史 API 沿用产品观察时钟携带这些元数据；JARM 不创建虚构产品或自动恶意标签，也未增加 JARM DSL 过滤字段。只有新扫描能获取新 JARM；重放旧数据不会主动连接网络。

实现使用固定版本 [netfp 0.2.1](https://docs.rs/netfp/0.2.1/netfp/) 的纯编解码与哈希组件，网络、速率及预算由扫描器控制。算法说明见 [Salesforce JARM](https://github.com/salesforce/jarm)。回归仅使用本地合成 TLS 响应，未探测外部 C2，也不代表已完成各类真实部署验证。


### 通过 Web 或服务器 CLI 管理 JARM

Web 入口为「扫描器 → 配置 → JARM 主动采集」，可修改 `enabled`、`concurrency`、`probe_timeout_seconds`、`max_stage_seconds`。管理员通过已有 `GET/PUT /api/scanner/{scanner_id}/configuration` 读写完整运行配置，发布请求需携带 `expectedRevision`；旧版本或并发更新发生冲突时重新加载后再发布。节点本地授权和下一任务边界生效规则不变。

服务器 CLI 读写同一份配置，无需运行 HTTP 或 Elasticsearch，仅需正确的 PostgreSQL 连接配置：

```bash
# 使用实际扫描器 UUID 替换 <ID>；可在命令前指定 --config /path/to/config.toml。
network_mapping_server scanner-config show <ID>
network_mapping_server scanner-config set-jarm <ID> --enabled true --concurrency 4 --probe-timeout-seconds 3 --max-stage-seconds 60 --change-reason "授权资产盘点"
network_mapping_server scanner-config set-jarm <ID> --enabled false --change-reason "暂停额外 TLS 握手"
```

`set-jarm` 仅修改给出的字段，保留其他 JARM 参数和网页抓取、端口扫描等配置；不传任何修改字段会报错。参数范围与 Web 相同，`--enabled` 必须显式传 `true` 或 `false`，变更原因最多 500 个字符。每次成功更新都在同一事务中写入新修订、历史与审计；如果 Web 或另一个 CLI 已先修改配置，则报修订冲突并退出，不覆盖并发更新。`show` 可核对当前文档和修订；现有 `set-web-content` 命令继续可用。

两种入口均只能管理服务端运行配置，不能越过扫描节点本地 `service_detection.enabled` / `service_detection.jarm.enabled` 授权。旧 worker 需同步升级后才能实际采集 JARM。
