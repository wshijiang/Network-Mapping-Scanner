# 扫描端更新日志

[文档中心](README.md) · [配套发布与升级](https://github.com/wshijiang/network-mapping/blob/main/docs/RELEASING.md)

## 未发布

- **JARM Web / CLI 用法**：补充 Web 和服务器 CLI 的查看、启用、停用及局部修改示例，说明修订冲突、参数边界、本地授权与 worker 升级要求。

- **JARM 主动采集**：新增默认关闭的 TLS 指纹采集，复用每 IP 限速，在已有 TLS 证据的端点执行最多 10 次有预算的握手。固定扫描地址，支持 SNI、取消和恢复边界，拒绝、超时和畸形响应不伪造有效哈希。同步本地/远程配置、公开字段快照、netfp 锁定依赖及使用说明；增加本地 TLS 回归。

- **服务产品配套验证**：补充 Sliver 类 mTLS 握手失败后公开叶证书、失败状态和字段完整性保留回归，供服务端规则 v2 的 Sliver / QakBot 候选复用。节点不增加探测请求或配置；补充使用范围和证据缺失说明。

- **服务产品证据**：在既有探测与预算内保留选中协议之外的 HTTP/HTTPS/TLS 握手，供服务端统一识别普通软件和 C2 产品候选；按模块去重，补充证据最多占用两倍 `max_result_bytes`，不足时标记 `product_evidence_truncated`。不改变协议选择、请求数量和网页富化行为。

- **服务识别与上传性能**：自适应回退改为一次建立端点证据摘要，减少整批反复遍历；上传批次借用缓存观察，读取有界成功响应体以复用连接，补充每批与 flush/规划耗时。统一 TOML/Docker 默认 masscan 速率为 10000，更新部署说明；加入报文兼容、连接复用、确认体异常回归与可重跑基准。测量范围和线上排查见 [性能核查](SCAN_PERFORMANCE.md)。


- **TLS 证据保留**：独立 TLS 探针在握手失败前已取得叶证书时，保留公开证书及必要服务端协商字段，维持失败状态；供服务端威胁线索分析使用。

- **网页内容富化（favicon / JS / 落地页）**：服务识别出 http/https 端点后，新增并发、异步、 best-effort 的网页资产抓取阶段，结果作为 `web_assets` 证据随既有上传链路入库，供服务端 `icon_md5` / `js_name` / `js_md5` 检索与图标展示：
  - favicon：按 `<link rel=icon>` 候选（rel 优先级排序）抓取，兜底 `/favicon.ico`；魔数校验拒收 200-HTML 错误页；原始字节上限默认 **64KB**，base64 上传，MD5 由服务端投影时计算（与 Hunter `web.icon` / Quake `favicon.hash` 一致）。
  - 外部 JS：提取同源 `<script src>`（跳过内联 / `data:` / 跨域），默认每页最多 **10** 个，逐个下载计算 **MD5**（只存哈希与路径，不存内容），单文件上限 512KB。
  - 落地页：仅当原探测为 3xx 或空 body 时条件性重抓 `/`，body 上限 256KB；重定向手动跟随且**钉死目标 IP 与端口**（自定义 DNS resolver + Location 缺省端口回填），跨主机名重定向不会把证据记到第三方服务器。
  - 严格有界：全局并发信号量（默认 16）、单请求超时（默认 10s）、块级总预算（默认 120s）、结果字节预算（沿用 64MB 块上限）；取消/超时保留已完成部分，富化失败绝不升级为扫描失败。
  - **重定向安全加固**：每个重定向跳板强制约束在被扫描的 IP+端口——IP 字面量 Location 指向其它地址、或显式不同端口时拒绝跟随（reqwest 对 IP 字面量绕过自定义 resolver），杜绝恶意端点借重定向把扫描器当内网探针；主机名重定向仍由 resolver 钉死到原 IP。
  - 超限 JS 只记录路径与 `truncated` 状态，**绝不发布前缀 MD5**；任务级覆盖只能关闭富化、不能突破运行时开关（本地 AND 远端）；取消到达时已完成的块先落 journal 再退出，重启不丢已完成探测。
  - 配置：`[service_detection.web_content]`（enabled 默认 true、concurrency、fetch_timeout_seconds、max_redirects、max_stage_seconds、max_favicon_bytes、max_js_files、max_js_bytes、max_body_bytes、user_agent），服务端运行时配置可覆盖全部数值，有效开关为本地 AND 远端；任务级 `scan_plan.web_content.enabled` 可单任务关闭。旧服务端/旧计划无该字段时按本地默认运行，协议与 plan 版本不变。

## v0.1.22（2026-11-18）

- 心跳能力改按有效配置上报：引擎开关取本地配置与服务端下发扫描配置的交集，服务端禁用某引擎后下一次心跳即收回对应 profile/阶段声明，与服务端调度门控保持一致。
- 必需阶段的引擎被有效配置禁用时，任务在启动任何引擎前即以路由失败（`route_unavailable`）上报，由服务端改派其他节点；不再先跑完端口扫描再以普通扫描错误原地重试三次。失败日志同步输出真实的 retryable 与 failure_class。
- Modbus TCP 改用固定版 zgrab2 模块，保留指定 Unit ID、响应关联和合法异常确认；适配器限制批次输入速率及在途数量。Modbus 现遵守 zgrab2 blocklist；镜像默认列表包含 RFC 1918 地址，内网扫描需部署方按授权配置。
- 修复 Modbus 低速探测时限速等待被误判为空闲而提前中止的问题；首个目标立即发送，后续仍受速率限制，并保留对卡住引擎的空闲超时。

## v0.1.21（2026-10-27 重新发布）

**2026-10-26 的同版本发布已撤回，2026-10-27 修复后重新发布**。请以本次 tag 指向的提交、BUILD-INFO 和 SHA-256 校验文件为准，不复用已撤回制品或旧 Actions 构建附件。本节按最终实现汇总此前阶段记录。

| 核对项 | 固定范围 |
| --- | --- |
| 上次发布 | `v0.1.20` · `d74f8622f2850cac7ee7a4c1bd098985dd66ceca` |
| 本次代码基线 | `95d5c93e76ae031b6d8e44e664257a10891a42be`（`main`） |
| 变动范围 | 27 个提交（含合并提交）；[完整比较](https://github.com/wshijiang/Network-Mapping-Scanner/compare/v0.1.20...95d5c93e76ae031b6d8e44e664257a10891a42be) |

本次另含版本、发布说明及文档整理；服务端同时固定配套控制台发布提交。

### 撤回后补充的修复

- 心跳和任务响应体传输中断时按网络故障退避重试，完整但无法解析的响应仍按协议错误处理。
- 运行过程中遇到不可恢复的错误而停止时返回非零退出码，便于进程管理器识别失败；正常停止仍返回零。
- 外部扫描引擎和模块 worker 启动遇到 `Text file busy` 时进行短暂、有界重试，避免并行测试中临时可执行文件的占用竞态导致 CI 偶发失败。
- 状态、诊断和模块数据库关闭时显式释放文件锁，避免并发启动的子进程短暂继承描述符后阻止数据库立即重开。

### 新增与调整

- **自动服务识别**：默认 adaptive，全部已实现 TCP 协议进入候选；补齐工业端口线索、剩余预算回退及 exhaustive。HTTPS 可细分 DoH，完整受支持 RFB 问候可确认非标准端口 VNC；不保证每个端点执行全部握手。
- **原生协议**：新增 DNS TCP、验证证书的 DoT/DoH、VNC、Modbus TCP、EtherNet/IP、经典 S7comm、OPC UA 最小握手；MQTT/MQTTS 改为可验证版本和认证拒绝的原生 CONNECT/CONNACK。不执行认证、桌面会话、过程数据读取或控制操作。详见[完整支持矩阵](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md)。
- **独立 UDP 任务**：plan v2 接入 DNS、EtherNet/IP ListIdentity、经典 BACnet/IP 单播，以及有界 IPv4 EtherNet/IP I/O / OPC UA UADP 被动接收。主动和被动模式各自默认使用支持的协议集；目标、端口、接收节点和窗口仍需明确配置，沉默不表示开放/关闭。
- **UDP 库 API**：公开 DNS/NTP/STUN 有界单播内核，具备事务关联、来源过滤、超时重试、取消和报文预算；NTP/STUN 仍未接入任务/CLI。库 API 与任务引擎范围见 [UDP 说明](UDP_DETECTION.md)。
- **能力与模块契约**：新增 `max_service_probes`、协议能力及 plan v2；Worker IPC 升为 **3**，继续复用期限、取消、限速、分块 ACK 和检查点；结果上传协议保持 **3**。
- **双语文档**：新增中英首页、部署与语言维护页面，默认 MkDocs 构建/预览/部署同时生成两种语言的页面、资源和搜索索引；支持子路径和显式语言选择，尚未翻译专题链接中文原文。见[语言与文档维护](LOCALIZATION.md)。

### 修复与维护

- 修复模块仓库在并行创建子进程时，继承的锁描述符导致旧 Registry 释放后仍无法立即重开的竞争：最后一个拥有者关闭数据库后显式解锁，存活的 Registry 克隆仍保持独占。Worker 及 masscan/zgrab2/Nuclei 引擎启动统一仅对短暂 `ETXTBSY` 进行最多 250 毫秒的异步重试，永久失败保留原始错误，不串行化或跳过测试。

- zgrab2 升级并固定至最新主分支 `835aa53808aed88b4c3e017d623b374fb26dca95`，RDP 改由上游模块完成协商、TLS 和可选 NTLM 指纹；已协商 RDP 后的 TLS/NTLM 失败保留服务类型及原始状态。补齐真实引擎 INI/回环测试和 CI 验证，修正 BUILD-INFO 中 Rust/Go 版本。
- zgrab2 INI 仅生成本批实际使用的外部模块并去重，避免未使用的模块配置影响本批探测。
- 原生 TCP（包括工业协议、DoT/DoH/MQTTS）与主动 UDP 握手复用 NUL 清理和 `max_result_bytes` 限制，避免设备字符串导致 PostgreSQL `22P05` 写入错误，并正确传递截断标记。

- 超大 zgrab2 握手在同一 JSON 字节预算内尽量保留 Banner、SSH/SMB 系统线索和 HTTP Server 头，继续标记截断；HTTP 正文截断状态向服务端传递，不增加目标请求。
- 被动接收检查点保存累计结果和已观察来源，避免跨重启多来源 ACK 覆盖；原生 TCP/UDP 接受末次结果时重新检查阶段期限，耗尽时不提交完成游标。
- 诊断存储异步调用完成前显式释放捕获状态，修复立即重开偶发锁冲突；保留节点身份和恢复数据。
- 适配 Hickory **0.26** 的解析器、记录和响应 API，保留用户指定 UDP/TCP 地址/端口与 TTL；适配 sha2 **0.11** 的小写十六进制编码，保持摘要、指纹和身份状态兼容。
- 锁定 rustls 更新至 **0.23.46**；更新 uuid、thiserror、libc、Rust/Go Docker 构建镜像和 Actions；补齐原生/systemd、模块更新、缓存及诊断文档。

### 升级与兼容

1. 先准备服务端 **0.1.30** 并完成[传输端点迁移](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md#存储升级与回滚)，再部署 Scanner **0.1.21** 和控制台 **0.1.24**，之后启用新增 UDP/工业协议任务。
2. 模块部署先暂停分配，排空旧 generation 的任务与检查点，配套替换 Agent、Worker 和完整 IPC **3** 模块包。不得混用 IPC 2/旧 Worker。见[模块升级](MODULE_UPDATES.md)。
3. 保留节点 ID、令牌、SQLite、状态目录、检查点及待上传结果，按[部署与升级](DEPLOYMENT.md)执行；普通升级不应清空状态或重新注册。已丢失证据只能通过后续任务重新采集。
4. DoH/DoT/MQTTS 保持证书与服务名验证，公开 CA 可配置；被动协议仅支持矩阵所述子集，经典 BACnet/IP 不支持 IPv6，不发送实时 I/O 控制流量。

本日志不代表真实产品/设备、线上节点或组播网络已完成验收；本次检查和默认忽略的测试见 release PR。

此前发布见 [GitHub Releases](https://github.com/wshijiang/Network-Mapping-Scanner/releases)；本节不重复计入 `v0.1.20` 已交付的功能。
