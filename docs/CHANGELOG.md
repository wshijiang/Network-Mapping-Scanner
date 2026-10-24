# 扫描端更新日志

[文档中心](README.md) · [部署与升级](DEPLOYMENT.md) · [服务端更新日志](https://github.com/wshijiang/network-mapping/blob/main/docs/CHANGELOG.md)

## 未发布：sha2 0.11 升级适配（2026-10-24）

- 修复 sha2 0.11 摘要输出不再实现 LowerHex 导致诊断、注册和 TLS 指纹编译失败；复用逐字节小写十六进制编码，保持已有摘要及身份状态兼容。
- 增加标准 SHA-256 已知向量回归；保留诊断快照、注册重启和 TLS 证据验证。
## 未发布：Hickory 0.26 升级适配（2026-10-24）

- 适配 Hickory 0.26 的解析器构造错误、连接配置、Lookup answer API、MX/SRV 字段与 DNS 消息元数据，修复依赖升级的编译失败。
- 指定 UDP/TCP 解析器继续固定用户提供的 IP/端口及传输；DNS 响应继续校验事务、问题、类型、长度和记录数上限。新增回环 UDP/TCP 自定义端口、来源元数据与 TTL 回归。

## 未发布：全部服务自动识别（2026-10-23）

- 默认识别策略为 adaptive，所有已实现 TCP 协议进入自动候选；补齐工业端口映射和工业回退/full exhaustive，HTTPS 自动细分 DoH，完整 RFB Banner 可确认非标准端口 VNC。
- 保留节点探测预算、阶段期限和 TLS 校验；TCP 无需 required_services，UDP 默认协议由服务端规范化后下发，IPv6 不尝试经典 BACnet/IP。
- 增加全模块默认端口覆盖、工业回退、HTTPS→DoH 细分与预算、RFB 正反例回归。

## 未发布：PR review 与 CI 核验修复（2026-10-23）

- 远程 CI 暴露诊断存储立即重开的偶发锁冲突；阻塞数据库调用在返回完成前显式释放捕获的 Store，并增加多线程连续重开回归，不增加重试或忽略失败。
- 核实 PR #91 的检查点与期限意见：被动接收改为在固定游标保存包含恢复结果的累计快照，并恢复已观察来源的去重集合，避免多条 ACK 证据被覆盖。
- 原生 TCP 与 UDP 探测在接受末次结果时重新检查阶段期限；UDP 阶段耗尽不再提交端点完成游标或返回成功。
- 增加跨重启多来源恢复、原生期限竞争及末端 UDP 超时回归。旧 IPC fixture 意见已由上一提交配套 IPC 3 修复，本轮核对保留。

## 未发布：加密 DNS、工业与 UDP 服务识别（2026-10-23）

- 增加默认验证证书的 DoT/DoH 原生识别，固定目标 IP、合法 SNI/路径、公开 CA；普通 HTTPS/HTML、重定向和不匹配 DNS 不确认 DoH。
- 增加显式 Modbus TCP、EtherNet/IP、经典 S7comm、OPC UA 最小握手；MQTT/MQTTS 改为原生 3.1.1/5.0 CONNECT/CONNACK，确认合法认证拒绝。
- plan v2 独立 UDP 任务接入 DNS、EtherNet/IP ListIdentity、BACnet/IP 单播，以及有界 IPv4 实时流量被动接收；不发送 I/O 控制数据，不把沉默标为开放/关闭。
- 新增 `max_service_probes` 能力和 IPC 3 参数契约，复用期限、限速、取消、ACK 与检查点。新增直接依赖 tokio-rustls/rustls-native-certs/ipnet，复用锁定传递版本；未进行无关升级。
- 详见[使用说明](USAGE.md)、[模块更新](MODULE_UPDATES.md)和[完整支持矩阵](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md)。被动协议仅支持文档列出的保守子集，真实设备验收仍需进行。

## 未发布：DNS TCP / VNC 服务探测（2026-10-23）

- 服务识别阶段新增原生 DNS TCP 与 VNC 探测：默认映射 53、5900–5909，支持显式选择协议探测非标准端口；不向 zgrab2 注册未支持的模块。默认服务策略继续识别其他已有协议。
- DNS 校验 TCP 分帧、随机事务 ID 和根 SOA 问题，合法拒绝响应只证明协议存在；VNC 只接收完整受支持的 RFB 问候，不尝试认证。结果记录 `source=native` 和有界 schema 2 证据。
- 节点上报 `scan_capabilities.service_protocols`，任务通过 `scan_plan.required_services` 显式选择 DNS/VNC，复用阶段期限、取消、限速、分块 ACK 与检查点。
- Worker IPC 升为 2，拒绝旧 Worker 静默忽略定向探测参数。启用模块的部署须排空旧 generation 任务，配套升级 Agent、Worker 和完整 IPC 2 模块包；结果上传仍为协议 3。详见[模块更新](MODULE_UPDATES.md)。
- 已完成合成协议、回环、真实 Worker 及本地回归；未进行线上节点/真实 DNS、VNC 产品验收。本条记录 A 阶段；其后实现见上方扩展条目。

## 未发布：服务识别扩展规划（2026-10-23）

- 补充 [DNS、DoH、DoT 与 VNC 扩展规划](https://github.com/wshijiang/network-mapping/blob/main/docs/DNS_DOH_DOT_VNC_PLAN.md)入口及 UDP 接入前置条件，明确原生适配器、统一预算、Worker/检查点兼容和协议验收。
- 本条仅涉及文档，尚未新增对应服务模块或开放 DNS UDP 任务；现有 DNS UDP 仍为独立库 API。
- 补充[工业服务识别规划](https://github.com/wshijiang/network-mapping/blob/main/docs/INDUSTRIAL_SERVICE_DETECTION_PLAN.md)：新增协议的有界识别、UDP 发现与被动观察、Worker/恢复及逐协议验收；MQTT/MQTTS 已有模块，作为核验与补强项，不重复计为新增支持。

## 未发布：服务探测第一批（2026-10-22）

- 新增 DNS/NTP/STUN UDP 单播探测库内核，具备事务匹配、连接式来源过滤、超时重试、取消、报文大小和无效响应预算。
- 仅有效协议响应生成识别结果；超时不判定关闭，证据不保留返回地址、名称或原始报文。
- 本批没有接入任务/CLI，也未上报 UDP 能力；线上 UDP 需后续先完成任务协商和服务端协议端点迁移。详见 [UDP 探测](UDP_DETECTION.md)及跨仓库分批计划。

## 未发布（自 v0.1.20 以来）

截至 **2026-10-21（北京时间）**，以最新已发布 tag [v0.1.20](https://github.com/wshijiang/Network-Mapping-Scanner/releases/tag/v0.1.20) 为基线，汇总主分支已合入的扫描端变动。

| 比较项 | 固定版本 |
| --- | --- |
| 上次发布 | `v0.1.20`，2026-10-15 发布，提交 `d74f8622f2850cac7ee7a4c1bd098985dd66ceca` |
| 本次截止 | `main` 的 `8ad7173b1f190c95a9f2ecfd1c0753ea7f7d5112` |
| 变动范围 | 12 个提交；[查看完整比较](https://github.com/wshijiang/Network-Mapping-Scanner/compare/v0.1.20...8ad7173b1f190c95a9f2ecfd1c0753ea7f7d5112) |

### 修复

- **超大握手保留系统线索**：zgrab2 模块结果超过大小预算时，不再只保留状态与错误摘要；在相同 JSON 字节预算内，尽量保留 banner、SSH 软件标识、SMB/会话系统字段及 HTTP `Server` 响应头，维持原有字段路径，供服务端系统识别使用。摘要仍标记 `truncated=true`，不保证超限原文完整。见[修复提交](https://github.com/wshijiang/Network-Mapping-Scanner/commit/72bacdb2af8be27c3e3bce1370768f0fde2a7c5d)。
- **传递 HTTP 正文截断状态**：服务证据中的 `truncated` 同时考虑模块整体截断和 HTTP/HTTPS 的 `response.body_truncated`，避免正文不完整却被服务端当作完整证据。该改动不增加目标请求。见[修复提交](https://github.com/wshijiang/Network-Mapping-Scanner/commit/22efb37eea76855e1a19d398c30da6bc167b8e7f)。

### 文档与构建

- 补充原生部署、systemd、注册、升级恢复和验收指南，整理 Docker、配置、引擎、缓存、远程诊断及模块热更新的阅读路径。见[部署指南](DEPLOYMENT.md)。
- 新增 MkDocs 文档站、按任务分组的首页与导航，以及将仓库源码相对链接转换为 GitHub URL 的构建钩子。见[文档维护](DOCUMENTATION.md)。
- Docker 构建阶段的 Go 从 `1.26.8-bookworm` 更新为 `1.27.2-bookworm`，Rust 从 `1.98.0-bookworm` 更新为 `1.99.0-bookworm`；不表示宿主机必须安装这两个 Docker 构建版本。
- 更新 GitHub Actions：`actions/upload-artifact` v4 → v7、`actions/download-artifact` v4 → v8、`actions/checkout` v5 → v7，并更新 `Swatinem/rust-cache` 的固定提交；Dependabot 目标分支切换为 `main`。

### 升级与兼容注意

1. 建议先部署配套服务端，再更新扫描器与控制台。服务端的 OS/Web 推断复用已有服务证据；本次扫描器更新改善证据保留与截断表达，不新增扫描模式或注册步骤。
2. 两项修复仅影响新采集/新生成的结果；已有上传和缓存中丢失的正文或系统字段不能自动恢复，需要重新执行相应服务识别任务。
3. 升级保留节点身份、状态目录、检查点及待上传结果，按[部署指南](DEPLOYMENT.md)和[扫描与上传恢复](recovery.md)执行停机、替换与验收，不通过清空状态重新注册来完成普通升级。
4. 环境变量注册、镜像内置 Nuclei 模板、模板锁释放顺序和按架构划分的 Docker `latest` 标签已随 `v0.1.20` 发布，不列为本次新增功能。

本节仅覆盖扫描端；服务端识别规则、通知和域名发现等变动见配套服务端更新日志。
