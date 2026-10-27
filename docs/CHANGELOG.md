# 扫描端更新日志

[文档中心](README.md) · [配套发布与升级](https://github.com/wshijiang/network-mapping/blob/main/docs/RELEASING.md)

## 未发布

### 修复

- 心跳和任务响应体传输中断时按网络故障退避重试，完整但无法解析的响应仍按协议错误处理。
- 运行过程中遇到不可恢复的错误而停止时返回非零退出码，便于进程管理器识别失败；正常停止仍返回零。
- 外部扫描引擎和模块 worker 启动遇到 `Text file busy` 时进行短暂、有界重试，避免并行测试中临时可执行文件的占用竞态导致 CI 偶发失败。
- 状态、诊断和模块数据库关闭时显式释放文件锁，避免并发启动的子进程短暂继承描述符后阻止数据库立即重开。

## v0.1.21（待发布）

发布准备日期：**2026-10-26（北京时间）**。release PR 待审；本地 tag 尚未推送，不表示已发布制品。本节按最终实现汇总原“未发布”阶段记录。

| 核对项 | 固定范围 |
| --- | --- |
| 上次发布 | `v0.1.20` · `d74f8622f2850cac7ee7a4c1bd098985dd66ceca` |
| 本次代码基线 | `386a3b5c8957c7179f0b2f48bc9c8e7c94359fcf`（`main`） |
| 变动范围 | 23 个提交（含合并提交）；[完整比较](https://github.com/wshijiang/Network-Mapping-Scanner/compare/v0.1.20...386a3b5c8957c7179f0b2f48bc9c8e7c94359fcf) |

本次另含版本、发布说明及文档整理；服务端同时固定配套控制台发布提交。

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
- 更新 uuid、thiserror、libc、Rust/Go Docker 构建镜像和 Actions；补齐原生/systemd、模块更新、缓存及诊断文档。

### 升级与兼容

1. 先准备服务端 **0.1.30** 并完成[传输端点迁移](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md#存储升级与回滚)，再部署 Scanner **0.1.21** 和控制台 **0.1.24**，之后启用新增 UDP/工业协议任务。
2. 模块部署先暂停分配，排空旧 generation 的任务与检查点，配套替换 Agent、Worker 和完整 IPC **3** 模块包。不得混用 IPC 2/旧 Worker。见[模块升级](MODULE_UPDATES.md)。
3. 保留节点 ID、令牌、SQLite、状态目录、检查点及待上传结果，按[部署与升级](DEPLOYMENT.md)执行；普通升级不应清空状态或重新注册。已丢失证据只能通过后续任务重新采集。
4. DoH/DoT/MQTTS 保持证书与服务名验证，公开 CA 可配置；被动协议仅支持矩阵所述子集，经典 BACnet/IP 不支持 IPv6，不发送实时 I/O 控制流量。

本日志不代表真实产品/设备、线上节点或组播网络已完成验收；本次检查和默认忽略的测试见 release PR。

此前发布见 [GitHub Releases](https://github.com/wshijiang/Network-Mapping-Scanner/releases)；本节不重复计入 `v0.1.20` 已交付的功能。
