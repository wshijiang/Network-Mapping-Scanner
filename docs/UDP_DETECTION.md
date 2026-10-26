# UDP 服务识别与独立探测内核

[文档中心](README.md) · [服务探测分批计划](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_DETECTION_ROADMAP.md)

## 当前任务与库 API

第一批新增公开 `scanner_rs::udp_probe` 库 API，包含 DNS、NTP、STUN 定向单播探测。该库保持独立；当前另有原生引擎通过 plan v2 将 DNS、EtherNet/IP、BACnet 单播及受限实时流量被动接收接入任务。须配套更新服务端并完成端点投影迁移，详见[服务协议识别与部署](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md)。NTP/STUN 尚未接入任务，不能据此声明可下发扫描。

UDP 主动任务自动尝试 DNS、EtherNet/IP ListIdentity 和 BACnet/IP（仅 IPv4）；被动任务自动解析支持的 EtherNet/IP I/O 与 OPC UA UADP 帧，无需手动勾选协议。服务端将默认协议集写入 plan，节点能力和预算仍按该集合校验；主动/被动任务保持分离，目标、端口和接收窗口仍需明确配置。

## 协议范围

| 协议 | 请求 | 响应关联与证据 |
| --- | --- | --- |
| DNS | 根 SOA，RD=0，无 ANY/EDNS/DNSSEC 或外部查询名 | 来源端点、事务 ID、完整消息和原问题匹配；记录数字 RCODE、TC、AA，不保留记录 |
| NTP | 48 字节 v4 mode 3 客户端请求 | 来源端点、mode 4、版本、stratum、originate 时间戳匹配；记录协议版本和 KoD，不推断软件版本 |
| STUN | 20 字节 Binding 请求 | 来源端点、magic cookie、96 位事务 ID、长度和 TLV 边界；成功要求合法 mapped-address，错误要求合法 error-code；不保存地址、软件名或错误原因 |

使用现有 Tokio 1、Hickory 0.26 和 ring，无新增依赖或锁文件变更。请求 ID 使用平台安全随机源；每次重试更换。NTP 当前只接受基本 48 字节响应，带认证/扩展的其他长度保守保持未确认。STUN 不执行 TURN Allocate，也不据此证明提供 TURN 中继。

## API 与边界

`probe(SocketAddr, UdpService, ProbeOptions, watch::Receiver<bool>)` 返回结构化 `ProbeResult`。默认每次超时 2 秒、2 次尝试；允许 1–2 次及单次不超过 5 秒。取消信号为 true 或控制通道关闭均停止。调用方必须在授权目标范围内执行，负责全局/每 IP 速率、并发、任务期限和持久化；当前库 API 不提供批量扫描入口。

连接式 UDP 过滤其他来源端点；本批不支持 TFTP 式服务端端口切换。拒绝端口 0、未指定地址、组播和有限广播（含 IPv4-mapped IPv6），不进行广播发现。接收缓冲多保留一个字节，超过 8 KiB 的报文整体拒绝，最多处理 32 个不匹配报文；DNS 在解码前限制声明的记录总数为 64。无效数据不能延长绝对超时。

| status | 含义 |
| --- | --- |
| identified | 已收到匹配协议响应，含 service 和有界 evidence |
| no_response | 未收到有效匹配响应；不能解释为 closed，也不证明 open |
| port_unreachable | 系统报告 ConnectionRefused；依赖平台 ICMP 交付能力 |
| response_limit | 无效/超限响应达到预算，识别未完成 |
| cancelled | 控制通道取消或关闭，识别未完成 |

其他 I/O 错误以 Result 错误返回，不伪装成无响应。错误、未确认和取消不得清除已有成功服务证据。

## 当前任务与后续范围

DNS TCP/UDP、DoH、DoT、VNC 及工业协议的实际范围见[完整支持矩阵](https://github.com/wshijiang/network-mapping/blob/main/docs/SERVICE_PROTOCOLS.md)。DNS/EtherNet/IP/BACnet 主动任务及 EtherNet/IP I/O、OPC UA UADP 的受限被动任务现已接入 plan v2；端点身份增加传输协议，既有部署须先完成配套服务端投影迁移。不能仅修改 TCP 过滤条件来启用 UDP，也不能将独立 NTP/STUN 库 API 当作可下发任务。

[DNS 扩展计划](https://github.com/wshijiang/network-mapping/blob/main/docs/DNS_DOH_DOT_VNC_PLAN.md)与[工业协议计划](https://github.com/wshijiang/network-mapping/blob/main/docs/INDUSTRIAL_SERVICE_DETECTION_PLAN.md)保留分批设计历史，当前能力以支持矩阵和任务文档为准。被动接收不向 UDP/2222 I/O 端口发送探测，不证明端口开放或会话有效。

尚待后续交付的范围包括 NTP/STUN 任务接入、Elasticsearch 原生明文/TLS Transport，以及 SNMP、NBNS、RPCbind、TFTP、SQL Browser、Memcached、SIP、CoAP、QUIC/DTLS 等专项协议；不计为本次发布支持。

## 验证

从扫描端仓库执行：

```sh
source /workspace/.cloud/env.sh
CARGO_TARGET_DIR=/workspace/.cloud/scanner-target cargo test --locked --lib udp_probe
cargo fmt --check
CARGO_TARGET_DIR=/workspace/.cloud/scanner-target cargo clippy --locked --all-targets -- -D warnings
```

测试包括协议正反例、回显、错误事务 ID、其他来源、超限数据、重试旧响应、无响应、取消及 IPv4/IPv6 回环。测试需要本地 UDP socket 权限；全部使用回环地址，不访问外部目标。它们不是线上节点或真实服务端到端验收。
