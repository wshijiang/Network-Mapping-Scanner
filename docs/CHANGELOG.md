# 扫描端更新日志

[文档中心](README.md) · [部署与升级](DEPLOYMENT.md) · [服务端更新日志](https://github.com/wshijiang/network-mapping/blob/main/docs/CHANGELOG.md)

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
