# Network Mapping 扫描器文档

[项目首页](../README.md) · [文档维护与本地预览](DOCUMENTATION.md)

扫描器负责注册、领取任务、执行扫描引擎并上传结果。首次部署需先准备可访问的服务端，再按下列路径配置和验收节点。

## 版本更新

| 文档 | 内容 |
| --- | --- |
| [更新日志](CHANGELOG.md) | 自上次发布 tag 以来的扫描端变动、固定比较范围与升级兼容注意 |
| [DNS 与 VNC 服务识别扩展计划](https://github.com/wshijiang/network-mapping/blob/main/docs/DNS_DOH_DOT_VNC_PLAN.md) | DNS TCP/VNC 首批已接入；DoH、DoT、UDP 后续接入与恢复验收计划 |
| [工业与物联网服务识别扩展计划](https://github.com/wshijiang/network-mapping/blob/main/docs/INDUSTRIAL_SERVICE_DETECTION_PLAN.md) | 待实现：Modbus TCP、EtherNet/IP、S7、OPC UA、BACnet/IP；已有 MQTT/MQTTS 核验与补强 |

## 从这里开始

| 当前任务 | 建议阅读顺序 |
| --- | --- |
| 新增扫描节点 | [部署选型与原生安装](DEPLOYMENT.md)或[Docker 部署](DOCKER.md) → [启动配置检查](CONFIG_CHECK.md) → [配置与使用](USAGE.md) |
| 接入扫描引擎 | [使用指南](USAGE.md) → [masscan 输出适配](MASSCAN.md) → 按需启用 [Nuclei](NUCLEI.md) |
| 排查任务或上传异常 | [扫描与上传恢复](recovery.md) → [远程诊断与日志](DIAGNOSTICS.md) → 按需检查[缓存状态](CACHE_MANAGEMENT.md) |
| 更新执行模块 | [热更新操作指南](MODULE_UPDATES.md) → [目标架构与设计边界](MODULAR_HOT_UPDATE_DESIGN.md) |
| 修改扫描器代码 | [维护参考](MAINTENANCE.md) → 对应引擎或协议专题 → [文档维护](DOCUMENTATION.md) |

清理缓存前先阅读身份、待上传结果与诊断队列的保护规则。模块热更新的已实现范围以操作指南为准，设计文档包含后续改造方案。

## 入门部署

| 文档 | 内容 |
| --- | --- |
| [部署选型与原生安装](DEPLOYMENT.md) | 环境准备、注册、systemd、升级恢复与验收 |
| [Docker 部署](DOCKER.md) | Compose、注册、权限、状态卷和镜像构建 |
| [启动配置检查](CONFIG_CHECK.md) | 本地部署字段、启动快照和心跳上报 |

## 配置与引擎

| 文档 | 内容 |
| --- | --- |
| [配置与使用](USAGE.md) | 扫描模式、引擎配置、远程参数、重连和双栈探测 |
| [UDP 探测内核与后续接入](UDP_DETECTION.md) | 当前 DNS/NTP/STUN 库 API、验证与未开放的任务链路 |
| [masscan 适配与迁移](MASSCAN.md) | 官方 list 输出、兼容模式、切换验证和回滚 |
| [Nuclei 部署与运维](NUCLEI.md) | 模板治理、参数语义、结果协议和上线检查 |
| [目标执行反馈](PERFORMANCE.md) | 连接采样、失败分类与兼容升级 |

## 运维排障

| 文档 | 内容 |
| --- | --- |
| [扫描与上传恢复](recovery.md) | 状态持久化、租约、检查点和重启恢复 |
| [扫描缓存管理](CACHE_MANAGEMENT.md) | 缓存清理、独占锁、身份与诊断状态保护 |
| [远程诊断与日志](DIAGNOSTICS.md) | 诊断队列、日志快照、重试和故障排查 |
| [模块执行与热更新](MODULE_UPDATES.md) | 当前实现：签名制品、在线激活、回滚和 HTTPS feed |

## 开发参考

| 文档 | 内容 |
| --- | --- |
| [扫描器维护参考](MAINTENANCE.md) | 模块职责、CLI、配置字段、开发与验证约定 |
| [模块化与热更新设计](MODULAR_HOT_UPDATE_DESIGN.md) | 目标架构、Worker 协议与更新事务；当前能力以操作指南为准 |
| [文档维护与本地预览](DOCUMENTATION.md) | 内容归属、导航维护、站内链接和 MkDocs 构建检查 |

## 配套组件

| 组件 | 文档职责 | 入口 |
| --- | --- | --- |
| 服务端 | 系统部署、扫描协议、存储、运维及外部 API | [服务端文档中心](https://github.com/wshijiang/network-mapping/blob/main/docs/README.md) |
| 扫描器 | 节点部署、引擎配置、执行恢复及本地诊断 | [扫描器文档中心](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/README.md) |
| Web 控制台 | 页面操作、前端集成、组件及交互验证 | [Web 文档中心](https://github.com/wshijiang/network-mapping-vue/blob/main/docs/README.md) |

## 文档维护

[语言切换与多语言文档](LOCALIZATION.md)：浏览器首选语言、手动 cookie、英文覆盖范围及中英统一构建。

新增专题时同步本页与 `mkdocs/mkdocs.yml` 的导航，提交前完成严格构建。内容归属、链接规则和命令见[文档维护与本地预览](DOCUMENTATION.md)。
