# Nuclei 漏洞扫描部署与运维

## 功能边界

扫描器仅在服务端下发 `vulnerability_scan` 计划时运行 Nuclei。执行顺序固定为：

1. masscan 发现开放端口；
2. 若节点启用 zgrab2，则尝试识别服务；
3. 根据开放端口和服务生成 Nuclei 目标；
4. 使用节点本地审核模板运行 Nuclei；
5. 将结构化漏洞元数据作为结果协议版本 3 上传。

控制端的“全部”模式映射为 `vulnerability_scan`。目标为域名时，DNS 扫描器先完成
`dns_records`，服务端仅把命中授权 CIDR 且未被排除的 A/AAAA 地址按地址族生成
`vulnerability_scan` 子任务；Nuclei 不直接接收域名解析器返回的未授权地址。

任务不能指定 Nuclei 二进制、模板路径或额外 CLI 参数。Nuclei 不会扫描 masscan 未发现的
端点。没有开放端口时漏洞阶段直接成功并返回空结果。

当前不支持认证请求头、登录态、Interactsh/OAST、DAST、代码模板或 Headless 模板。漏洞记录
也不进入资产端点当前状态和高级搜索投影；任务详情最多展示最近 500 条，完整事实仍按配置保存
在 PostgreSQL 或 Elasticsearch。

仅可扫描已经取得明确授权的资产。

## 安装前提

- 扫描节点已安装可执行的 `nuclei`，或配置其绝对路径；
- 模板使用 Docker 内置的官方稳定版本，或本地独立的签名模板目录；
- 服务端已支持 `vulnerability_scan` 和结果协议版本 3；
- masscan 可正常运行，zgrab2 为可选依赖。

部署前先检查本机 Nuclei 帮助和模板：

```bash
nuclei -version
nuclei -validate \
  -disable-unsigned-templates \
  -templates /opt/nuclei-templates/safe
```

参数名称以部署节点的 `nuclei -h` 为准；上游完整参数参考见
[ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei#usage)。

扫描器启动时会检查 `path` 指向可执行普通文件，并检查 `templates_path` 指向可访问目录。
任一检查失败时不会进入任务领取循环。

## 配置

```toml
[nuclei]
enabled = true
path = "nuclei"
templates_path = "/opt/nuclei-templates/safe"
bundled_templates_path = ""
update_templates = false
template_update_timeout_seconds = 300
severities = ["medium", "high", "critical"]
rate_limit = 20
bulk_size = 5
concurrency = 5
timeout_seconds = 10
retries = 1
max_runtime_seconds = 1800
max_findings = 10000
max_result_bytes = 262144
```

| 字段 | 默认值 | 有效范围或含义 |
|---|---:|---|
| `enabled` | `false` | 是否声明并执行漏洞扫描能力 |
| `path` | `nuclei` | 绝对/相对路径，或从 `PATH` 解析的命令名 |
| `templates_path` | 空 | 运行时模板目录；Docker 使用数据卷内的可写副本 |
| `bundled_templates_path` | 空 | 可选内置模板种子；Docker 为 `/opt/nuclei-templates/bundled` |
| `update_templates` | `false` | 本地启动时是否联网更新模板；只在 enabled=true 时执行 |
| `template_update_timeout_seconds` | `300` | 单次启动更新超时，1–3600 秒 |
| `severities` | medium/high/critical | 1–5 项：info、low、medium、high、critical |
| `rate_limit` | `20` | 全局每秒最大请求数，1–10000 |
| `bulk_size` | `5` | 每个模板并行分析的主机数，1–1000 |
| `concurrency` | `5` | 并行执行的模板数，1–1000 |
| `timeout_seconds` | `10` | 单次请求超时，1–300 秒 |
| `retries` | `1` | 失败请求重试次数，0–10 |
| `max_runtime_seconds` | `1800` | 单任务 Nuclei 最长运行时间，10–86400 秒 |
| `max_findings` | `10000` | 单任务最大漏洞结果数，1–100000 |
| `max_result_bytes` | `262144` | 单行 JSONL 最大字节数，4096–1048576 |

建议先使用默认低并发，在隔离测试资产上观察目标系统、扫描节点和出口网络负载后逐步调整。
`rate_limit` 是全局请求速率，`bulk_size` 是单模板的主机并行度，`concurrency` 是模板并行度，
三者不是同一个限制。

## 固定安全参数

扫描器通过参数数组直接启动进程，不经过 shell。有效调用等价于：

```text
nuclei
  -list <临时目标文件>
  -templates <templates_path>
  -severity <severities>
  -jsonl -silent
  -no-interactsh
  -disable-unsigned-templates
  -disable-update-check
  -rate-limit <rate_limit>
  -bulk-size <bulk_size>
  -concurrency <concurrency>
  -timeout <timeout_seconds>
  -retries <retries>
```

这些参数带来以下行为：

- `-no-interactsh` 排除依赖 OAST 的模板；
- `-disable-unsigned-templates` 拒绝未签名或签名不匹配的模板；
- `-disable-update-check` 禁止扫描命令隐式检查 Nuclei 或模板更新；
- 未传入 `-dast`、`-code` 或 `-headless`，因此不会主动启用这些高风险执行模式；
- 只解析标准输出中的 JSONL，不保存 Nuclei 原始 request/response 字段。

## 目标生成

目标来自本次任务的开放端口 observation，并去重、排序后写入临时文件：

- 已识别 HTTP/HTTPS/TLS 服务时生成带 scheme 的 URL；
- 常见 Web 端口使用内置 scheme 推断；
- 其他端点使用 `host:port`，由 Nuclei 模板协议决定处理方式；
- IPv6 地址使用 `[address]:port` 格式。

临时目标文件使用进程 ID 和 UUID 命名，正常结束、取消、超时和已处理的错误路径都会删除。

## 结果协议

漏洞结果使用协议版本 3 的 `vulnerability` observation。例如：

```json
{
  "kind": "vulnerability",
  "ip": "192.0.2.10",
  "port": 443,
  "protocol": "https",
  "template_id": "cve-example",
  "name": "Example vulnerability",
  "severity": "high",
  "matcher_name": "body",
  "matched_at": "https://192.0.2.10:443/",
  "description": "Structured template description",
  "remediation": "Apply the vendor update.",
  "tags": ["cve"],
  "references": ["https://example.invalid/advisory"],
  "classification": {},
  "extracted_results": [],
  "source": "nuclei",
  "observed_at": 1788393600000
}
```

服务端仅接受 `http://` 或 `https://` 引用，并对必填字段、严重级别、数组数量、单项长度和
总 JSON 大小进行验证。稳定身份由端点、模板 ID、matcher 和匹配位置组成，用于避免上传重试
产生重复记录。

## 模板更新与治理

Docker 镜像默认包含官方完整模板。CI 查询最新稳定 Release 后将 tag 解析为不可变提交，
两个原生架构使用相同的模板 SHA。镜像 labels、BUILD-INFO 与 `NM-BUNDLED-REVISION` 记录来源；
本地默认构建固定为 v10.5.0（2026-10-15 核对），也可显式传入模板版本和提交 build args。

env 开关为 `NM__NUCLEI__UPDATE_TEMPLATES`，文件部署对应 `[nuclei].update_templates`。
关闭时不执行更新命令；开启且 Nuclei enabled 时，在正常启动、领取任务前单独运行
`nuclei -update-templates -update-template-dir <暂存目录>`，只更新模板，不升级程序。
该命令不能附带 `-disable-update-check`，因为当前上游版本会连显式更新也一并禁用。
实际扫描命令仍固定关闭更新。启动准备、注册和健康检查的行为分别处理：注册/健康检查不更新模板。

模板在暂存目录准备，成功后替换活动目录；更新失败或超时保留旧目录并使本次启动报错。
目录切换中断会在下次启动恢复。默认数据卷保存可写副本，重建容器不会丢失已更新模板。
更换镜像内置版本会重新播种；希望只使用自定义目录时清空 bundled_templates_path。
本地更新开关不会由服务端远程配置开启。签名模块模式使用独立版本化模板包，不能同时启用本地更新。


推荐使用不可变、版本化的模板目录，例如 `/opt/nuclei-templates/2026-09-03`：

1. 在非生产目录获取候选模板；
2. 审阅模板协议、请求方法、路径、payload、签名和严重级别；
3. 使用与生产相同的 Nuclei 版本执行 `-validate`；
4. 在隔离测试资产上运行并人工复核命中；
5. 记录模板来源版本和目录 SHA-256 清单；
6. 将只读目录部署到扫描节点，修改 `templates_path` 并重启扫描器；
7. 观察失败率、请求量和误报后再扩大节点范围。

不要让 Web 服务账号、任务创建者或远程 API 对模板目录拥有写权限。不要在扫描器运行期间
原地修改模板目录。

## 上线与回滚顺序

首次上线必须先部署服务端数据库/API，再部署扫描器，最后部署前端。旧服务端会拒绝扫描器的
协议版本 3 结果。

建议的验收步骤：

1. 确认服务端数据库约束允许 `vulnerability_scan`、协议 3 和 vulnerability observation；
2. 启动启用 Nuclei 的扫描器，确认心跳包含 `vulnerability_scan` 和
   `vulnerability_detection`；
3. 使用隔离测试目标创建漏洞扫描任务；
4. 确认端口发现、可选服务识别和漏洞阶段依次执行；
5. 确认任务详情显示漏洞数量、严重级别、模板、修复建议和引用；
6. 检查缓存、服务端记录和日志中不存在原始请求/响应或凭据。

新版扫描器对端口、服务和漏洞结果都统一使用协议版本 3；仅设置
`nuclei.enabled=false` 不能恢复协议版本 2。回滚服务端前必须先停止新版扫描器领取任务，在
新服务端上排空其协议 3 待上传批次，再回滚扫描器二进制并确认旧节点恢复协议 2，最后才能
回滚服务端。SQLite 中仍有协议 3 待上传数据时，不应降级服务端或删除节点状态。

## 故障排查

### 节点不声明漏洞扫描能力

- 确认 `[nuclei].enabled=true`；
- 检查 `path` 是否可执行；
- 检查 `templates_path` 是否为可访问目录；
- 查看启动日志中的配置验证错误并重启节点。

### 漏洞任务一直等待

至少需要一台在线、地址族就绪且声明 `vulnerability_scan` 的扫描器。指定扫描器模式还要求
所选节点同时满足这些条件。

### Nuclei 非零退出

任务会失败而不是上传不完整结果。使用相同 Nuclei 和模板目录在节点上执行 `-validate`，再
检查签名不匹配、模板语法、文件权限、网络超时及 stderr 摘要。

### 命中存在但任务失败

任一无效 JSONL 行、单行过大、结果数超限或总运行时间超限都会使漏洞阶段失败。结合日志中的
`invalid JSONL`、`max_result_bytes`、`finding limit` 或 `runtime limit` 信息处理，不要通过无限
提高限制绕过异常模板。

### 预期的 OAST 漏洞没有结果

这是默认安全策略：`-no-interactsh` 会排除 OAST 模板。当前实现不提供远程开启方式。
