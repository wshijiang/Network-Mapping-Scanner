# Docker 扫描端部署

启动配置检查兼容文件部署和 Docker env 配置；终端、日志及控制端 Web 提示见 [启动配置检查](CONFIG_CHECK.md)。

[项目首页](../README.md) · [部署总览与原生安装](DEPLOYMENT.md) · [文档中心](README.md) · [masscan](MASSCAN.md) · [恢复](recovery.md)

镜像 `ghcr.io/wshijiang/network-mapping-scanner` 支持 Linux AMD64/ARM64，包含 scanner-rs、
官方 masscan 1.3.2、zgrab2 master 快照 `835aa538`（2026-10-22 UTC，含 RDP） 和 Nuclei v3.11.1。全部工具固定提交，Nuclei 默认关闭，
镜像内置官方最新稳定版模板，CI 在 prepare 中解析一次不可变提交供两种架构共用。许可证及对应源码见 [第三方工具说明](../docker/THIRD_PARTY.md)。
Rust 1.98.0、Go 1.26.8 与运行环境均基于 Debian 12，基础镜像固定多架构 digest。

使用已有镜像无需本地编译。先完成服务端部署，所有命令从 `Network-Mapping-Scanner/` 运行；需要 Docker Engine 与 Compose ≥ 2.20，host 网络面向 Linux 主机。

[准备配置](#准备运行配置) · [注册与启动](#首次注册与运行) · [节点验收](#nuclei-与节点验收) · [升级与恢复](#升级与恢复) · [常见问题](#常见问题) · [本地构建](#可选本地构建) · [CI 发布](#github-自动构建与发布)

## 准备运行配置

从 `Network-Mapping-Scanner/` 运行：

```sh
mkdir -p docker/runtime
cp docker/.env.example docker/.env
chmod 0600 docker/.env
```

编辑 `docker/.env`：`SCANNER_IMAGE` 填已批准版本或完整 digest，
`NM__SCANNER__C_SERVER`、`NM__SCANNER__C_PORT` 指向服务端。
上传地址默认从同一主机和端口生成，也可设置 `NM__UPLOAD__ENDPOINT`。
主机字段只填主机名/IP，不填协议、端口和路径；使用服务端的**实际对外入口**，例如代理后的域名与 443。跨主机不能填 `localhost`，也不能使用服务端 Compose 内部服务名 `server`。模板中的镜像占位版本必须替换。`cp` 仅用于首次安装，已有节点编辑原文件并保留数据卷。
Docker 默认 `--config-source env`，Compose 通过 `env_file: ./.env` 注入参数，无需挂载 TOML。
变量按 `NM__SECTION__FIELD` 映射到 `section.field`，数字/布尔按字段类型解析，数组使用 JSON。
未知变量报错；可通过对应的 `_FILE` 变量读取 Secret，直接值与 `_FILE` 不得同时提供。
`.env` 建议设为 0600，不提交到仓库。修改后通过 `up -d --force-recreate` 重建容器，restart 不更新环境。

文件部署继续使用 `--config config.toml`（默认 file 模式），不会被环境配置隐式覆盖。
私有 CA 可按 Compose 注释挂载完整可信 CA bundle；保留 `NM__SCANNER__VERIFY_TLS=true`。
例如将包含所需公共 CA 与私有根 CA 的 PEM bundle 放在 `docker/runtime/ca-certificates.crt`，取消 Compose 对应挂载的注释。该绑定会替换容器的系统 CA bundle，应保留所需公共信任链，供服务端、模板更新和备用公网 IP 接口使用；无需复制服务端私钥。

首次启动前确认镜像可拉取、服务端 HTTPS 从此主机可达、授权目标路由正确、数据卷独立，且节点内存/磁盘足够。镜像已有引擎和模板，不要覆盖整个 `/usr/local/bin` 或可写状态目录来“补装”工具。

## 权限、网络与状态

Compose 面向 Linux Docker Engine，采用 host 网络，不使用 ports。初版以 root 启动并删除全部
默认 capabilities，仅添加 NET_RAW，确保原始套接字权限能传递到 masscan 子进程；
没有 privileged、Docker socket 或宿主机根目录挂载。必要的 NET_ADMIN 必须在节点实测后单独增加。
不建议直接改成非 root，需先验证 capability 继承和 raw-socket 操作；rootless Docker 与 Desktop
不视为已验证扫描环境。host 网络保留宿主机接口、路由和 IPv6 能力，也扩大网络访问范围，
扫描任务只能面向已授权资产。

scanner-data 保存 SQLite、WAL/SHM、身份、上传进度和旧 JSON 导入文件，scanner-logs 保存日志。
每个节点独立一份数据卷，不能让多个进程共享 SQLite 或复制同一身份到多个节点。
不要使用只挂载 sqlite3 单文件的方式，不要清空状态解决断线问题。
镜像 STOPSIGNAL 和 Compose 都使用 SIGINT，stop_grace_period 为 90 秒；现有程序仅处理 SIGINT，
超时后的 SIGKILL 仍可能中断任务，需观察停止时长。当前尚未新增 SIGTERM 支持。

## 首次注册与运行

在服务端创建扫描器后，把 ID 和一次性 Token 填入 `docker/.env`：

```dotenv
NM__REGISTRATION__SCANNER_ID=控制台返回的UUID
NM__REGISTRATION__TOKEN=控制台返回的一次性Token
```

```sh
docker compose --env-file docker/.env -f docker/compose.example.yml config --quiet
docker compose --env-file docker/.env -f docker/compose.example.yml pull
docker compose --env-file docker/.env -f docker/compose.example.yml up -d
docker compose --env-file docker/.env -f docker/compose.example.yml ps
docker compose --env-file docker/.env -f docker/compose.example.yml logs --tail=100 scanner
```

`config --quiet` 只验证 Compose 结构与插值，不验证 Token、应用参数、引擎或远端就绪。配置展开和容器环境可能含凭据，排障时只共享脱敏日志。私有 GHCR 包需要注册表读取权限。

首次启动自动注册，将运行令牌和注册凭据 SHA-256 摘要一起原子写入 SQLite，然后继续运行。
容器重启或重建时，如果凭据摘要未变化，直接恢复身份，不再消耗注册 Token。
更换一次性 Token 后重建容器会重新注册；失败不替换本地身份、不记录成功摘要。
若服务端已消耗 Token 而响应或本地落盘失败，需要重新签发 Token，注册接口与本地数据库不是跨系统事务。
注册成功后可以删除 Token；只保留相同 ID 或同时删除注册两项均可继续恢复身份。
清除 `.env` 中的注册 Token 后，在任务边界使用 `up -d --force-recreate scanner` 更新容器环境，确认仍沿用 scanner-data 中的身份。
更换 ID 时若有未上传结果会拒绝切换。数据卷丢失或更换服务端地址后，需要重新签发注册凭据。
运行令牌失效不会触发无限注册重试，应由管理员提供新的一次性 Token。

显式 CLI `--id`/`--token` 仍执行注册后退出；env 自动注册则继续进入正常扫描流程。
注册参数不写回 `.env`，一次性 Token 明文不写入 SQLite。健康检查不自动注册或更新模板。
新状态库版本为 4；旧库自动升级并保留身份及待上传结果，旧版本程序不能直接打开升级后的库。
已有节点迁移时先停止原进程，保留完整数据卷；无需把运行令牌复制进 env。

## Nuclei 与节点验收

镜像内置 masscan、zgrab2、Nuclei 和官方模板，默认无需额外安装或挂载模板。
`NM__NUCLEI__ENABLED=true` 开启漏洞扫描，`NM__NUCLEI__UPDATE_TEMPLATES=true` 允许正常启动时
联网更新一次；默认 false，只使用镜像内置或已经缓存的模板。
内置模板位于 `/opt/nuclei-templates/bundled`，首次启用会复制到 scanner-data 中的可写模板目录。
新镜像的内置版本变化时会重新初始化；运行时更新在独立暂存目录进行，成功后替换，
失败或超时保留原模板并报错。模板版本和提交记录在镜像 labels、BUILD-INFO 及模板目录中。
更新只涉及模板，不升级 Nuclei 二进制；每次实际扫描仍关闭隐式更新，并保留签名和协议限制。
文件配置的对应开关为 `[nuclei].update_templates`，最长更新时限由 `template_update_timeout_seconds` 控制。
模块模式使用签名版本化模板包，不能同时启用本地启动更新。完整说明见 [Nuclei 文档](NUCLEI.md)。

CI 从 OCI 产物检查版本/架构/config digest，在隔离 Docker 网络中的一个临时 ES HTTP 端点上验证
NET_RAW、官方 masscan list 输出和 zgrab2 HTTP 握手，并核对 Nuclei 版本；不扫描外部地址。
临时 ES 数据目录使用最大 1 GiB 的 tmpfs，隔离 runner 构建缓存造成的磁盘水位压力；
只有集群健康为 green/yellow 且等待未超时才开始扫描。就绪等待最多 180 秒，容器提前退出或
被 OOM 杀死会立即报错；诊断和清理命令各限制为 10 秒，失败后仍继续清理并保留原始错误。
生产必须进一步验证 host 网络、IPv4/IPv6、服务端注册/心跳、任务取消、断线恢复、
SQLite 上传恢复和审核模板联调。没有周期执行 --health-check：该 CLI 会打开状态数据库，
且当前实现远端健康失败仍可能返回成功，不适合作为容器自动重启依据。以服务端心跳和诊断监控节点。

### 现场验收

- 控制台显示注册后的同一 ID、持续心跳和 `accepting_tasks=true`，所需 IPv4/IPv6 与 profile 可用。
- 对已授权的小范围目标完成端口任务，再按需测试服务识别、DNS、Nuclei；确认 `ResultUploadCompleted` 和控制台可查询结果。
- 正常 `stop scanner` 使用 SIGINT，状态和引擎正常收尾；再次 `up -d scanner` 恢复原身份，不消耗注册 Token。
- 在维护窗口验证断线恢复与保留卷重建；观察日志、上传状态和服务端任务归属，不能仅以容器 running 判断扫描可用。
- 监控 scanner-data、scanner-logs 的磁盘空间，备份配置与状态，并确认每个节点使用不同数据卷。

## 升级与恢复

1. 记录当前镜像 digest、引擎/模板版本和配置，核对目标版本的协议及 schema 兼容性。先验收服务端，再选择一个节点试升级；暂停新任务分配并等待上传完成。
2. 在 `.env` 中修改 `SCANNER_IMAGE` 为固定版本/digest，保持服务端地址、项目名和卷不变，先校验、拉取并停止节点：

   ```sh
   docker compose --env-file docker/.env -f docker/compose.example.yml config --quiet
   docker compose --env-file docker/.env -f docker/compose.example.yml pull scanner
   docker compose --env-file docker/.env -f docker/compose.example.yml stop scanner
   ```

3. 确认节点与扫描引擎已退出，以现有卷备份工具保存**整个 scanner-data** 及配置/日志；挂载目录部署则停机备份整个目录。不要在运行中仅复制 SQLite 主文件；还需包含 WAL/SHM、诊断库/快照及已启用的模块资源。
4. 重建节点并检查日志：

   ```sh
   docker compose --env-file docker/.env -f docker/compose.example.yml up -d --force-recreate scanner
   docker compose --env-file docker/.env -f docker/compose.example.yml logs --tail=100 scanner
   ```

5. 验收身份恢复、心跳、引擎能力及授权任务，再逐批升级其他节点。正常升级无需重新注册或填写运行令牌。

Compose 项目名默认为 `network-mapping-scanner`。同一 Docker 主机部署多个节点时，为每个节点使用独立配置与固定 `-p` 项目名、独立 ID，且所有命令保持该项目名；否则会操作同一容器和数据卷。更换项目名会创建新的空卷，不能把它误判为身份失效。

旧程序可能拒绝升级后的 schema 4。回滚需先确认兼容性，必要时停机恢复升级前完整数据备份，再用旧 digest 重建；服务端可能已接收部分批次，恢复后按任务归属和幂等上传收敛。不要执行 `down -v`、清空 SQLite 或复制其他节点身份。Nuclei 内置模板也可能随镜像改变，回滚验收应核对实际模板版本，详见 [Nuclei 指南](NUCLEI.md)。

## 常见问题

| 现象 | 优先检查 |
| --- | --- |
| 镜像拉取失败 | 占位版本、GHCR 包权限/可见性、目标架构 |
| 证书错误 | 服务端域名、可信 CA bundle 是否挂入容器，保留 TLS 校验 |
| 注册失败/Token 已使用 | ID 与 Token 是否配对、是否已消费；重新签发后重建容器，保留原状态 |
| 重建后要求注册 | 项目名和 scanner-data 是否改变、服务端 origin 是否改变；先找到原身份库 |
| 在线但不接任务 | 查看启动引擎检查、`accepting_tasks`、维护状态和地址族/profile |
| raw-socket 权限错误 | 是否为已验证的 Linux host 网络、root + NET_RAW，接口与引擎权限是否正确 |
| env 修改未生效 | 使用原 `.env` 与 Compose 文件重建容器；restart 不更新环境 |
| SQLite/诊断锁冲突 | 是否有其他容器、原生进程或维护命令共享同一数据目录 |
| 停止后被强杀 | 检查 SIGINT、实际收尾耗时、90 秒预算及磁盘/子进程状态 |

## 可选本地构建

仅需要自定义镜像时，在扫描端仓库执行：

```sh
docker buildx build --build-arg REVISION="$(git rev-parse HEAD)" \
  --tag network-mapping-scanner:local --load .
```

把 `.env` 中 `SCANNER_IMAGE` 设置为 `network-mapping-scanner:local`，使用前述配置与启动步骤；本地镜像无需执行远端 `pull`。此构建不会发布镜像，工具和模板来源仍以 Dockerfile 固定提交为准。

## GitHub 自动构建与发布

`.github/workflows/docker.yml` 在 `main`、`dev`、`dev/**`、`feature/**`、`fix/**`、
`release/**` 提交以及面向 `main`/`dev` 的 PR 上运行；扫描仓库另外兼容现有 `rust` 分支。
`workflow_dispatch` 留空版本时只构建；填写 `promote_version` 时只提升已发布镜像的 latest。工作流文件需先进入远端相应分支，手动入口需在默认 `main` 中存在。

两个原生 runner 分别构建 `linux/amd64` 与 `linux/arm64`，Dockerfile 内执行
`cargo fmt --check`、`cargo clippy --locked --all-targets`、`cargo test --locked` 和 release 构建。
GHA 缓存按组件/架构分开，Cargo.lock 和基础镜像 digest 固定；APT 软件仓库仍会变化，
因此不承诺不同日期重新构建有相同字节。缓存失效不会影响正确性。

Docker 使用固定版本 `cargo-chef 0.1.78`：先从真实 manifests 和目标列表生成依赖配方，
再分别预编译 Clippy、开发/测试和 release 依赖。编译产物保存在普通 Docker 层中，
由现有 `type=gha,mode=max` 跨运行保存；没有需要额外导出的 BuildKit cache mount。
只修改业务源码时配方保持不变，依赖编译层可复用；依赖、features、工具链或基础镜像变化时重新构建。
真实 Cargo.toml、Cargo.lock、build.rs、源码和编译期资源在预编译后恢复，随后执行完整检查和测试。
Cargo 构建和测试使用默认并发，不设置 jobs 或 test-threads。

独立归档构建通过固定提交的 `Swatinem/rust-cache` 缓存 Cargo 下载和依赖编译产物，
按组件/目标三元组、Rust 编译器及构建环境区分；musl 的链接器和 RUSTFLAGS 在恢复缓存前配置。
`release.yml` 在 main 的 Cargo.toml、Cargo.lock、build.rs 或该工作流变化时预热四个目标的缓存，
此路径不打包、不上传归档、不发布。普通业务源码提交不额外触发预热。
只有 main 和 tag 运行写 Cargo 缓存；手动运行其他分支只读取可访问的缓存。
tag/手动归档构建保留原有行为，GitHub Release 发布仍要求 tag push。
Cargo 缓存和 Docker GHA 缓存共同占用仓库缓存容量；比较冷缓存、重复构建、源码修改和依赖更新的
总耗时及缓存传输耗时，容量不足或缓存过期时允许回退到完整编译。

镜像以包含 SBOM/最小构建来源证明的 OCI archive 保存为 Actions artifact，保留 14 天。
CI 校验所有 blob 摘要、镜像版本/提交/架构、前端提交（服务端）和归档 SHA-256，
再将同一产物导入 Docker 执行冒烟测试。发布复制这些产物，不重新编译。
SBOM/来源证明只说明构建组成与来源，不等同于镜像签名。

首次启用前，在对应仓库完成：

1. 确认 Actions 可使用 `ubuntu-24.04-arm`；私有仓库额度/runner 可用性不足时需提供相同架构的 runner。
2. 创建 `container-release` Environment，允许正式版本 tag，按套餐能力配置 Required reviewers。
   私有仓库并非所有套餐都支持 reviewer 门禁；无此能力时保留逐版本人工授权和受限 tag 创建权限。
3. 将仓库变量 `DOCKER_PUBLISH_ENABLED` 设置为 `true` 才启用镜像发布。
   该变量是功能开关，不代表对任何组件或版本的发布授权。
4. GHCR 使用 `GITHUB_TOKEN`，只在发布 job 授予 `packages: write`；确认包关联仓库与 Actions 写权限。
   首次发布后人工确认包可见性，私有镜像拉取需要相应读权限。

**只有用户批准明确组件、版本、提交及远端写操作后才可推送 `vX.Y.Z` tag。**
tag 必须与 Cargo.toml/Cargo.lock 版本一致，且提交已包含于远端 `main`。
分支、PR 和手动构建不写 GHCR。正式发布前执行仓库 AGENTS.md 的完整预检，
包括依赖提交在远端可达、二进制版本、测试、归档检查和具体推送顺序。

首次引入 Docker 发布也应使用新的、明确批准的版本，不能为触发新工作流重推或复用已发布 tag。

发布生成 `vX.Y.Z` 和 `sha-<完整提交>`；稳定版本发布成功后自动维护以下可移动标签：

| 标签 | 运行架构 |
| --- | --- |
| `ghcr.io/wshijiang/network-mapping-scanner-amd64:latest` | 仅 Linux AMD64，保留该架构的构建证明 |
| `ghcr.io/wshijiang/network-mapping-scanner-arm64:latest` | 仅 Linux ARM64，保留该架构的构建证明 |

`docker/latest.py` 先读回正式版本，核对组件、Git tag 对应提交、两种架构的配置和各自证明的关联。
按数值比较稳定版本，旧版本不能覆盖更新的 latest；预发布版本不移动 latest。
所有标签更新与正式发布共享仓库级并发锁。两个架构使用独立的镜像名称，各自维护 `:latest`。
Skopeo 跨镜像仓库复制对应架构的全部 layers 和构建证明，逐个读回核对 digest；
注册表不支持两个镜像仓库的原子事务，失败后可重试修复部分更新。
版本与 SHA 标签保持不可变，latest 不替代生产部署的 digest 固定。

已有正式镜像可在 **Docker images → Run workflow** 填写 `promote_version`（如 `0.1.19`），
复用相同校验与 `container-release` 环境，仅补齐 latest，不构建、不重推版本或 SHA 标签。
此入口不依赖 `DOCKER_PUBLISH_ENABLED`：它只提升已存在的正式镜像；留空仍只构建。
首次创建这两个 GHCR 包后，检查它们各自的可见性和 Actions 访问权限。

若任一正式标签已经存在，立即拒绝覆盖。网络/认证失败也会停止，不能视为标签不存在。
发布后读回 manifest，确认两种架构、证明文件和标签 digest 一致，并在运行摘要记录 digest。
`build-<run-id>-<attempt>-<arch>` 是发布阶段上传 OCI 的暂存标签，不是稳定版本；暂不自动删除。

归档发布工作流 `release.yml` 与镜像工作流分别由同一次已授权 tag push 触发，
避免依赖 `GITHUB_TOKEN` 创建 Release 后不会自动触发的 `release: published` 事件。
两条工作流没有跨工作流原子性：需监控两条运行。任一步失败时保留状态并报告，
未经新的明确授权不能重跑发布、删除/覆盖标签或静默重新发布。

生产部署固定完整 digest；升级前备份数据库和配置，检查 schema/结果协议兼容性，
回滚不清空状态、不重新注册。已有数据库的自动升级不能靠旧镜像降级自动撤销。

## 开发验证

从对应 Rust 仓库运行：

```sh
python3 -m unittest discover -s docker -p 'test_*.py'
python3 docker/ci.py metadata --component scanner
shellcheck docker/publish.sh
actionlint .github/workflows/docker.yml .github/workflows/release.yml
```

新代码的 OCI 合约测试会拒绝损坏 blob、错误版本/提交/架构、缺少证明、归档路径穿越和错误校验和。
容器冒烟必须有 Docker Engine、Buildx、Skopeo 和 OpenSSL；无 Docker 权限时不能把容器验收记为通过。
后端 cargo test 默认跳过需要真实数据库的 ignore 测试，CI 容器冒烟不代表全部数据库集成测试已通过。

官方参考：[多架构构建](https://docs.docker.com/build/ci/github-actions/multi-platform/)、
[构建来源证明](https://docs.docker.com/build/ci/github-actions/attestations/)、
[GHA 缓存](https://docs.docker.com/build/cache/backends/gha/)、
[GHCR 发布](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)、
[Environment 门禁](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)。


### CI 构建磁盘占用

扫描镜像同时编译 Rust 三个程序、zgrab2 和 Nuclei。Docker 层会保留每个
RUN 结束时的文件，Go 模块与编译缓存留在前一个层后，即使后续删除也不能
回收该层空间。本构建在各工具的编译 RUN 内复制二进制、许可证和 blocklist
后立即清理 Go 缓存和源码。Rust CI 关闭 dev/test 调试符号与增量编译，仍执行
全部检查和测试，release 优化配置保持原样。

两个一次性 GitHub runner 在构建前清理未使用的预装 SDK 和 Docker 缓存；
OCI 与 GHA 缓存导出完成后、导入镜像进行 smoke test 前清理 Buildx 快照。
工作流在这些节点输出磁盘容量。清理不涉及发布产物、节点数据库或生产主机。
