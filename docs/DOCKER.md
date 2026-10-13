# Docker 扫描端部署

启动配置检查兼容文件部署和 Docker 只读配置挂载；终端、日志及控制端 Web 提示见 [启动配置检查](CONFIG_CHECK.md)。

[项目首页](../README.md) · [文档中心](README.md) · [masscan](MASSCAN.md) · [恢复](recovery.md)

镜像 `ghcr.io/wshijiang/network-mapping-scanner` 支持 Linux AMD64/ARM64，包含 scanner-rs、
官方 masscan 1.3.2、zgrab2 v1.0.0 和 Nuclei v3.11.1。全部工具固定提交，Nuclei 默认关闭，
镜像不包含模板。许可证及对应源码见 [第三方工具说明](../docker/THIRD_PARTY.md)。
Rust 1.98.0、Go 1.26.8 与运行环境均基于 Debian 12，基础镜像固定多架构 digest。

## 本地构建与准备

从 `Network-Mapping-Scanner/` 运行：

```sh
docker buildx build --build-arg REVISION="$(git rev-parse HEAD)" \
  --tag network-mapping-scanner:local --load .
mkdir -p docker/runtime
cp docker/config.example.toml docker/runtime/config.toml
cp docker/.env.example docker/.env
```

修改 `scanner.c_server`、`c_port` 和 `upload.endpoint` 指向同一服务端；上传地址使用该服务器的
实际 API 路径。保留 verify_tls=true、官方 masscan 绝对路径及 standard_list 模式。
`.env` 的 SCANNER_IMAGE 填已批准版本或完整 digest。私有 CA 可按 Compose 注释挂载完整可信 CA bundle，
其中保留公共根证书；不要以关闭证书校验替代安装 CA。配置文件需 root 可读且其他用户不可读，
管理员可使用属主 0:0、模式 0400；容器删掉了 DAC_OVERRIDE，root 也不能绕过任意文件权限。

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

在服务端创建扫描器后取得一次性 ID/Token。正常进程没有身份时会退出，因此先执行注册任务。
从扫描仓库运行，交互读取 Token，避免写入 Compose 或 shell 历史：

```sh
read -r -p 'Scanner ID: ' SCANNER_ID
read -r -s -p 'Registration token: ' SCANNER_TOKEN
printf '\n'
docker compose --env-file docker/.env -f docker/compose.example.yml run --rm scanner \
  --config /etc/network-mapping-scanner/config.toml \
  --database /var/lib/network-mapping-scanner/scanner-state.sqlite3 \
  --state-file /var/lib/network-mapping-scanner/scanner-state.json \
  --log-directory /var/log/network-mapping-scanner \
  --id "$SCANNER_ID" --token "$SCANNER_TOKEN"
unset SCANNER_TOKEN
docker compose --env-file docker/.env -f docker/compose.example.yml up -d
```

CLI 仍通过参数传 Token，注册期间有宿主机进程/容器检查权限的用户可能看到该参数；限制节点管理权限。
注册成功会保存 SQLite 身份并退出，日常启动不得重复携带注册参数。
已有节点迁移时先停止原进程，保留完整数据库及对应日志/旧状态；新镜像使用同一状态目录。
若旧 TOML 含 token/runtime_token，清理秘密使用 rename，需要临时挂载可写的配置目录，
不能只绑定单个可写 TOML 文件。身份入库并清理后恢复只读配置。

## Nuclei 与节点验收

启用漏洞扫描时，将审核、签名、固定版本的模板目录按 Compose 注释只读挂载，设置 enabled=true。
镜像不下载模板、不安装浏览器、不主动启用 headless/code/OAST。XDG 配置和缓存写入数据卷，
模板更新、签名与实际 Nuclei 调用约束参见 [Nuclei 文档](NUCLEI.md)。

CI 从 OCI 产物检查版本/架构/config digest，在隔离 Docker 网络中的一个临时 ES HTTP 端点上验证
NET_RAW、官方 masscan list 输出和 zgrab2 HTTP 握手，并核对 Nuclei 版本；不扫描外部地址。
临时 ES 数据目录使用最大 1 GiB 的 tmpfs，隔离 runner 构建缓存造成的磁盘水位压力；
只有集群健康为 green/yellow 且等待未超时才开始扫描。就绪等待最多 180 秒，容器提前退出或
被 OOM 杀死会立即报错；诊断和清理命令各限制为 10 秒，失败后仍继续清理并保留原始错误。
生产必须进一步验证 host 网络、IPv4/IPv6、服务端注册/心跳、任务取消、断线恢复、
SQLite 上传恢复和审核模板联调。没有周期执行 --health-check：该 CLI 会打开状态数据库，
且当前实现远端健康失败仍可能返回成功，不适合作为容器自动重启依据。以服务端心跳和诊断监控节点。

## GitHub 自动构建与发布

`.github/workflows/docker.yml` 在 `main`、`dev`、`dev/**`、`feature/**`、`fix/**`、
`release/**` 提交以及面向 `main`/`dev` 的 PR 上运行；扫描仓库另外兼容现有 `rust` 分支。
`workflow_dispatch` 只构建，不发布。工作流文件需先进入远端相应分支，手动入口需在默认 `main` 中存在。

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

发布生成 `vX.Y.Z` 和 `sha-<完整提交>`；不自动维护 `latest`，避免并发旧版本覆盖新版本。
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
