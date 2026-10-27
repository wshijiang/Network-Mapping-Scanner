# 扫描工具来源与许可证

工具源码保持未修改；镜像的 licenses/ 保留上游许可证，BUILD-INFO 记录固定提交。

| 工具 | 版本 | 对应源码 |
| --- | --- | --- |
| masscan | 1.3.2 | https://github.com/robertdavidgraham/masscan/tree/06902c40d1494881c17b7968ef530e1d6bbd320c |
| zgrab2 | master snapshot 835aa538 (2026-10-22 UTC) | https://github.com/zmap/zgrab2/tree/835aa53808aed88b4c3e017d623b374fb26dca95 |
| Nuclei | v3.11.1 | https://github.com/projectdiscovery/nuclei/tree/a8c88feb4a1c8e961b7902534ce3af97e9d524a4 |

masscan 使用 AGPL。分发镜像时，分发方必须按其许可证提供对应源码及构建说明；
固定源码可以从上述提交页面或 GitHub 的该提交归档取得，构建步骤见根目录 Dockerfile。
如修改工具，须同步提供修改后的对应源码，不能只链接未修改的上游。
Nuclei 官方模板随镜像分发，来源为 https://github.com/projectdiscovery/nuclei-templates 。
CI 在每次构建前解析最新稳定 Release，两个架构固定同一提交；本地默认 v10.5.0，
对应 f8b8b8dcd70d93826c3767e1829ef8243af9f03b（2026-10-15 核对）。
模板上游 LICENSE.md 保存在镜像 licenses/nuclei-templates/ 中，来源记录在 BUILD-INFO 与 OCI labels。
运行时可选择更新模板，实际执行仍受扫描器签名、协议、目标和速率设置约束。
