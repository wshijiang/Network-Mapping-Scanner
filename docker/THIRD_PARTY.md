# 扫描工具来源与许可证

工具源码保持未修改；镜像的 licenses/ 保留上游许可证，BUILD-INFO 记录固定提交。

| 工具 | 版本 | 对应源码 |
| --- | --- | --- |
| masscan | 1.3.2 | https://github.com/robertdavidgraham/masscan/tree/06902c40d1494881c17b7968ef530e1d6bbd320c |
| zgrab2 | v1.0.0 | https://github.com/zmap/zgrab2/tree/ea734bcf60ef2921684cb522dfb87a07a322afa6 |
| Nuclei | v3.11.1 | https://github.com/projectdiscovery/nuclei/tree/a8c88feb4a1c8e961b7902534ce3af97e9d524a4 |

masscan 使用 AGPL。分发镜像时，分发方必须按其许可证提供对应源码及构建说明；
固定源码可以从上述提交页面或 GitHub 的该提交归档取得，构建步骤见根目录 Dockerfile。
如修改工具，须同步提供修改后的对应源码，不能只链接未修改的上游。
Nuclei 模板不包含在镜像内，模板的来源、版本、签名和许可证由部署方独立审核。
