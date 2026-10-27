# Network Mapping Scanner documentation

This is the English entry point for the scanner component. The first translated pages cover deployment and language support. Advanced topics currently remain in Chinese and are linked explicitly below.

- [Deployment and verification](DEPLOYMENT.md)
- [Language selection and documentation maintenance](LOCALIZATION.md)
- [Complete Chinese documentation](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/README.md)
- [Change log (Chinese)](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/CHANGELOG.md)
- [Source repository](https://github.com/wshijiang/Network-Mapping-Scanner)

## Release preparation

This component is preparing **0.1.21**, paired with server **0.1.30**, scanner **0.1.21**, and web console **0.1.24**. Release PRs remain open for review; version tags are local only. Existing installations must complete the transport endpoint migration before enabling new UDP tasks. Upgrade the Agent, Worker and complete module bundle together to IPC **3**, retaining node identity and pending results. See the [release and upgrade procedure (Chinese)](https://github.com/wshijiang/network-mapping/blob/main/docs/RELEASING.md) and the change log above for scope, rollback and tag checks after merging.

## Service detection fixes

RDP now uses native TPKT/X.224 negotiation on TCP/3389 or an explicitly selected custom port.
A validated negotiation response or rejection identifies the service; no credentials, TLS/CredSSP
session or desktop session are attempted. Bare legacy X.224 confirms remain unidentified to avoid
confusing RDP with other protocols. Automatic detection on custom ports remains subject to probe budgets.
The pinned zgrab2 build has no RDP module, so RDP is excluded from its INI configuration. External
configurations include only modules used in the current batch. Upgrade the matching Agent, Worker and
module bundle; see the [usage and troubleshooting guide (Chinese)](../USAGE.md).
Native TCP and active UDP evidence now also removes NUL characters and enforces `max_result_bytes`,
marking truncated evidence instead of allowing invalid database strings or oversized handshake details.

## Related components

- [Server documentation](https://github.com/wshijiang/network-mapping/blob/main/docs/README.md)
- [Web console documentation](https://github.com/wshijiang/network-mapping-vue/blob/main/docs/README.md)
- [Scanner documentation](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/README.md)

The language menu switches to the translated counterpart when one exists. Otherwise it opens that language's documentation home. Translations do not change CLI options, API fields, protocol names or original evidence. Check the complete Chinese reference for features not covered here.
