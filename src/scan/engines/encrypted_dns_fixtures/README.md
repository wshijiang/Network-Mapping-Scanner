# Local protocol test credentials

This private key and test CA/server certificate are deliberately public fixtures,
created only for loopback DoT/DoH tests. Never use them for deployments.
The CA private key is not included. The server certificate covers `probe.test`,
`127.0.0.1` and `::1`; tests validate certificates rather than disabling TLS.
