# First Scan

Use a controlled test application or a lab target.

```bash
cargo run --bin nexus -- scan https://example.com --scan-type full
```

Review the output for:

- Injection findings
- Missing headers
- CORS misconfigurations
- SSRF indicators
