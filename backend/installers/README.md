# Bundled agent installers

CI (`.github/workflows/ci.yml`, job `images`) places the generic, unconfigured
installers here before building the backend image:

* `cnapp-agent-windows-x64.msi`    - WiX MSI (no enrollment properties set)
* `cnapp-agent-macos-universal.pkg` - pkgbuild component package
* `manifest.json`                  - `{"version": "...", "files": {"<name>": "<sha256>"}}`

The server copies one per download and injects the enrollment config
(`app/services/installers.py`). Files whose SHA-256 does not match
`manifest.json` are refused. Nothing here is committed except this README;
set `AGENT_INSTALLERS_DIR` to serve installers from another directory
(e.g. your own signed builds). See docs/DEVICE_MANAGEMENT.md.
