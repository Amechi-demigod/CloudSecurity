# Approved device scripts

Each directory is one script that admins can run on enrolled devices from the
console (**Devices > Scripts**). Scripts are changed **only by pull request**
(code review), published as a bundle signed with the script-signing key by
`.github/workflows/device-scripts-release.yml` (tag `scripts-vX.Y.Z`), and the
agent verifies the signature and the script's SHA-256 right before running it.

```
device-scripts/<name>/manifest.json   name, description, platform, interpreter, timeout, risk, typed parameters
device-scripts/<name>/script.ps1|.sh|.zsh
```

Parameters reach the script only as environment variables `CNAPP_PARAM_<NAME>`
(upper-case), validated against the signed schema; they are never put on a
command line. Scripts run as SYSTEM (Windows) / root (macOS) with a timeout;
stdout and stderr are truncated.

`risk: low` is for read-only information scripts: one admin can run them.
`medium` / `high` need a second admin's approval. Reviewers: check that the
risk level is honest, that the script cannot be steered by its parameters
beyond what the schema allows, and that it prints what an admin needs.

Validate locally: `python scripts/device_scripts.py lint`. Full guide:
[docs/DEVICE_SCRIPTS.md](../docs/DEVICE_SCRIPTS.md).
