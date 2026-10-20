# ADR-0001: Signed, reviewed device scripts (and why the agent stays bounded)

- **Status:** accepted
- **Date:** 2026-10-20
- **Context area:** endpoint agent, device management

## Context

Until now the endpoint agent had one hard rule: it **never runs commands or
scripts sent by the server**. It executed a fixed allow-list of actions
(re-check posture, collect logs, lock, restart, change interval), so even a
fully compromised CNAPP server could not run code on laptops. Self-update
(docs/AGENT_UPDATES.md) already relaxed this in one bounded way: the server can
make devices run a new agent binary, but only one signed by a release key the
server never holds.

Admins now need small, routine fixes and lookups on devices (list local
administrators, restart the print spooler, clean temp files) without a
separate RMM tool. Adding a generic "run this PowerShell" would turn the CNAPP
server, and every admin account, into a remote root shell on the fleet.

## Decision

Allow **only approved scripts**, with every trust decision made outside the
server and re-checked on the device:

1. **Source of truth is the repository.** Scripts live in
   `device-scripts/<name>/` with a manifest (platform, interpreter, timeout,
   risk level, typed parameters). They change only through pull requests,
   i.e. code review.
2. **Signed bundles, dedicated key.** A tag `scripts-vX.Y.Z` runs
   `.github/workflows/device-scripts-release.yml` in the protected environment
   `script-release`, which signs a manifest containing the SHA-256 of every
   script with `SCRIPT_SIGNING_KEY` (Ed25519). This key is separate from the
   agent release key, uses its own domain-separation string, and never exists
   on the CNAPP server.
3. **The agent decides.** Agents trust only script-signing public keys
   compiled into them. Right before running, the agent fetches the signed
   manifest and the script, verifies signature, expiry, anti-rollback,
   platform and the script hash, and validates the parameters against the
   *signed* typed schema (int ranges, enums, booleans, anchored patterns). No
   free-form input exists.
4. **Data, never code.** Parameter values reach the script only as
   environment variables `CNAPP_PARAM_*`; nothing from the server is put on a
   command line or spliced into script text. Fixed interpreter paths and
   arguments, timeout with process-tree kill, capped output.
5. **Human control proportional to risk.** The signed manifest's `risk` is
   authoritative: `low` (read-only) runs with one admin; `medium` / `high`
   need a second admin (two-person approval, shared with remote wipe). Every
   run is audited with script, bundle version, parameters, requester, approver,
   exit code.

## Why the agent remains bounded

The set of code the agent can be made to run is exactly: *(agent binaries
signed with the release key)* ∪ *(scripts in bundles signed with the
script-signing key, invoked with parameters inside their signed schema)*. Both
sets are fixed by reviewed commits and an approval-gated signing step in
GitHub; neither can be extended from the CNAPP server, its database, or an
admin session. A compromised server can choose **which** signed script runs
**where** and with which **schema-valid** parameters, can withhold scripts,
and can try to replay old ones (blocked by expiry and anti-rollback). It
cannot write new code. That is a strictly smaller power than an RMM "run
script" feature and comparable to the existing allow-listed actions, with the
list now maintained through code review instead of agent releases.

## Consequences

- The README / DEVICE_MANAGEMENT.md statement changes from "never runs
  scripts" to "never runs scripts that were not reviewed and signed".
- Script authors must think in schemas: no "run arbitrary path" parameters;
  `string` parameters require an anchored pattern.
- A new secret and environment must be set up once (`scripts/device-scripts-keygen`),
  and agents must be updated once to trust the new key.
- Whoever holds both the signing-environment approval and an admin account
  can run signed scripts on any device: risk levels must be honest, reviewers
  must check them, and high-impact scripts should be `high` (second admin).
- Rejected alternatives: server-side signing (the server would hold the key,
  defeating the purpose); free-form scripts with approval only (two admins
  could still run anything; no review trail); storing scripts only in the
  database (no code review).
