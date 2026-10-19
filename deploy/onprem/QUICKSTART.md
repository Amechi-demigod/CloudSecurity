# On-prem quick start (one page)

Single Ubuntu Server 24.04 box, internal network / VPN only. Full guide: [docs/DEPLOY_ONPREM.md](../../docs/DEPLOY_ONPREM.md).

## Prepare (before you start)

| What | Example | Notes |
|---|---|---|
| Server | Ubuntu Server 24.04 LTS, 2 vCPU, 4 GB RAM, 50 GB disk, x86_64 | fresh install, OpenSSH enabled, your SSH key added |
| Static IP | `10.0.0.20` | reserve it in DHCP or configure netplan |
| Internal DNS name | `cnapp.corp.local` -> `10.0.0.20` | A record on your internal DNS (AD DNS etc.) |
| Admin email | `you@corp.com` | becomes the first (break-glass) admin |
| GHCR read token | GitHub PAT with **read:packages** | GitHub > Settings > Developer settings > Personal access tokens. Classic PAT: tick only `read:packages`. Save it in a file on the server, e.g. `~/ghcr.token` |
| Client ranges | `10.0.0.0/8,192.168.0.0/16` | LAN + VPN ranges allowed to reach 80/443 |
| Outbound HTTPS | ghcr.io, pkg-containers.githubusercontent.com, Docker Hub, download.docker.com, Ubuntu mirrors | plus login.microsoftonline.com / management.azure.com / Teams / Slack / SMTP if you use them |
| (optional) internal CA | AD CS certificate + key for `cnapp.corp.local` | otherwise the built-in CA is used |

## Install (about 10 minutes)

```bash
ssh you@10.0.0.20
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/Amechi-demigod/CloudSecurity.git     # private repo: use your GitHub login/PAT
cd CloudSecurity/deploy/onprem
sudo ./cnapp-ctl install \
  --hostname cnapp.corp.local --ip 10.0.0.20 \
  --admin-email you@corp.com \
  --allowed-cidrs 10.0.0.0/8,192.168.0.0/16 \
  --ghcr-user <github-user> --ghcr-token-file ~/ghcr.token \
  --image-tag latest
rm ~/ghcr.token          # stored root-only under /opt/cnapp/secrets now
```

(No git on the server? Copy the `deploy/onprem` folder with `scp -r`.) The installer checks the box, installs Docker from Docker's
apt repo (GPG key fingerprint verified), creates `/opt/cnapp`, generates every secret, creates an internal CA + server
certificate, logs in to GHCR, configures UFW (SSH from your current address first), enables security auto-updates,
the nightly backup timer and the `cnapp` systemd service, starts the stack and prints the **admin password once**.

Using your own certificate instead: before `install`, put `server.crt` (full chain) and `server.key` in
`/opt/cnapp/tls/`, or afterwards run `sudo cnapp-ctl tls import --cert server.crt --key server.key --chain chain.pem --ca root.pem`.

## Trust the CA on clients (built-in CA only)

```bash
scp you@10.0.0.20:/opt/cnapp/tls/cnapp-root-ca.crt .      # public certificate
```

* **Windows** (admin PowerShell): `certutil -addstore -f Root cnapp-root-ca.crt` - or GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Trusted Root Certification Authorities > Import.
* **macOS**: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cnapp-root-ca.crt` - or an MDM "Certificate" payload.
* **Firefox**: Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import (or `security.enterprise_roots.enabled=true`).

Compare the SHA-256 fingerprint with `sudo cnapp-ctl tls show`.

## First login and day one

1. Open `https://cnapp.corp.local`, sign in with the printed password, set up MFA (authenticator app), save the recovery codes.
2. **Users**: add colleagues (or configure Entra SSO, guide section 8).
3. **Devices > Enroll devices**: roll out the agent (next section).
4. **Settings > Notifications**: add a Teams/Slack/email channel and send a test.
5. Azure scanner (optional): Reader-role service principal -> `AZURE_*` in `/opt/cnapp/cnapp.env` -> `sudo cnapp-ctl restart`.

## Roll out to all devices

1. **Devices > Enroll devices > Download installer**: pick *Windows (MSI)* or *macOS (pkg)*, expiry (30 days), maximum
   devices (500), optional device group. Leave *Include the server's CA* ticked while you use the built-in CA. You get
   one file with the server URL, a dedicated enrollment token and the CA inside; no per-device token.
2. Deploy it:
   * **GPO**: copy `cnapp-agent-setup.msi` to a share readable by *Domain Computers*; GPO on the computers' OU:
     Computer Configuration > Policies > Software Settings > Software Installation > New > Package (UNC path) > Assigned.
     Or a startup script: `msiexec /i \\server\share\cnapp-agent-setup.msi /qn`.
   * **Intune**: Apps > Windows > Add > Line-of-business app (the MSI), assign to a device group. macOS: Apps > macOS > macOS app (PKG).
   * **SCCM**: Application from the MSI, install `msiexec /i "cnapp-agent-setup.msi" /qn`.
   * **Jamf / Kandji**: upload the pkg, policy / Blueprint scoped to your Macs.
   * **By hand**: double-click, or `msiexec /i cnapp-agent-setup.msi /qn` / `sudo installer -pkg cnapp-agent-setup.pkg -target /`.
3. Devices appear under **Devices** within a couple of minutes. Revoke the installer's token under *Enrollment tokens*
   when you are done (enrolled devices keep working).
4. Troubleshooting on a device: `cnapp-agent status` (Windows: `"%ProgramFiles%\CNAPP Agent\cnapp-agent.exe" status`,
   macOS: `sudo /usr/local/cnapp-agent/bin/cnapp-agent status`); logs in `%ProgramData%\CNAPP Agent\logs\agent.log` /
   `/Library/Logs/CNAPP Agent/agent.log`. Uninstall: `msiexec /x cnapp-agent-setup.msi /qn` /
   `sudo /usr/local/cnapp-agent/bin/cnapp-uninstall.sh`.

Signing: the downloaded installers are unsigned (they are modified per download). For SmartScreen-free rollouts sign the
generic MSI yourself and pass `CNAPP_SERVER` / `CNAPP_TOKEN` as properties. Details:
[DEVICE_MANAGEMENT.md](../../docs/DEVICE_MANAGEMENT.md#roll-out-to-all-devices).

## Move from the IP address to a DNS name with your PFX

```bash
# internal DNS first: cnapp.wakanow.com -> 10.10.11.57 (split-horizon / internal zone)
scp wakanow.pfx you@10.10.11.57:
sudo cnapp-ctl tls import-pfx --pfx ~/wakanow.pfx --hostname cnapp.wakanow.com   # prompts for the PFX password
shred -u ~/wakanow.pfx
```

Production today: `https://cnapp.wakanow.com` with a publicly trusted DigiCert wildcard certificate, so installers carry
no CA and devices need no certificate deployment. Old (RC2-40) PFX exports are handled automatically. Agents enrolled with `https://10.10.11.57` keep working (the
built-in certificate is still served for the IP address); download new installers so new devices use the DNS name.
Change only the URL (certificate already covers it): `sudo cnapp-ctl set-hostname cnapp.wakanow.com`.
Full guide: [DEPLOY_ONPREM.md, section 4](../../docs/DEPLOY_ONPREM.md#switch-to-a-dns-name-and-your-own-certificate-pfx).

## Everyday commands

```bash
sudo cnapp-ctl status                 # health, version, certificate, backups
sudo cnapp-ctl logs backend -f
sudo cnapp-ctl update --check         # is a newer image available?
sudo cnapp-ctl update --tag <sha>     # backup, pull, recreate, health check, automatic rollback
sudo cnapp-ctl backup                 # also runs nightly at 02:30 (14 days kept)
sudo cnapp-ctl restore /opt/cnapp/backups/cnapp-db-<ts>.dump.gz
sudo cnapp-ctl tls renew              # built-in certificate (397 days; auto-renewed 30 days before expiry)
sudo cnapp-ctl tls import-pfx --pfx f.pfx [--hostname NAME]   # your certificate (password prompted)
sudo cnapp-ctl set-hostname NAME      # change the URL agents/installers/users use
sudo cnapp-ctl reset-password --email you@corp.com
```

Keep a copy of `/opt/cnapp/backups/*.config.tar.gz` (settings, encryption keys, CA) somewhere safe off the server:
without it a database backup cannot be fully restored on a new machine.
