"""Finding templates of the attack-surface scanner: one entry per check (VAPT layout: description, business impact,
steps to reproduce, how to fix per server type, references, compliance mapping).

CVSS 3.1 vectors are scored with app/vulnmatch/versions.cvss3_base_score. `auto_fail` marks the PCI-ASV automatic
failures (rules.py); `dos_only` marks denial-of-service-only issues, which never fail a pre-ASV scan; `special_note`
puts the item in Part 3b of the report."""
from __future__ import annotations

from typing import Any

from ..vulnmatch.versions import cvss3_base_score

PCI = "PCI DSS v4.0"
ISO = "ISO/IEC 27001:2022"

REMOTE_ADMIN = {
    "title_prefix": "Remote access service exposed",
}

AV_N = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"


def severity_for(score: float) -> str:
    return "critical" if score >= 9.0 else "high" if score >= 7.0 else "medium" if score >= 4.0 \
        else "low" if score > 0 else "info"


def _t(title: str, vector: str | None, cwe: str | None, description: str, impact: str, steps: list[str],
       fix: dict[str, str], references: list[str], compliance: dict[str, list[str]], *, auto_fail: bool = False,
       dos_only: bool = False, special_note: str | None = None, severity: str | None = None) -> dict[str, Any]:
    score = cvss3_base_score(vector) if vector else 0.0
    return {"title": title, "vector": vector, "cvss": score or 0.0, "cwe": cwe, "description": description,
            "impact": impact, "steps": steps, "fix": fix, "references": references, "compliance": compliance,
            "auto_fail": auto_fail, "dos_only": dos_only, "special_note": special_note,
            "severity": severity or severity_for(score or 0.0)}


_TLS_FIX = {
    "General": "Disable the protocol so that only TLS 1.2 and TLS 1.3 are offered, then re-scan.",
    "nginx": "ssl_protocols TLSv1.2 TLSv1.3;   # in the server / http block, then: nginx -t && nginx -s reload",
    "Apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3   # then: apachectl configtest && apachectl graceful",
    "IIS": ("Disable the protocol in the registry (HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\"
            "SCHANNEL\\Protocols\\<TLS 1.0|TLS 1.1|SSL 3.0>\\Server: Enabled=0, DisabledByDefault=1) or use IIS Crypto, "
            "then restart the server."),
}
_TLS_REFS = ["https://datatracker.ietf.org/doc/html/rfc8996", "https://www.pcisecuritystandards.org/"]
_TLS_COMP = {PCI: ["4.2.1", "2.2.7", "11.3.2"], ISO: ["A.8.24"]}


def _tls_proto(name: str, cwe: str = "CWE-326") -> dict[str, Any]:
    return _t(f"{name} is enabled", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", cwe,
              f"The service accepts {name} connections. {name} is deprecated and has known cryptographic weaknesses.",
              "Traffic protected only by this protocol can be decrypted or tampered with by an attacker able to "
              "intercept it. PCI ASV rules fail a scan for SSL and early TLS regardless of the score.",
              [f"Offer a {name} ClientHello to {{host}}:{{port}} (for example `openssl s_client -connect "
               f"{{host}}:{{port}} -{'ssl3' if name == 'SSLv3' else 'tls1' if name == 'TLS 1.0' else 'tls1_1'}`).",
               "The server answers with a ServerHello at that version instead of refusing the handshake."],
              _TLS_FIX, _TLS_REFS, _TLS_COMP, auto_fail=True)


def _weak_cipher(cls: str) -> dict[str, Any]:
    return _t(f"Weak cipher suites accepted ({cls})", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-326",
              f"The service negotiates {cls} cipher suites, which provide little or no protection.",
              "Encrypted traffic can be recovered or modified by an attacker on the network path.",
              ["Send a ClientHello offering only the weak suites to {host}:{port}.",
               "The server selects one of them in its ServerHello."],
              {"General": f"Remove {cls} suites from the cipher list; prefer AEAD suites (AES-GCM, ChaCha20-Poly1305).",
               "nginx": "ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!RC4:!3DES:!EXPORT;",
               "Apache": "SSLCipherSuite ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!RC4:!3DES:!EXPORT",
               "IIS": "Disable the cipher in SCHANNEL\\Ciphers (or use IIS Crypto's Best Practices template) and restart."},
              ["https://ciphersuite.info/"], _TLS_COMP)


def _hdr(name: str, header: str, desc: str, impact: str, fix_value: str, cwe: str = "CWE-693",
         vector: str | None = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N") -> dict[str, Any]:
    return _t(f"{name} header missing", vector, cwe, desc, impact,
              ["Request {url} and inspect the response headers.", f"No `{header}` header is returned."],
              {"General": f"Send `{header}: {fix_value}` on every response.",
               "nginx": f"add_header {header} \"{fix_value}\" always;",
               "Apache": f"Header always set {header} \"{fix_value}\"",
               "IIS": f"<system.webServer><httpProtocol><customHeaders><add name=\"{header}\" value=\"{fix_value}\" />"
                      "</customHeaders></httpProtocol></system.webServer>   (web.config)"},
              ["https://owasp.org/www-project-secure-headers/"], {PCI: ["6.2.4"], ISO: ["A.8.26", "A.8.9"]})


_FILE_FIX = {"General": "Remove the file from the web root (store backups and configuration outside it), and deny access "
                        "to dot-files and archives. Rotate any credential that may have been exposed.",
             "nginx": "location ~ /\\.(?!well-known) { deny all; }\nlocation ~* \\.(bak|old|sql|zip|tar|gz|env)$ { deny all; }",
             "Apache": "<FilesMatch \"(^\\.|\\.(bak|old|sql|zip|tar|gz|env)$)\">\n  Require all denied\n</FilesMatch>",
             "IIS": "Add a request-filtering rule denying these extensions / hidden segments (web.config "
                    "<requestFiltering><fileExtensions>, <hiddenSegments>) and delete the file."}

TEMPLATES: dict[str, dict[str, Any]] = {
    "tls-sslv3": _tls_proto("SSLv3"),
    "tls-tls10": _tls_proto("TLS 1.0"),
    "tls-tls11": _tls_proto("TLS 1.1"),
    "tls-weak-rc4": _weak_cipher("RC4"), "tls-weak-3des": _weak_cipher("3DES"),
    "tls-weak-export": _weak_cipher("EXPORT"), "tls-weak-null": _weak_cipher("NULL"),
    "tls-weak-anonymous-dh": _weak_cipher("anonymous DH"),
    "tls-cert-expired": _t("TLS certificate has expired", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", "CWE-298",
                           "The certificate presented by the service is past its expiry date.",
                           "Browsers warn users or refuse the connection; users get used to clicking through warnings, "
                           "which makes interception easier. Under PCI ASV rules an invalid certificate fails the scan.",
                           ["Connect to {host}:{port} with TLS and read the certificate's notAfter date."],
                           {"General": "Issue and install a renewed certificate; automate renewal (ACME)."},
                           ["https://letsencrypt.org/docs/"], {PCI: ["4.2.1", "11.3.2"], ISO: ["A.8.24"]}),
    "tls-cert-expiring": _t("TLS certificate expires soon", None, "CWE-298",
                            "The certificate expires within 30 days.", "An expired certificate interrupts the service "
                            "and fails an ASV scan.", ["Read the certificate's notAfter date on {host}:{port}."],
                            {"General": "Renew the certificate now and automate renewal."}, [],
                            {PCI: ["4.2.1"], ISO: ["A.8.24"]}, severity="info"),
    "tls-cert-self-signed": _t("TLS certificate is self-signed", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                               "CWE-295", "The certificate is signed by itself, not by a trusted certificate authority.",
                               "Clients cannot verify the server's identity, so a man-in-the-middle cannot be told apart "
                               "from the real server.", ["Connect to {host}:{port} and compare certificate issuer and subject."],
                               {"General": "Install a certificate from a public certificate authority."},
                               ["https://letsencrypt.org/"], {PCI: ["4.2.1", "11.3.2"], ISO: ["A.8.24"]}),
    "tls-cert-untrusted": _t("TLS certificate chain is not trusted", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                             "CWE-295", "The certificate chain does not validate against the public trust stores "
                             "(missing intermediate certificate or unknown issuer).",
                             "Clients show warnings or fail; the server identity cannot be verified.",
                             ["Connect to {host}:{port} with certificate verification enabled."],
                             {"General": "Serve the full chain (leaf plus intermediates) from a public CA."}, [],
                             {PCI: ["4.2.1", "11.3.2"], ISO: ["A.8.24"]}),
    "tls-cert-mismatch": _t("TLS certificate does not match the host name", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            "CWE-297", "The certificate's names do not include the host name used to reach the service.",
                            "Clients warn or fail, and cannot confirm they reached the intended server.",
                            ["Connect to {host}:{port} with SNI {host} and compare the certificate names."],
                            {"General": "Issue a certificate that lists this host name (SAN), or serve the correct "
                                        "certificate for this name."}, [], {PCI: ["4.2.1", "11.3.2"], ISO: ["A.8.24"]}),
    "tls-cert-weak-key": _t("TLS certificate uses a weak key or signature", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "CWE-326", "The certificate uses an RSA key shorter than 2048 bits or a SHA-1 / MD5 signature.",
                            "Weak keys and signatures can be forged or broken with moderate resources.",
                            ["Read the certificate on {host}:{port} and inspect its key size and signature algorithm."],
                            {"General": "Re-issue the certificate with an RSA 2048+ (or ECDSA P-256) key and SHA-256 signature."},
                            [], _TLS_COMP),
    "hdr-hsts": _hdr("Strict-Transport-Security (HSTS)", "Strict-Transport-Security",
                     "The HTTPS site does not tell browsers to always use HTTPS.",
                     "Users can be downgraded to HTTP by a network attacker (SSL stripping).",
                     "max-age=31536000; includeSubDomains", "CWE-319"),
    "hdr-csp": _hdr("Content-Security-Policy", "Content-Security-Policy",
                    "No Content-Security-Policy is sent, so the browser applies no restrictions on script sources.",
                    "Cross-site scripting has a larger impact: injected scripts can load from anywhere.",
                    "default-src 'self'", "CWE-1021", None),
    "hdr-xfo": _hdr("X-Frame-Options", "X-Frame-Options", "The page can be embedded in a frame on another site.",
                    "Clickjacking: users can be tricked into clicking hidden controls.", "DENY", "CWE-1021"),
    "hdr-xcto": _hdr("X-Content-Type-Options", "X-Content-Type-Options",
                     "Browsers may guess content types (MIME sniffing).",
                     "Uploaded or reflected content may be interpreted as script.", "nosniff", "CWE-693", None),
    "cookie-flags": _t("Cookie without Secure / HttpOnly / SameSite flags", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                       "CWE-614", "A cookie is set without one or more of the Secure, HttpOnly and SameSite attributes.",
                       "Session cookies can be sent over HTTP, read by scripts or sent in cross-site requests.",
                       ["Request {url} and read the Set-Cookie response headers (values are not stored)."],
                       {"General": "Set `Secure; HttpOnly; SameSite=Lax` (or Strict) on session cookies.",
                        "nginx": "proxy_cookie_flags ~ secure httponly samesite=lax;",
                        "Apache": "Header edit Set-Cookie ^(.*)$ \"$1; Secure; HttpOnly; SameSite=Lax\"",
                        "IIS": "<httpCookies httpOnlyCookies=\"true\" requireSSL=\"true\" /> in web.config (system.web)."},
                       ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                       {PCI: ["6.2.4", "6.5.x"], ISO: ["A.8.26"]}),
    "http-server-banner": _t("Web server discloses its version", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                             "CWE-200", "The Server (or X-Powered-By) header reveals the product and version.",
                             "Attackers can pick exploits for the exact version without probing.",
                             ["Request {url} and read the Server / X-Powered-By headers."],
                             {"General": "Hide version information.", "nginx": "server_tokens off;",
                              "Apache": "ServerTokens Prod\nServerSignature Off",
                              "IIS": "Remove X-Powered-By (customHeaders); set removeServerHeader=\"true\" in requestFiltering."},
                             [], {PCI: ["2.2.x"], ISO: ["A.8.9"]}),
    "file-exposed": _t("Sensitive file or archive is downloadable", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                       "CWE-538", "A backup, archive, version-control or configuration file is served by the web server. "
                       "The scanner only requests the first bytes and stores status, size and type, never the content.",
                       "Source code, credentials and customer data can be downloaded by anyone.",
                       ["Send `GET {path}` with `Range: bytes=0-255` to {host}:{port}.",
                        "The server answers 200/206 with a matching file signature."],
                       _FILE_FIX, ["https://cwe.mitre.org/data/definitions/538.html"],
                       {PCI: ["6.2.4", "2.2.x"], ISO: ["A.8.9", "A.8.12"]}),
    "admin-panel": _t("Administration interface exposed to the internet", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                      "CWE-284", "An administration or management interface is reachable from the internet.",
                      "It becomes a target for password guessing and for exploits of the management software.",
                      ["Request {url} and observe a login or management page."],
                      {"General": "Restrict the interface to a VPN or an allow-list of source addresses and require MFA.",
                       "nginx": "location /admin { allow 203.0.113.0/24; deny all; }",
                       "Apache": "<Location /admin>\n  Require ip 203.0.113.0/24\n</Location>",
                       "IIS": "Add an IP Address and Domain Restrictions rule for the path (allow only your ranges)."},
                      [], {PCI: ["1.4.x", "2.2.7", "8.4.x"], ISO: ["A.8.20", "A.8.5"]}),
    "api-docs": _t("API documentation or GraphQL playground exposed", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                   "CWE-200", "Interactive API documentation (Swagger/OpenAPI) or a GraphQL playground is public.",
                   "It lists every endpoint and parameter, helping attackers find unauthenticated or weak functions.",
                   ["Request {url} and observe the documentation page."],
                   {"General": "Disable the documentation endpoints in production or require authentication."},
                   [], {PCI: ["6.2.4"], ISO: ["A.8.26"]}),
    "dir-listing": _t("Directory listing is enabled", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-548",
                      "The web server shows the contents of a directory when no index page exists.",
                      "Files not meant to be public (backups, uploads, logs) can be found and downloaded.",
                      ["Request {url}; the response is an automatic index page."],
                      {"General": "Disable automatic directory indexes.", "nginx": "autoindex off;",
                       "Apache": "Options -Indexes",
                       "IIS": "IIS Manager > Directory Browsing > Disable (or <directoryBrowse enabled=\"false\" />)."},
                      [], {PCI: ["2.2.x", "6.2.4"], ISO: ["A.8.9"]}, special_note="browsable_directory"),
    "iis-shortname": _t("IIS short file name (tilde) disclosure", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "CWE-200", "IIS answers differently for requests that match 8.3 short names, revealing that "
                        "short names exist. The scanner uses the standard two-request probe and does not enumerate names.",
                        "Attackers can discover file and folder names (including unlinked ones).",
                        ["Request `GET /*~1*/.aspx` and `GET /zzqx9*~1*/.aspx` on {host}:{port}.",
                         "The first returns 404 and the second 400."],
                        {"General": "Disable 8.3 name creation: `fsutil 8dot3name set 1`, remove existing short names, "
                                    "and add a request-filtering rule denying `~` in URLs.",
                         "IIS": "<requestFiltering allowDoubleEscaping=\"false\"><denyUrlSequences><add sequence=\"~\" />"
                                "</denyUrlSequences></requestFiltering>"},
                        ["https://soroush.me/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf"],
                        {PCI: ["6.2.4"], ISO: ["A.8.9"]}),
    "verbose-error": _t("Verbose server error pages", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-209",
                        "Error pages show stack traces, file paths or framework details.",
                        "Internal details help an attacker plan further attacks.",
                        ["Request {url}; the response body contains a stack trace or framework error."],
                        {"General": "Turn on generic error pages and log details server-side only.",
                         "IIS": "<customErrors mode=\"RemoteOnly\" /> and <httpErrors errorMode=\"DetailedLocalOnly\" />.",
                         "nginx": "Disable debug modes of the application; proxy_intercept_errors on;",
                         "Apache": "ServerSignature Off; set the application to production mode."},
                        [], {PCI: ["6.2.4", "6.5.5"], ISO: ["A.8.26"]}),
    "external-scripts": _t("Scripts loaded from other domains", None, "CWE-829",
                           "The page loads scripts or frames from domains other than its own.",
                           "A compromise of those domains runs code in your visitors' browsers.",
                           ["Request {url} and list <script src> and <iframe src> attributes."],
                           {"General": "Self-host scripts or use Subresource Integrity (integrity=\"sha384-...\")."},
                           [], {PCI: ["6.4.3", "11.6.1"], ISO: ["A.8.26"]}, severity="info",
                           special_note="embedded_links"),
    "default-credentials": _t("Vendor default credentials accepted", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                              "CWE-1392", "A service accepted a vendor-default username and password. (Opt-in check; "
                              "the credentials tried are neither stored nor shown.)",
                              "Anyone can sign in and take over the service.",
                              ["Re-run the check (Re-test) and review the audit log entry for who enabled it."],
                              {"General": "Change the default credentials immediately and review the system for misuse."},
                              ["https://cwe.mitre.org/data/definitions/1392.html"],
                              {PCI: ["2.2.2", "8.3.x"], ISO: ["A.8.5"]}, auto_fail=True, special_note="default_credentials"),
    "eol-software": _t("End-of-life software detected", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-1104",
                       "The detected software version is no longer supported by its vendor and receives no security fixes.",
                       "Newly found vulnerabilities will never be fixed. PCI ASV rules fail unsupported software.",
                       ["Read the service banner of {host}:{port}: {product} {version}."],
                       {"General": "Upgrade to a supported release."},
                       [], {PCI: ["6.3.3", "12.3.4", "11.3.2"], ISO: ["A.8.8"]}, auto_fail=True),
    "cve": _t("Known vulnerability in detected software", None, None, "", "", [], {}, [],
              {PCI: ["6.3.3", "11.3.2"], ISO: ["A.8.8"]}),
}

# Risky services: port -> (id, name, vector, note, special_note)
RISKY: dict[int, tuple[str, str, str, str | None]] = {
    23: ("telnet", "Telnet (cleartext remote login)", f"{AV_N}/S:U/C:H/I:H/A:H", "remote_access"),
    21: ("ftp", "FTP (cleartext file transfer)", f"{AV_N}/S:U/C:L/I:L/A:N", None),
    3389: ("rdp", "Remote Desktop Protocol (RDP)", f"{AV_N}/S:U/C:H/I:H/A:N", "remote_access"),
    5900: ("vnc", "VNC remote desktop", f"{AV_N}/S:U/C:H/I:H/A:N", "remote_access"),
    445: ("smb", "SMB file sharing", f"{AV_N}/S:U/C:H/I:H/A:N", None),
    139: ("netbios", "NetBIOS session service", f"{AV_N}/S:U/C:H/I:N/A:N", None),
    135: ("msrpc", "Microsoft RPC endpoint mapper", f"{AV_N}/S:U/C:L/I:N/A:N", None),
    3306: ("mysql", "MySQL database", f"{AV_N}/S:U/C:H/I:H/A:N", None),
    5432: ("postgres", "PostgreSQL database", f"{AV_N}/S:U/C:H/I:H/A:N", None),
    1433: ("mssql", "Microsoft SQL Server", f"{AV_N}/S:U/C:H/I:H/A:N", None),
    1521: ("oracle", "Oracle database listener", f"{AV_N}/S:U/C:H/I:H/A:N", None),
    27017: ("mongodb", "MongoDB database", f"{AV_N}/S:U/C:H/I:H/A:N", None),
    6379: ("redis", "Redis", f"{AV_N}/S:U/C:H/I:H/A:N", None),
    9200: ("elasticsearch", "Elasticsearch", f"{AV_N}/S:U/C:H/I:H/A:N", None),
    11211: ("memcached", "Memcached", f"{AV_N}/S:U/C:H/I:N/A:N", None),
    5984: ("couchdb", "CouchDB", f"{AV_N}/S:U/C:H/I:H/A:N", None),
    2375: ("docker", "Docker API (unencrypted)", f"{AV_N}/S:C/C:H/I:H/A:H", None),
    873: ("rsync", "rsync daemon", f"{AV_N}/S:U/C:L/I:L/A:N", None),
    5985: ("winrm", "Windows Remote Management", f"{AV_N}/S:U/C:H/I:H/A:N", "remote_access"),
    2049: ("nfs", "NFS", f"{AV_N}/S:U/C:H/I:N/A:N", None),
    161: ("snmp", "SNMP", f"{AV_N}/S:U/C:L/I:N/A:N", None),
}


def risky_template(port: int) -> dict[str, Any] | None:
    r = RISKY.get(port)
    if not r:
        return None
    cid, name, vector, note = r
    return _t(f"{name} exposed to the internet", vector, "CWE-284",
              f"{name} accepts connections from the internet on port {port}.",
              "Services that are not meant to be public enlarge the attack surface: attackers can guess credentials, "
              "intercept cleartext traffic or exploit unpatched flaws." + (" Remote access software is listed in "
              "Part 3b of the report." if note else ""),
              ["Open a TCP connection to {host}:{port}; it is accepted.",
               "Review the banner shown in the evidence."],
              {"General": "Close the port at the firewall / security group, or restrict it to a VPN or fixed source "
                          "addresses. Use encrypted alternatives (SSH, SFTP, TLS) where the service is needed.",
               "IIS": "Windows Firewall: block the port from the internet (New-NetFirewallRule -Direction Inbound "
                      f"-LocalPort {port} -Protocol TCP -Action Block) and use RD Gateway / VPN for remote access.",
               "nginx": "Bind the service to 127.0.0.1 or a private interface; front it with a VPN.",
               "Apache": "Bind the service to 127.0.0.1 or a private interface; front it with a VPN."},
              ["https://www.cisa.gov/news-events/news/securing-network-infrastructure-devices"],
              {PCI: ["1.4.x", "2.2.x", "11.3.2"], ISO: ["A.8.20", "A.8.21"]}, special_note=note), f"risky-{cid}"


def template(check_id: str) -> dict[str, Any]:
    if check_id.startswith("risky-"):
        for port in RISKY:
            if RISKY[port][0] == check_id[6:]:
                return risky_template(port)[0]  # type: ignore[index]
    return TEMPLATES[check_id]
