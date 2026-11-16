"""The fixed TCP port list of the scanner (a TCP connect scan, no raw packets) and service names."""
from __future__ import annotations

TOP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 119, 123, 135, 137, 139, 143, 161, 179, 389, 443, 445, 465, 500, 514,
    515, 548, 554, 587, 631, 636, 873, 990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1701, 1723, 1883, 2049, 2082,
    2083, 2086, 2087, 2181, 2222, 2375, 2376, 3000, 3128, 3306, 3389, 3478, 4000, 4443, 4567, 5000, 5001, 5060, 5222,
    5432, 5601, 5672, 5900, 5901, 5984, 5985, 5986, 6000, 6379, 6443, 7001, 7070, 7443, 7547, 8000, 8008, 8080, 8081,
    8082, 8083, 8086, 8088, 8090, 8123, 8181, 8243, 8280, 8443, 8444, 8500, 8800, 8834, 8880, 8888, 9000, 9042, 9090,
    9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 10250, 11211, 15672, 27017, 32400, 50000)

HTTP_PORTS = frozenset({80, 81, 2082, 2086, 3000, 4000, 5000, 5001, 5601, 7001, 7070, 8000, 8008, 8080, 8081, 8082,
                        8083, 8086, 8088, 8090, 8123, 8181, 8280, 8500, 8800, 8880, 8888, 9000, 9090, 9999, 10000,
                        15672, 32400})
HTTPS_PORTS = frozenset({443, 2083, 2087, 2376, 4443, 5986, 6443, 7443, 8243, 8443, 8444, 9443, 10250})
TLS_ONLY_PORTS = frozenset({465, 636, 990, 993, 995})  # implicit TLS, not HTTP: certificate / protocol checks only
# Ports where the server speaks first: the banner is read.
BANNER_PORTS = frozenset({21, 22, 23, 25, 110, 143, 587, 3306, 5900, 5901, 119})

SERVICE_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
                 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
                 465: "smtps", 587: "submission", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
                 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "rdp",
                 5432: "postgresql", 5900: "vnc", 5984: "couchdb", 5985: "winrm", 6379: "redis", 8080: "http-alt",
                 8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"}
