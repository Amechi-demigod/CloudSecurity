"""gunicorn settings for the production container (all overridable via env).

    gunicorn -c gunicorn.conf.py app.main:app
"""
import os

from app.config import Settings
from app.logging_setup import dict_config

_settings = Settings()

bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"
worker_class = "uvicorn_worker.UvicornWorker"
workers = int(os.getenv("WEB_CONCURRENCY", "2"))
timeout = int(os.getenv("GUNICORN_TIMEOUT", "60"))
graceful_timeout = int(os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "30"))
# Longer than the load balancer's idle timeout so it, not us, closes idle connections.
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", "75"))
# Recycle workers now and then (bounded memory growth); jitter avoids restarting all at once.
max_requests = int(os.getenv("GUNICORN_MAX_REQUESTS", "2000"))
max_requests_jitter = 200
# Do not let uvicorn rewrite the client address from X-Forwarded-* headers;
# app.auth.client_ip() applies TRUST_PROXY_HEADERS / TRUSTED_PROXY_CIDRS itself.
forwarded_allow_ips = "127.0.0.1"
accesslog = "-"
errorlog = "-"
logconfig_dict = dict_config(_settings.effective_log_format, _settings.log_level)
# Worker heartbeat files in RAM (a container's /tmp may be a slow overlay filesystem).
_SHM = "/dev/shm"  # noqa: S108 - gunicorn's documented heartbeat location, not a temp file
worker_tmp_dir = _SHM if os.path.isdir(_SHM) else None
# gunicorn >= 26 opens a management socket under $HOME by default; not needed in a container.
control_socket_disable = True
