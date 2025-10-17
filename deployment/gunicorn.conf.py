# Gunicorn configuration for production deployment
import os
from multiprocessing import cpu_count

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = cpu_count() * 2 + 1
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50

# Timeout settings
timeout = 30
keepalive = 2
graceful_timeout = 30

# Process naming
proc_name = "cloudshield"

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Server mechanics
preload_app = True
daemon = False
pidfile = "/tmp/gunicorn.pid"
user = None
group = None
tmp_upload_dir = None

# SSL (for production with SSL certificates)
# keyfile = "/path/to/keyfile"
# certfile = "/path/to/certfile"

def when_ready(server):
    """Called just after the server is started."""
    server.log.info("CloudShield server is ready. Listening on: %s", server.address)

def worker_int(worker):
    """Called just after a worker exited on SIGINT or SIGQUIT."""
    worker.log.info("worker received INT or QUIT signal")

def on_exit(server):
    """Called just before exiting."""
    server.log.info("CloudShield server is shutting down")

def on_reload(server):
    """Called to recycle workers during a reload via SIGHUP."""
    server.log.info("CloudShield server is reloading")
