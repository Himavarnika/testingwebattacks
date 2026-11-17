import os

bind = f"{os.environ.get('LAB_HOST', '0.0.0.0')}:{os.environ.get('LAB_PORT', '8080')}"
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
worker_class = "gthread"
threads = int(os.environ.get("GUNICORN_THREADS", "4"))
timeout = 120
graceful_timeout = 30
accesslog = "-"
errorlog = "-"
capture_output = True
preload_app = True
