import os
workers = 1
timeout = 600
worker_class = 'uvicorn.workers.UvicornWorker'
accesslog = '-'
errorlog = '-'
loglevel = 'debug'

bind = ['0.0.0.0:8080']
