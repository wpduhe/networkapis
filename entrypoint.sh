#!/bin/bash
exec python -m uvicorn src.main:app --host 0.0.0.0 --port ${PORT} --log-config loggingconfig.json
wait -n
exit $?