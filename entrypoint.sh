#!/bin/bash
exec python -m uvicorn main:app --host 0.0.0.0 --port ${PORT} --log-config /opt/app/loggingconfig.json
wait -n
exit $?