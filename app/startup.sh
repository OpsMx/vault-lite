#!/bin/sh
. /venv/bin/activate
gunicorn -b :8200 -w 4 --access-logfile - --error-logfile - vault-lite:APP
