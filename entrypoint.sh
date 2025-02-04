#!/bin/bash

python manage.py migrate --noinput
python manage.py collectstatic --noinput
gunicorn blog_backend.wsgi:application --bind 0.0.0.0:8000 --workers 2