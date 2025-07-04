#!/usr/bin/env bash
# exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Run database migrations
flask db init

flask db migrate -m "Initial migration with username and profile picture."

flask db upgrade

# (Optional) Create admin user if it doesn't exist.
# This is a simple way to ensure the admin is always available.
# Note: In a real production app, you might handle this differently.
flask create-admin


