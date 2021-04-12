#!/usr/bin/env python
"""Util to add initial admin user"""

from crackq.models import User
from crackq.cq_api import bcrypt, parse_json_schema
from crackq import app, db
from getpass import getpass
from marshmallow import ValidationError
import json

print('Creating initial admin account')
user = input('Enter Username:')
email = input('Enter Email:')
password = getpass('Enter Password:')
creds_json = json.dumps(
    {
        "user": user,
        "password": password,
        "email": email,
    })
try:
    parse_json_schema().loads(creds_json)
except ValidationError as errors:
    print('Validation error: {}'.format(errors))
    exit(1)
pass_hash = bcrypt.generate_password_hash(password).decode('utf-8')
with app.app_context():
    user = User(username=user, email=email,
                password=pass_hash, is_admin=True)
    db.session.add(user)
    db.session.commit()
    print('New user added')
