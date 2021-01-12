#!/usr/bin/env python
"""Util to add initial admin user"""

from crackq.models import User
from crackq.cq_api import bcrypt
from crackq import app, db
from getpass import getpass

print('Creating initial admin account')
user = input('Enter Username:')
email = input('Enter Email:')
password = getpass('Enter Password:')
pass_hash = bcrypt.generate_password_hash(password).decode('utf-8')
with app.app_context():
    user = User(username=user, email=email,
                password=pass_hash, is_admin=True)
    db.session.add(user)
    db.session.commit()
    print('New user added')
