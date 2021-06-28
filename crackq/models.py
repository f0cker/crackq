"""SQL database models for user management"""

import json
import uuid

from sqlalchemy import Column
from sqlalchemy.types import (
    Boolean,
    DateTime,
    Integer,
    JSON,
    String,
    Unicode,
    )
from sqlalchemy_utils import UUIDType
from crackq.db import db


def gen_uuid():
    """Generate UUID"""
    return uuid.uuid4().hex


class User(db.Model):
    """Flask-login User model for session management"""
    __tablename__ = 'user'
    id = Column(UUIDType(binary=True), default=gen_uuid, primary_key=True,
                index=True)
    __table_args__ = {'extend_existing': True}
    active = Column(Boolean())
    username = Column(String(255), unique=True)
    email = Column(String(255))
    last_login_at = Column(DateTime())
    last_seen = Column(DateTime())
    current_login_at = Column(DateTime())
    last_login_ip = Column(String(100))
    current_login_ip = Column(String(100))
    login_count = Column(Integer)
    confirmed_at = Column(DateTime())
    job_ids = Column(JSON, unique=True)
    task_ids = Column(JSON, unique=True)
    is_admin = Column(Boolean())
    password = Column(Unicode(100))

    def is_active(self):
        """Required method for flask-login User class"""
        return self.active

    def get_id(self):
        """Required method for flask-login User class"""
        return self.id

    def is_anonymous(self):
        """Required method for flask-login User class"""
        return False

    def is_authenticated(self):
        """Required method for flask-login User class"""
        return True

    def __repr__(self):
        """Required method for flask-login User class"""
        ret = {
            'user': self.username,
            'job_ids': self.job_ids,
            'task_ids': self.job_ids,
            'email': self.email,
            'last_seen':  self.last_seen,
            'password': self.password
            }
        return json.dumps(ret)


class Templates(db.Model):
    """Template job array list"""
    __tablename__ = 'templates'
    id = Column(UUIDType(binary=True), default=gen_uuid, primary_key=True,
                index=True)
    __table_args__ = {'extend_existing': True}
    name = Column(String(255))


class Tasks(db.Model):
    """Tasks job array list"""
    __tablename__ = 'tasks'
    id = Column(UUIDType(binary=True), default=gen_uuid, primary_key=True,
                index=True)
    __table_args__ = {'extend_existing': True}
    name = Column(String(255))
    job_ids = Column(JSON, unique=True)
