import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from logging.config import fileConfig
from sqlalchemy import create_engine, Column, ForeignKey
from sqlalchemy.types import (
    Boolean,
    DateTime,
    #Column,
    Integer,
    String,
    #ForeignKey,
    TypeDecorator,
    JSON,
    )
from crackq.db import db

class User(db.Model):
    """Flask-login User model for session management"""
    __tablename__ = 'user'
    #__abstract__ = True
    #__table_args__ = {'extend_existing': True}
    active = Column(Boolean())
    username = Column(String(255), unique=True, index=True,
                      primary_key=True)
    email = Column(String(255), unique=True)
    last_login_at = Column(DateTime())
    last_seen = Column(DateTime())
    current_login_at = Column(DateTime())
    last_login_ip = Column(String(100))
    current_login_ip = Column(String(100))
    login_count = Column(Integer)
    confirmed_at = Column(DateTime())
    job_ids = Column(JSON, unique=True)

    def is_active(self):
        """Required method for flask-login User class"""
        return self.active

    def get_id(self):
        """Required method for flask-login User class"""
        return self.username

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
            'email': self.email,
            'last_seen':  self.last_seen,
            }
        return json.dumps(ret)
