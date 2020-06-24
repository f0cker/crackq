import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
#from flask_security import UserMixin, RoleMixin
from sqlalchemy import create_engine, Column, ForeignKey
#from sqlalchemy.ext.declarative import declarative_base
#from sqlalchemy.orm import backref, relationship
from sqlalchemy.types import (
    Boolean,
    DateTime,
    Integer,
    JSON,
    String,
    Unicode,
    )
from crackq.db import db
#Base = declarative_base()


"""
class RolesUsers(db.Model):
    __tablename__ = 'roles_users'
    id = db.Column(Integer(), primary_key=True)
    user_id = Column('user_id', Integer(), ForeignKey('user.id'))
    role_id = Column('role_id', Integer(), ForeignKey('role.id'))

class Role(db.Model, RoleMixin):
    __tablename__ = 'role'
    id = db.Column(Integer(), primary_key=True, index=True)
    name = Column(db.String(40), unique=True)
    username = Column(String(255), unique=True)
    description = Column(String(255))
"""
#Flask-security User-Roles relationship helper class
#Flask-security Role model for session management


class User(db.Model):
    """Flask-login User model for session management"""
    __tablename__ = 'user'
    id = Column(Integer(), primary_key=True, index=True)
    __table_args__ = {'extend_existing': True}
    active = Column(Boolean())
    username = Column(String(255), unique=True)
    email = Column(String(255), unique=True)
    last_login_at = Column(DateTime())
    last_seen = Column(DateTime())
    current_login_at = Column(DateTime())
    last_login_ip = Column(String(100))
    current_login_ip = Column(String(100))
    login_count = Column(Integer)
    confirmed_at = Column(DateTime())
    job_ids = Column(JSON, unique=True)
    is_admin = Column(Boolean())
    password = Column(Unicode(100))
    #roles = relationship('Role', secondary='roles_users',
    #                     backref=backref('user', lazy='dynamic'))

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
            'email': self.email,
            'last_seen':  self.last_seen,
            'password': self.password
            }
        return json.dumps(ret)
