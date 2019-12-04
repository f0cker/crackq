# -*- coding: utf-8 -*-
import base64
import logging
import os
import urllib
import uuid
import zlib

from flask import Flask
from flask import redirect
from flask import request
from flask import url_for
from flask.ext.login import LoginManager
from flask.ext.login import UserMixin
from flask.ext.login import current_user
from flask.ext.login import login_required
from flask.ext.login import login_user
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

# PER APPLICATION configuration settings.
# Each SAML service that you support will have different values here.
idp_settings = {
    u'example.com': {
        u"metadata": {
            "local": [u'./example.com.metadata']
        }
    },
}
app = Flask(__name__)
app.secret_key = str(uuid.uuid4())  # Replace with your secret key
login_manager = LoginManager()
login_manager.setup_app(app)
