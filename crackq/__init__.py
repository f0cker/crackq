"""Init file for CrackQ. Initialized Flask App"""
from crackq.conf import hc_conf
from crackq.db import db
from flask import Flask
from flask_cors import CORS
from flask_login import (
    LoginManager,
    login_required,
    login_user,
    logout_user,
    UserMixin,
    current_user
    )
from flask_migrate import Migrate
from flask_session import Session
from flask_seasurf import SeaSurf
from flask_sqlalchemy import SQLAlchemy

import nltk

CRACK_CONF = hc_conf()
app = Flask(__name__)

aconf = CRACK_CONF['app']
app.config['DEBUG'] = False
app.config['JSON_SORT_KEYS'] = False
app.config['SESSION_TYPE'] = aconf['SESSION_TYPE']
app.config['SQLALCHEMY_DATABASE_URI'] = aconf['SQLALCHEMY_DATABASE_URI']
app.config['SESSION_COOKIE_HTTPONLY'] = aconf['SESSION_COOKIE_HTTPONLY']
app.config['SESSION_COOKIE_SECURE'] = aconf['SESSION_COOKIE_SECURE']
app.config['PERMANENT_SESSION_LIFETIME'] = int(aconf['PERMANENT_SESSION_LIFETIME'])
app.config['SESSION_PERMANENT'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_SQLALCHEMY'] = db

def create_app(app):
    """Create and configure an instance of the Flask application."""
    # uncomment below 3 lines when testing from npm/gui dev env
    #CORS(app, resources={r'/*': {'origins': 'http://localhost:8081',
    #                             'supports_credentials': True},
    #                    })
    app.config['CSRF_COOKIE_NAME'] = 'csrftoken'
    admin_view = cq_api.Admin.as_view('admin')
    profile_view = cq_api.Profile.as_view('profile')
    bench_view = cq_api.Benchmark.as_view('benchmark')
    login_view = cq_api.Login.as_view('login')
    logout_view = cq_api.Logout.as_view('logout')
    sso_view = cq_api.Sso.as_view('sso')
    options_view = cq_api.Options.as_view('options')
    queuing_view = cq_api.Queuing.as_view('queuing')
    add_view = cq_api.Adder.as_view('adder')
    report_view = cq_api.Reports.as_view('reports')
    tasks_view = cq_api.TasksView.as_view('tasks')
    templates_view = cq_api.TemplatesView.as_view('templates')
    app.add_url_rule('/api/admin/', defaults={'user_id': None},
                     view_func=admin_view, methods=['POST', 'GET'])
    app.add_url_rule('/api/admin/<uuid:user_id>',
                     view_func=admin_view, methods=['GET', 'DELETE',
                                                    'PUT', 'PATCH'])
    app.add_url_rule('/api/admin/',
                     view_func=admin_view, methods=['POST'])
    app.add_url_rule('/api/profile/',
                     view_func=profile_view, methods=['GET', 'POST'])
    app.add_url_rule('/api/benchmark/',
                     view_func=bench_view, methods=['GET', 'POST'])
    app.add_url_rule('/api/login',
                     view_func=login_view, methods=['GET', 'POST'])
    app.add_url_rule('/api/sso',
                     view_func=sso_view, methods=['GET', 'POST'])
    app.add_url_rule('/api/logout',
                     view_func=logout_view, methods=['GET'])
    app.add_url_rule('/api/options',
                     view_func=options_view, methods=['GET'])
    app.add_url_rule('/api/queuing/<string:job_id>',
                     view_func=queuing_view, methods=['GET', 'DELETE',
                                                      'PUT', 'PATCH'])
    app.add_url_rule('/api/add',
                     view_func=add_view, methods=['POST'])
    app.add_url_rule('/api/reports',
                     view_func=report_view, methods=['GET', 'POST'])
    app.add_url_rule('/api/tasks/templates', defaults={'temp_id': None},
                     view_func=templates_view, methods=['GET', 'PUT', 'DELETE'])
    app.add_url_rule('/api/tasks/templates/<uuid:temp_id>',
                     view_func=templates_view, methods=['DELETE'])
    app.add_url_rule('/api/tasks',
                     view_func=tasks_view, methods=['GET', 'POST'])
    app.add_url_rule('/api/tasks/<uuid:task_id>',
                     view_func=tasks_view, methods=['DELETE'])
    migrate = Migrate()
    with app.app_context():
        session = Session(app)
        # comment out below line when testing from npm/gui dev env 
        csrf.init_app(app)
        migrate.init_app(app, db, compare_type=True, render_as_batch=True)
        db.init_app(app)
        login_manager.init_app(app)
        db.create_all()
        app.session_interface.db.create_all()
    return app

nltk.download("wordnet")

csrf = SeaSurf()
login_manager = LoginManager()
login_manager.session_protection = "strong"

@login_manager.user_loader
def load_user(user_id):
    """Flask load user info from db"""
    return User.query.get(user_id)

from crackq import cq_api, crackqueue, run_hashcat
from crackq.models import User, Templates
create_app(app)
