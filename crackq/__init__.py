"""Init file for CrackQ. Initialized Flask App"""
from crackq import cq_api, crackqueue, run_hashcat
from crackq.conf import hc_conf
from crackq.db import db
from crackq.models import User, Templates
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

import nltk

CRACK_CONF = hc_conf()


def create_app():
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__)
    aconf = CRACK_CONF['app']
    #CORS(app, resources={r'/*': {'origins': 'http://localhost:8081',
    #                             'supports_credentials': True},
    #                    })
    app.config['DEBUG'] = False
    app.config['JSON_SORT_KEYS'] = False
    app.config['SESSION_TYPE'] = aconf['SESSION_TYPE']
    app.config['SQLALCHEMY_DATABASE_URI'] = aconf['SQLALCHEMY_DATABASE_URI']
    app.config['SESSION_COOKIE_HTTPONLY'] = aconf['SESSION_COOKIE_HTTPONLY']
    app.config['SESSION_COOKIE_SECURE'] = aconf['SESSION_COOKIE_SECURE']
    app.config['PERMANENT_SESSION_LIFETIME'] = int(aconf['PERMANENT_SESSION_LIFETIME'])
    app.config['SESSION_PERMANENT'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    csrf = SeaSurf()
    app.config['CSRF_COOKIE_NAME'] = 'csrftoken'
    csrf.init_app(app)
    db.init_app(app)
    with app.app_context():
        db.create_all()
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
    login_manager.init_app(app)
    session = Session(app)
    session.init_app(app)
    migrate = Migrate()
    migrate.init_app(app, db, compare_type=True, render_as_batch=True)
    session.app.session_interface.db.create_all()
    return app

login_manager = LoginManager()
login_manager.session_protection = "strong"
nltk.download("wordnet")


@login_manager.user_loader
def load_user(user_id):
    """Flask load user info from db"""
    return User.query.get(user_id)

app = create_app()
