"""Init file for CrackQ. Initialized Flask App"""
from flask import Flask
from flask_cors import CORS
from flask_restful import Api
from crackq import cq_api
from crackq.conf import hc_conf
from crackq.db import db
from crackq.models import User
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
from flask_security import Security, SQLAlchemyUserDatastore

CRACK_CONF = hc_conf()


def create_app():
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__)
    aconf = CRACK_CONF['app']
    CORS(app, resources={r'/*': {'origins': 'http://localhost:8081',
                                 'supports_credentials': True},
                        })
    app.config['DEBUG'] = True
    app.config['SESSION_TYPE'] = aconf['SESSION_TYPE']
    app.config['SQLALCHEMY_DATABASE_URI'] = aconf['SQLALCHEMY_DATABASE_URI']
    app.config['SESSION_COOKIE_HTTPONLY'] = aconf['SESSION_COOKIE_HTTPONLY']
    app.config['SESSION_COOKIE_SECURE'] = aconf['SESSION_COOKIE_SECURE']
    app.config['PERMANENT_SESSION_LIFETIME'] = int(aconf['PERMANENT_SESSION_LIFETIME'])
    app.config['SESSION_PERMANENT'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    #csrf = SeaSurf()
    app.config['CSRF_COOKIE_NAME'] = 'csrftoken'
    #csrf.init_app(app)
    db.init_app(app)
    with app.app_context():
        db.create_all()
    admin_view = cq_api.Admin.as_view('admin')
    profile_view = cq_api.Profile.as_view('profile')
    app.add_url_rule('/api/admin/', defaults={'user_id': None},
                     view_func=admin_view, methods=['POST', 'GET'])
    app.add_url_rule('/api/admin/<int:user_id>',
                     view_func=admin_view, methods=['GET', 'DELETE', 'PUT', 'PATCH'])
    app.add_url_rule('/api/admin/',
                     view_func=admin_view, methods=['POST'])
    app.add_url_rule('/api/profile/',
                     view_func=profile_view, methods=['GET', 'POST'])
    api = Api(app)
    api.add_resource(cq_api.Login, '/api/login')
    api.add_resource(cq_api.Sso, '/api/sso')
    api.add_resource(cq_api.Logout, '/api/logout')
    api.add_resource(cq_api.Options, '/api/options')
    api.add_resource(cq_api.Queuing, '/api/queuing/<job_id>')
    api.add_resource(cq_api.Adder, '/api/add')
    api.add_resource(cq_api.Reports, '/api/reports')
    login_manager.init_app(app)
    session = Session(app)
    session.init_app(app)
    migrate = Migrate()
    migrate.init_app(app, db, compare_type=True)
    session.app.session_interface.db.create_all()
    return app

login_manager = LoginManager()
login_manager.session_protection = "strong"


@login_manager.user_loader
def load_user(user_id):
    """Flask load user info from db"""
    return User.query.get(user_id)

app = create_app()
