from flask import Flask#, request
from flask_cors import CORS
from flask_restful import Api
#from flask_restful import reqparse, abort, Api, Resource
from crackq import cq_api
from crackq.conf import hc_conf
from crackq.db import db
#from logging.config import fileConfig
from flask_talisman import Talisman
from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin, current_user
#from flask_login import LoginManager
from flask_session import Session
from crackq.models import User
from flask_seasurf import SeaSurf

CRACK_CONF = hc_conf()


def create_app(test_config=None):
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__)
    aconf = CRACK_CONF['app']
    #CORS(app, resources={r'/*': {'origins': 'http://localhost:8081',
    #                             'supports_credentials': True},
    #                    })
    app.config['SESSION_TYPE'] = aconf['SESSION_TYPE']
    app.config['SQLALCHEMY_DATABASE_URI'] = aconf['SQLALCHEMY_DATABASE_URI']
    app.config['SESSION_COOKIE_HTTPONLY'] = aconf['SESSION_COOKIE_HTTPONLY']
    app.config['SESSION_COOKIE_SECURE'] = aconf['SESSION_COOKIE_SECURE']
    app.config['PERMANENT_SESSION_LIFETIME'] = int(aconf['PERMANENT_SESSION_LIFETIME'])
    app.config['SESSION_PERMANENT'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    #Talisman(app, strict_transport_security=False)
    #csrf = SeaSurf()
    app.config['CSRF_COOKIE_NAME'] = 'csrftoken'
    #csrf.init_app(app)
    db.init_app(app)
    with app.app_context():
        db.create_all()
    api = Api(app)
    api.add_resource(cq_api.Login, '/api/login')
    api.add_resource(cq_api.Sso, '/api/sso')
    api.add_resource(cq_api.Logout, '/api/logout')
    api.add_resource(cq_api.Options, '/api/options')
    api.add_resource(cq_api.Queuing, '/api/queuing/<job_id>')
    api.add_resource(cq_api.Adder, '/api/add')
    api.add_resource(cq_api.Reports, '/api/reports')

    #login_manager = LoginManager()
    #login_manager.session_protection = "strong"
    login_manager.init_app(app)
    session = Session(app)
    session.init_app(app)
    session.app.session_interface.db.create_all()
    return app

login_manager = LoginManager()
login_manager.session_protection = "strong"
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

app = create_app()
#db.create_all()


#if __name__ == '__main__':
#	#app = Flask(__name__)
#	#api = Api(app)
#	app.run(host='0.0.0.0', port=8080, debug=True)
