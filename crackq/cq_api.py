"""Main Flask code handling REST API"""
import base64
import json
import os
import re
import rq
import saml2
import threading
import time
import uuid

import crackq
from crackq.db import db
from crackq.logger import logger
from crackq.models import User, Templates, Tasks
from crackq import crackqueue, hash_modes, auth
from crackq.validator import FileValidation as valid
from crackq.conf import hc_conf
from crackq.run_hashcat import write_template
from datetime import datetime
from flask import (
    abort,
    Flask,
    jsonify,
    redirect,
    request,
    session)
from flask.views import MethodView
from flask_bcrypt import Bcrypt
from flask_seasurf import SeaSurf
from flask_login import (
    LoginManager,
    login_required,
    login_user,
    logout_user,
    current_user)
from functools import wraps
from marshmallow import Schema, fields, validate, ValidationError
from marshmallow.validate import Length, Range
from operator import itemgetter
from pathlib import Path
from pypal import pypal
from redis import Redis
from rq import Queue
from rq.serializers import JSONSerializer
from saml2 import BINDING_HTTP_POST
from saml2 import sigver
from sqlalchemy.orm import exc

# set perms
os.umask(0o077)

# Setup Flask App
login_manager = LoginManager()
app = Flask(__name__)
csrf = SeaSurf()
bcrypt = Bcrypt(app)
CRACK_CONF = hc_conf()

# Define HTTP messages
ERR_INVAL_JID = {'msg': 'Invalid Job ID'}
ERR_METH_NOT = {'msg': 'Method not supported'}
ERR_BAD_CREDS = {"msg": "Bad username or password"}


class StringContains(validate.Regexp):
    """
    Custom validation class to reject any strtings matching supplied regex

    See validate.Regexp for args/return values
    """
    default_message = 'Invalid input for this field.'

    def __call__(self, value):
        if len(self.regex.findall(value)) > 0:
            raise ValidationError(self._format_error(value))
        return value


class batch_schema(Schema):
    """
    Child schema for parse_json_schema to handle nested dict fields
    """
    job_id = fields.UUID()
    place = fields.Int()


class job_schema(Schema):
    """
    Child schema for parse_json_schema to handle jobs nested dict fields
    """
    error_messages = {
        "name": "Invalid input characters",
        "username": "Invalid input characters",
        }
    job_id = fields.UUID(allow_none=None)
    task_id = fields.UUID(allow_none=None)
    hash_list = fields.List(fields.String(validate=StringContains(
                            r'[^A-Za-z0-9\*\$\@\/\\\.\:\-\_\+\.\+\~]')),
                            allow_none=False, error_messages=error_messages)
    wordlist = fields.Str(allow_none=True, validate=[StringContains(r'[^A-Za-z0-9\_\-]'),
                                                     Length(min=1, max=60)])
    wordlist2 = fields.Str(allow_none=True, validate=[StringContains(r'[^A-Za-z0-9\_\-]'),
                                                      Length(min=1, max=60)])
    attack_mode = fields.Int(allow_none=True, validate=Range(min=0, max=9))
    rules = fields.List(fields.String(validate=[StringContains(r'[^A-Za-z0-9\_\-]'),
                                                Length(min=1, max=60)]),
                        allow_none=True)
    username = fields.Bool(allow_none=True)
    notify = fields.Bool(allow_none=True)
    increment = fields.Bool(allow_none=True)
    disable_brain = fields.Bool(allow_none=True)
    potcheck = fields.Bool(allow_none=True)
    increment_min = fields.Int(allow_none=True, validate=Range(min=0, max=20))
    increment_max = fields.Int(allow_none=True, validate=Range(min=0, max=20))
    mask = fields.Str(allow_none=True,
                      validate=StringContains(r'[^aldsu\?0-9a-zA-Z]'))
    mask_file = fields.List(fields.String(validate=[StringContains(r'[^A-Za-z0-9\_\-]'),
                                                    Length(min=1, max=60)]),
                            allow_none=True)
    name = fields.Str(allow_none=True,
                      validate=StringContains(r'[^A-Za-z0-9\_\-\ ]'),
                      error_messages=error_messages)
    hash_mode = fields.Int(allow_none=False, validate=Range(min=0, max=65535))
    restore = fields.Int(validate=Range(min=0, max=1000000000000))
    benchmark_all = fields.Bool(allow_none=True)
    timeout = fields.Int(validate=Range(min=1, max=28800000), allow_none=True)


class parse_json_schema(job_schema):
    """
    Class to create the schema for parsing received JSON arguments

    job_details: str
                string returned from rq.job.description

    Returns
    ------
    deets_dict: dictionary
                only the specified job details are returned

    """
    error_messages = {
        "name": "Invalid input characters",
        "username": "Invalid input characters",
        }
    user = fields.Str(allow_none=False, validate=StringContains(r'[^A-Za-z0-9\_\-]'))
    password = fields.Str(allow_none=False,
                          validate=StringContains(r'[^\w\!\@\#\$\%\^\&\*\(\)\-\+\.\,\\\/\]\[\=]'))
    confirm_password = fields.Str(allow_none=True,
                                  validate=[StringContains(r'[^\w\!\@\#\$\%\^\&\*\(\)\-\+\.\,\\\/\]\[\=]'),
                                            Length(min=10, max=60)])
    new_password = fields.Str(allow_none=True,
                              validate=[StringContains(r'[^\w\!\@\#\$\%\^\&\*\(\)\-\+\.\,\\\/\]\[\=]'),
                              Length(min=10, max=60)])
    email = fields.Str(allow_none=False,
                       validate=StringContains(r'[^\w\@\^\-\+\./]'))
    admin = fields.Bool(allow_none=True)
    policy_check = fields.Bool(allow_none=True)
    complexity_length = fields.Int(validate=Range(min=1, max=48),
                                   allow_none=True)
    admin_list = fields.List(fields.String(validate=StringContains(
                             r'[^A-Za-z0-9\*\$\@\/\.\-\_\+]')),
                             allow_none=True, error_messages=error_messages)
    batch_job = fields.List(fields.Nested(batch_schema))
    jobs = fields.List(fields.Nested(job_schema))
    fields.Nested(job_schema)

def get_jobdetails(job_details):
    """
    Function to help pull only required information from a specified redis job
    description string.
    job_details: str
                string returned from rq.job.description

    Returns
    ------
    deets_dict: dictionary
                only the specified job details are returned

    """
    deets_dict = {}
    if 'Benchmark' in job_details:
        deet_match_list = [
            'name',
            'benchmark',
            'benchmark_all'
            ]
    else:
        deet_match_list = [
            'hash_mode',
            'attack_mode',
            'mask',
            'wordlist',
            'wordlist2',
            'rules',
            'name',
            'username',
            'increment',
            'increment_min',
            'increment_max',
            'disable_brain',
            'brain_check',
            'restore']
    ###***make this less ugly
    ###***review stripping here for improvement
    logger.debug('Parsing job details:\n{}'.format(job_details))
    # Process rules list separately as workaround for splitting on comma
    if '[' in job_details:
        ###***add mask_file here when updating to allow list of files
        rules_split = job_details[job_details.rfind('[')+1:job_details.rfind(']')].strip()
        rules_list = [rule.strip().rstrip("'").lstrip("'") for rule in rules_split.split(',')]
    else:
        rules_list = None
    deets_split = job_details[job_details.rfind('(')+1:job_details.rfind(')')].split(',')
    for deets in deets_split:
        deet = deets.split('=')[0].strip(' ')
        if deet in deet_match_list:
            deets_dict[deet] = deets.strip().split('=')[1].strip().rstrip("'").lstrip("'")
    if 'Benchmark' in job_details:
        return deets_dict
    if rules_list:
        rule_names = []
        for key, rule in dict(CRACK_CONF['rules']).items():
            if rule in rules_list:
                rule_names.append(key)
        deets_dict['rules'] = rule_names
    else:
        deets_dict['rules'] = None
    if 'mask' in deets_dict:
        if deets_dict['mask']:
            mask = deets_dict['mask']
            for key, mask_file in dict(CRACK_CONF['masks']).items():
                if mask in mask_file:
                    deets_dict['mask'] = key
    if 'wordlist' in deets_dict:
        if deets_dict['wordlist']:
            wordlist = deets_dict['wordlist']
            for key, word in dict(CRACK_CONF['wordlists']).items():
                if wordlist in word:
                    deets_dict['wordlist'] = key
                    break
                else:
                    deets_dict['wordlist'] = None
    if 'wordlist2' in deets_dict:
        wordlist = deets_dict['wordlist2']
        for key, word in dict(CRACK_CONF['wordlists']).items():
            if wordlist in word:
                deets_dict['wordlist2'] = key
                break
            else:
                deets_dict['wordlist2'] = None
    return deets_dict


def add_jobid(job_id):
    """Add job_id to job_ids column in user table"""
    user = User.query.filter_by(username=current_user.username).first()
    if user.job_ids:
        logger.debug('Current registered job_ids: {}'.format(user.job_ids))
        jobs = json.loads(user.job_ids)
    else:
        logger.debug('No job_ids registered with current user')
        jobs = None
    logger.debug('Registering new job_id to current user: {}'.format(job_id))
    if isinstance(jobs, list):
        if job_id not in jobs:
            jobs.append(job_id)
        else:
            logger.warning('job_id already registered to user: {}'.format(job_id))
    else:
        jobs = [job_id]
    user.job_ids = json.dumps(jobs)
    db.session.commit()
    logger.debug('user.job_ids: {}'.format(user.job_ids))


def del_jobid(job_id):
    """Delete job_id from job_ids column in user table"""
    with crackq.app.app_context():
        for user in User.query.all():
            if user.job_ids and job_id in user.job_ids:
                jobs = json.loads(user.job_ids)
                logger.debug('Registered jobs: {}'.format(jobs))
                if isinstance(jobs, list):
                    logger.debug('Unregistering job_id: {}'.format(job_id))
                    if job_id in jobs:
                        jobs.remove(job_id)
                        user.job_ids = json.dumps(jobs)
                        db.session.commit()
                        logger.debug('user.job_ids: {}'.format((user.job_ids)))
                        return True
                else:
                    logger.error('Error removing job_id')
            else:
                logger.debug('Job ID not registered with user')
        return False


def check_jobid(job_id):
    """Check user owns the job_id"""
    logger.debug('Checking job_id: {} belongs to user: {}'.format(
                 job_id, current_user.username))
    user = User.query.filter_by(username=current_user.username).first()
    if user.job_ids:
        if job_id in user.job_ids:
            return True
        else:
            return False
    else:
        return False


def check_rules(orig_rules):
    """
    Check provided rules list is sane

    Arguments
    ---------
    orig_rules: list
        List of rules to check

    Returns
    -------
    rules: list
        List of rules or False if any are invalid
    """
    logger.debug('Checking rules valid')
    try:
        if orig_rules is None:
            rules = None
        elif isinstance(orig_rules, list):
            rules = []
            for rule in orig_rules:
                if rule in CRACK_CONF['rules']:
                    logger.debug('Using rules file: {}'.format(CRACK_CONF['rules'][rule]))
                    rules.append(CRACK_CONF['rules'][rule])
        else:
            logger.debug('Invalid rules provided')
            rules = False
    except KeyError:
        logger.debug('Invalid rules provided')
        rules = False
    return rules


def check_mask(orig_masks):
    """
    Check provided mask file list is sane

    Arguments
    ---------
    orig_masks: list
        List of mask files to check

    Returns
    -------
    mask_files: list
        List of mask files or False if any are invalid
    """
    logger.debug('Checking mask files are valid')
    try:
        if orig_masks is None:
            mask_file = None
        elif isinstance(orig_masks, list):
            mask_file = []
            for mask in orig_masks:
                if mask in CRACK_CONF['masks']:
                    #mask_name = CRACK_CONF['masks'][mask]
                    logger.debug('Using mask file: {}'.format(mask))
                    mask_file.append(CRACK_CONF['masks'][mask])
            return mask_file if len(mask_file) > 0 else None
        else:
            logger.debug('Invalid mask file provided')
            return False
    except KeyError:
        logger.debug('Invalid mask file provided')
        return False
    # this is just set to use the first mask file in the list for now
    #mask = mask_file[0] if mask_file else mask


def admin_required(func):
    @wraps(func)
    def wrap(*args, **kwargs):
        """Decorator to check user is admin"""
        try:
            logger.debug('User authenticating {}'.format(current_user.username))
            if current_user.is_admin:
                return func(*args, **kwargs)
        except AttributeError as err:
            logger.debug(err)
            logger.debug('Anonymous user cant be admin')
        return abort(401)
    return wrap


def create_user(username, email=None, password=None):
    """
    Adds a new user to the SQLAlchemy datastore

    Arguments
    ---------
    username: string
        Username to create

    Returns
    -------
    result: boolean
        True/False indicating status of delete operation
    """
    if User.query.filter_by(username=username).first():
        logger.debug('User already exists')
        return False
    else:
        user = User(username=username, email=email,
                    password=password, is_admin=False)
        db.session.add(user)
        db.session.commit()
        logger.debug('New user added')
        return True


def del_user(user_id):
    """
    Delete a user from the SQLAlchemy datastore

    Arguments
    ---------
    user_id: int
        User ID number for the user to delete

    Returns
    -------
    result: boolean
        True/False indicating status of delete operation
    """
    try:
        user = User.query.filter_by(id=user_id).first()
        db.session.delete(user)
        db.session.commit()
        return True
    except AttributeError:
        return False
    except exc.UnmappedInstanceError:
        return False


def email_check(email):
    """
    Simple regex check string is an email address

    Arguments
    --------
    email: str
        email address string to check
    Returns
    -------
    match: boolean
        true/false for valid email match
    """
    regex = r'^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
    if re.search(regex, email):
        logger.debug('Email address found')
        return True
    else:
        return False


def del_job(job):
    """
    Function to delete a job. Used to spawn a thread
    and wait for jobs to cleanup hashcat proc
    """
    time.sleep(22)
    logger.debug('Thread: deleting job')
    job.delete()
    del_jobid(job.id)


@login_manager.user_loader
def load_user(user_id):
    """user_loader function requried as part of Flask login-manager"""
    return User.query.filter_by(username=user_id).first()


class Sso(MethodView):
    """
    SAML2 Single Sign On Class

    Login class handles saml sso authentication responses from IDP,
    validates authenticity and authenticates if successful.
    """
    def __init__(self):
        if CRACK_CONF['auth']['type'] == 'saml2':
            self.meta_url = CRACK_CONF['auth']['saml_manifest']
            self.meta_file = CRACK_CONF['auth']['meta_file']
            self.entity_id = CRACK_CONF['auth']['entity_id']
            self.group = CRACK_CONF['auth']['group']
            self.saml_auth = auth.Saml2(self.meta_url,
                                        self.meta_file, self.entity_id)
            self.saml_client = self.saml_auth.s_client()

    def get(self):
        """
        Login mechanism, using GET to redirect to SAML IDP.
        """
        if CRACK_CONF['auth']['type'] == 'saml2':
            self.reqid, info = self.saml_client.prepare_for_authenticate()
            redirect_url = None
            for key, value in info['headers']:
                if key == 'Location':
                    redirect_url = value
            response = redirect(redirect_url, code=302)
            return response
        else:
            return jsonify(ERR_METH_NOT), 405

    @csrf.exempt
    def post(self):
        """
        Handle returned SAML reponse
        """
        if not CRACK_CONF['auth']['type'] == 'saml2':
            return jsonify(ERR_METH_NOT), 405
        ###***validate
        ###***readd/fix reqid verification
        saml_resp = request.form['SAMLResponse']
        logger.debug('SAML SSO reponse received:\n {}'.format(saml_resp))
        try:
            saml_parse = self.saml_client.parse_authn_request_response(saml_resp,
                                                        BINDING_HTTP_POST)
        except sigver.SignatureError as err:
            return 'Invalid Signature', 500
        except saml2.validate.ResponseLifetimeExceed as err:
            return 'Invalid SAML Request', 500
        #if saml_parse.in_response_to not in self.reqid:
        #    'Unsolicited authentication response', 500
        if saml_parse.authn_statement_ok():
            user_info = saml_parse.ava.items()
            groups = []
            for key, val in user_info:
                if 'name' in key:
                    username = val[0]
                if 'email' in key:
                    email = val[0]
                else:
                    email = None
                if self.group and 'Group' in key:
                    groups = val
            if self.group:
                if len(groups) > 0:
                    if self.group not in groups:
                        logger.debug('User authorised, but not in valid domain group')
                        return 'User is not authorised to use this service', 401
                else:
                    logger.debug('No groups returned in SAML response')
                    return 'User is not authorised to use this service', 401
            #try:
            #    username
            #except UnboundLocalError:
            #    return {'msg': 'No user returned in SAML response'}, 500
            logger.debug('Authenticated: {}'.format(username))
            user = load_user(username)
            if user:
                crackq.app.session_interface.regenerate(session)
            else:
                if email_check(email):
                    create_user(username, email=email)
                else:
                    create_user(username)
            user = load_user(username)
            if isinstance(user, User):
                crackq.app.session_interface.regenerate(session)
                login_user(user)
            else:
                logger.error('No user object loaded')
                return jsonify(ERR_BAD_CREDS), 401 
            return redirect('/')
        else:
            ###***add error output to debug
            logger.debug('Login error')
            return jsonify(ERR_BAD_CREDS), 401


class Login(MethodView):
    """
    Authentication handler

    Login class handles authentication, it's protocol agnostic
    and just needs the 'authenticate' fucntion to provide a
    'Success' or 'Failure' result. The 'authenticate' function
    can use any supported protocols or a custom protocol can be
    created.
    """
    def post(self):
        """
        Login mechanism, using POST.
        Supply the following in the body: {"user": "xxx", "password": "xxx"}

        """
        try:
            marsh_schema = parse_json_schema().load(request.json)
            args = marsh_schema
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        if CRACK_CONF['auth']['type'] == 'ldap':
            username = args['user']
            password = args['password']
            if not username:
                return jsonify({"msg": "Missing username parameter"}), 400
            if not password:
                return jsonify({"msg": "Missing password parameter"}), 400
            ldap_uri = CRACK_CONF['auth']['ldap_server']
            ldap_base = CRACK_CONF['auth']['ldap_base']
            auther = auth.Ldap()
            authn = auther.authenticate(ldap_uri, username, password,
                                        ldap_base=ldap_base)
            logger.debug('LDAP reply: {}'.format(authn))
            if authn[0] == "Success":
                logger.debug('Authenticated: {}'.format(username))
                user = load_user(username)
                if user:
                    crackq.app.session_interface.regenerate(session)
                    login_user(user)
                else:
                    if len(authn) > 1:
                        email = authn[1]
                    else:
                        email = username
                    if email_check(email):
                        logger.debug('Email address found, using for notify')
                        create_user(username, email=email)
                    else:
                        create_user(username)
                    user = load_user(username)
                if isinstance(user, User):
                    crackq.app.session_interface.regenerate(session)
                    login_user(user)
                else:
                    logger.error('No user object loaded')
                    return jsonify(ERR_BAD_CREDS), 401
                return 'OK', 200
            elif authn[0] == "Invalid Credentials":
                return jsonify(ERR_BAD_CREDS), 401
            else:
                logger.debug('Login error: {}'.format(authn))
                return jsonify(ERR_BAD_CREDS), 401
        if CRACK_CONF['auth']['type'] == 'sql':
            user = User.query.filter_by(username=args['user']).first()
            if isinstance(user, User):
                if bcrypt.check_password_hash(user.password, args['password']):
                    crackq.app.session_interface.regenerate(session)
                    login_user(user)
                    return 'OK', 200
            return jsonify(ERR_BAD_CREDS), 401
        else:
            return jsonify(ERR_METH_NOT)


class Logout(MethodView):
    """
    Session Logout

    Class to logout and clear flask session cookie
    """
    @login_required
    def get(self):
        logger.debug('User logged out: {}'.format(current_user.username))
        user = User.query.filter_by(username=current_user.username).first()
        crackq.app.session_interface.destroy(session)
        user.active = False
        db.session.commit()
        logout_user()
        return 'Logged Out', 200


class Queuing(MethodView):
    """
    Class to interact with the crackqueue module

    This will instantiate a crackqueue instance and use
    it to manage jobs in the Redis queue using RQ

    """
    def __init__(self):
        self.crack_q = crackqueue.Queuer()
        self.q = self.crack_q.q_connect()
        rconf = CRACK_CONF['redis']
        self.log_dir = CRACK_CONF['files']['log_dir']
        self.redis_con = Redis(rconf['host'], rconf['port'])
        self.req_max = CRACK_CONF['misc']['req_max']
        self.speed_q = Queue('speed_check', connection=self.redis_con,
                             serializer=JSONSerializer)

    def zombie_check(self, started, failed, cur_list):
        """
        This method will check and remove zombie jobs from
        the started queue.

        RQ has a bug which causes multiple started jobs to exist
        after a system error has occured (unplanned exeception of some sort).
        This method will clean this up and requeus the affected job.
        """
        logger.debug('Checking for zombie jobs')
        while len(started.get_job_ids()) > 1:
            logger.debug('Zombie job detected')
            logger.debug('Started jobs: {}'.format(cur_list))
            hung_dict = {}
            for j in cur_list:
                job = self.q.fetch_job(j)
                if job is not None:
                    hung_dict[j] = job.started_at
            latest = max(hung_dict, key=hung_dict.get)
            for j in cur_list:
                if j != latest:
                    job = self.q.fetch_job(j)
                    if job:
                        job.set_status('failed')
                        failed.add(job)
                        logger.debug('Cleaning state job: {}'.format(j))
                        started.remove(job)
                        try:
                            if job.meta['Requeue Count'] <= int(self.req_max):
                                failed.requeue(j)
                                job.meta['Requeue Count'] += 1
                                job.save_meta()
                        except KeyError:
                            job.meta['Requeue Count'] = 0

    def get_comp_dict(self, comp_list, session=False):
        """
        Function to get complete queue information

        Arguments
        ---------
        comp_list: list
            list of job IDs in complete queue
        session: string
            session ID to reduce returned dictionary to jobs owned by user.

        Returns
        -------
        comp_dict: dictionary
            dict containing high-level info for jobs in complete queue
        """
        comp_dict = {}
        for job_id in comp_list:
            if session:
                if check_jobid(job_id):
                    job = self.q.fetch_job(job_id)
                else:
                    job = None
            ###***remove below?
            else:
                job = self.q.fetch_job(job_id)
            if job:
                comp_dict[job_id] = {}
                job_deets = get_jobdetails(job.description)
                try:
                    if isinstance(job.meta['HC State'], dict):
                        cracked = str(job.meta['HC State']['Cracked Hashes'])
                        total = str(job.meta['HC State']['Total Hashes'])
                        comp_dict[job_id]['Cracked'] = '{}/{}'.format(cracked, total)
                        comp_dict[job_id]['Running Time'] = job.meta['HC State']['Running Time']
                        try:
                            comp_dict[job_id]['Name'] = get_jobdetails(job.description)['name']
                        except KeyError:
                            comp_dict[job_id]['Name'] = 'No name'
                        except AttributeError:
                            comp_dict[job_id]['Name'] = 'No name'
                except KeyError:
                    logger.debug('No HC state, checking state file')
                    job_file = valid.val_filepath(path_string=self.log_dir,
                                                  file_string='{}.json'.format(job_id))
                    try:
                        with open(job_file, 'r') as jobfile_fh:
                            job_deets = json.loads(jobfile_fh.read().strip())
                            comp_dict[job_id]['Name'] = job_deets['name']
                            cracked = job_deets['Cracked Hashes']
                            total = job_deets['Total Hashes']
                            comp_dict[job_id]['Cracked'] = '{}/{}'.format(cracked, total)
                            comp_dict[job_id]['Running Time'] = '0'
                    except FileNotFoundError as err:
                        logger.debug('Failed to open job file: {}'.format(err))
                except Exception as err:
                    logger.debug('Failed to open job file: {}'.format(err))
            else:
                logger.error('Job is missing: {}'.format(job_id))
        return comp_dict

    @login_required
    def get(self, job_id):
        """
        Method to get job status

        job_id: str
            hex reprisentation of uuid job ID

        Returns
        ------

        """
        time_now = datetime.now().strftime("%Y-%m-%d %H:%M")
        time_now = datetime.strptime(time_now, '%Y-%m-%d %H:%M')
        current_user.last_seen = time_now
        db.session.commit()
        ###***re-add this for validation?
        #args = marsh_schema.data
        started = rq.registry.StartedJobRegistry(queue=self.q)
        failed = rq.registry.FailedJobRegistry(queue=self.q)
        cur_list = started.get_job_ids()
        ###**update all connections to user get_current_connection()??
        self.zombie_check(started, failed, cur_list)
        q_dict = self.crack_q.q_monitor(self.q)
        logger.debug('Current jobs: {}'.format(cur_list))
        failed_dict = self.crack_q.check_failed(self.q)
        comp_list = self.crack_q.check_complete(self.q)
        last_comp = []
        end_times = {}
        if len(comp_list) > 0:
            ###***make this a function/method
            for j in comp_list:
                if check_jobid(j):
                    job = self.q.fetch_job(j)
                    if job:
                        ended = job.ended_at
                        if ended:
                            end_times[j] = ended
            if len(end_times) > 0:
                latest = max(end_times, key=end_times.get)
            else:
                latest = None
            if latest:
                job = self.q.fetch_job(latest)
            else:
                job = None
            if job:
                try:
                    job_name = get_jobdetails(job.description)['name']
                except KeyError:
                    job_name = 'No name'
                except AttributeError:
                    job_name = 'No name'
                # just a single job for now
                last_comp = [{'job_name': job_name,
                              'job_id': latest}]
        else:
            last_comp = [{'job_name': 'None'}]
        q_dict['Last Complete'] = last_comp
        logger.debug('Completed jobs: {}'.format(comp_list))
        logger.debug('q_dict: {}'.format(q_dict))
        if not job_id.isalnum():
            return jsonify(ERR_INVAL_JID), 500
        if job_id == 'all':
            ###***definitely make these a function
            if len(cur_list) > 0:
                job = self.q.fetch_job(cur_list[0])
                if current_user.job_ids and job:
                    if cur_list[0] in json.loads(current_user.job_ids):
                        job.meta['email_count'] = 0
                        job.save()
                if job:
                    if 'HC State' in job.meta:
                        ###***remove this?
                        if isinstance(job.meta['HC State'], dict):
                            job_details = get_jobdetails(job.description)
                            try:
                                q_dict['Current Job'][cur_list[0]]['Job Details'] = job_details
                            except KeyError:
                                logger.error('No job to update - does not exist')
                else:
                    logger.error('No Queue')
            if len(q_dict) > 0:
                for qjob_id in q_dict['Queued Jobs']:
                    job = self.q.fetch_job(qjob_id)
                    job_details = get_jobdetails(job.description)
                    q_dict['Queued Jobs'][qjob_id]['Job Details'] = job_details
            return jsonify(q_dict), 200
        elif job_id == 'failed':
            return jsonify(failed_dict), 200
        elif job_id == 'failedless':
            failess_dict = {}
            for job_id in failed_dict:
                if check_jobid(job_id):
                    failess_dict[job_id] = failed_dict[job_id]
            return jsonify(failess_dict), 200
        elif job_id == 'complete':
            comp_dict = {}
            comp_dict = self.get_comp_dict(comp_list, session=False)
            return jsonify(comp_dict), 200
        elif job_id == 'completeless':
            comp_dict = {}
            comp_dict = self.get_comp_dict(comp_list, session=True)
            return jsonify(comp_dict), 200
        else:
            try:
                marsh_schema = parse_json_schema().load({'job_id': job_id})
                job_id = marsh_schema['job_id'].hex
            except ValidationError as errors:
                logger.debug('Validation error: {}'.format(errors))
                return errors.messages, 500
            if check_jobid(job_id):
                job = self.q.fetch_job(job_id)
                if job:
                    cracked_file = '{}{}.cracked'.format(self.log_dir, job_id)
                    job_details = get_jobdetails(job.description)
                    if job_id in q_dict['Queued Jobs']:
                        job_dict = {
                            'Status': 'Queued',
                            'Time started': None,
                            'Time finished': None,
                            'Job Details': job_details,
                            'Result': job.result,
                            'HC State': job.meta,
                            }
                    else:
                        job_dict = {
                            'Status': job.get_status(),
                            'Time started': str(job.started_at),
                            'Time finished': str(job.ended_at),
                            'Job Details': job_details,
                            'Result': job.result,
                            'HC State': job.meta,
                            }
                    try:
                        with open(cracked_file, 'r') as cracked_fh:
                            job_dict['Cracked'] = [crack.strip() for crack in cracked_fh]
                    except IOError as err:
                        logger.debug('Cracked file does not exist: {}'.format(err))
                    return jsonify(job_dict), 200
                else:
                    return abort(404)
            else:
                return abort(401)

    @login_required
    def put(self, job_id):
        """
        Method to reorder the queue

        This will clear the queued jobs and re-add them in
        the order specified with a JSON batch add

        jobord_dict: dict
            Dictionary containing batch job add details as:
                {job_id: place}
            job_id: str hex representation of uuid job ID
            place: int indicating place in queue

        Returns
        ------
        """
        try:
            marsh_schema = parse_json_schema().load(request.json)
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return jsonify({'msg': errors.messages}), 500
        comp = rq.registry.FinishedJobRegistry(queue=self.q)
        ###***change this to match reports, validate job_id correctly
        if job_id == "reorder":
            logger.debug('Reorder queue command received')
            logger.debug(marsh_schema['batch_job'])
            try:
                adder = Adder()
                if len(marsh_schema['batch_job']) < 1:
                    logger.error('Reorder failed: Invalid request')
                    return {'msg': 'Reorder failed - Invalid request'}, 500
                for job in marsh_schema['batch_job']:
                    job_id = job['job_id']
                    if adder.session_check(self.log_dir, job_id):
                        logger.debug('Valid session found')
                        started = rq.registry.StartedJobRegistry(queue=self.q)
                        cur_list = started.get_job_ids()
                        if job_id in cur_list:
                            logger.error('Job is already running')
                            return {'msg': 'Job is already running'}, 500
                marsh_schema['batch_job'].sort(key=itemgetter('place'))
                for job in self.q.jobs:
                    job.set_status('finished')
                    job.save()
                    comp.add(job, -1)
                    job.cleanup(-1)
                for job in marsh_schema['batch_job']:
                    Queue.dequeue_any(self.q, None, connection=self.redis_con,
                                      serializer=JSONSerializer)
                    j = self.q.fetch_job(job['job_id'])
                    ###***check this covers case when job is in requeued state
                    self.q.enqueue_job(j)
                    j.meta['CrackQ State'] = 'Run/Restored'
                    j.save_meta()
                return {'msg': 'Queue order updated'}, 200
            except Exception as err:
                ###***fix to specific exception types
                logger.error('Reorder failed: {}'.format(err))
                return {'msg': 'Reorder failed'}, 500

    @login_required
    def patch(self, job_id):
        """
        Method to stop/remove a job from the active queue to complete
        and cancel current hashcat job if it's already running

        Arguments
        ---------
        job_id: str
            hex reprisentation of uuid job ID

        Returns
        ------
        HTTP 204

        """
        try:
            marsh_schema = parse_json_schema().load({'job_id': job_id})
            job_id = marsh_schema['job_id'].hex
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        try:
            logger.debug('Stopping job: {:s}'.format(job_id))
            job = self.q.fetch_job(job_id)
            started = rq.registry.StartedJobRegistry(queue=self.q)
            cur_list = started.get_job_ids()
            comp = rq.registry.FinishedJobRegistry(queue=self.q)
            if job_id in cur_list:
                job.meta['CrackQ State'] = 'Stop'
                job.save_meta()
                return 'Stopping Job: Sending signal to Hashcat', 204
            else:
                job.set_status('finished')
                job.save()
                comp.add(job, -1)
                job.cleanup(-1)
                Queue.dequeue_any(self.q, None, connection=self.redis_con,
                                  serializer=JSONSerializer)
                return 'Stopped Job', 200
        except AttributeError as err:
            logger.debug('Failed to stop job: {}'.format(err))
            return jsonify(ERR_INVAL_JID), 404

    @login_required
    def delete(self, job_id):
        """
        Method to remove a job from the queue completely
        and cancel current hashcat job if it's already running.
        This will remove all trace of the job

        Arguments
        ---------
        job_id: str
            hex reprisentation of uuid job ID

        Returns
        ------
        HTTP 200 or 204 depending on what state job is in

        """
        try:
            marsh_schema = parse_json_schema().load({'job_id': job_id})
            job_id = marsh_schema['job_id'].hex
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        try:
            logger.debug('Deleting job: {:s}'.format(job_id))
            job = self.q.fetch_job(job_id)
            started = rq.registry.StartedJobRegistry(queue=self.q)
            cur_list = started.get_job_ids()
            speed_session = '{}_speed'.format(job_id)
            speed_job = self.speed_q.fetch_job(speed_session)
            if speed_job:
                logger.debug('Deleting Speed Job')
                speed_job.meta['CrackQ State'] = 'Delete'
                speed_job.save_meta()
                if speed_job.get_status() != 'started':
                    speed_job.delete()
            if job_id in cur_list:
                job.meta['CrackQ State'] = 'Delete'
                job.save_meta()
                del_thread = threading.Thread(target=del_job, args=(job,))
                del_thread.start()
                return {'msg': 'Deleted Job'}, 204
            del_jobid(job_id)
            job.delete()
            started.cleanup()
            return {'msg': 'Deleted Job'}, 200
        except AttributeError as err:
            logger.error('Failed to delete job: {}'.format(err))
            return jsonify(ERR_INVAL_JID), 404


class Options(MethodView):
    """
    Class for pulling option information, such as a list of available
    rules and wordlists

    """
    def __init__(self):
        self.crack_q = crackqueue.Queuer()
        self.q = self.crack_q.q_connect()
        rconf = CRACK_CONF['redis']
        self.redis_con = Redis(rconf['host'], rconf['port'])

    @login_required
    def get(self):
        """
        Method to get config information


        Returns
        ------
        hc_dict: dictionary
            crackq config options for rules/wordlists


        """
        hc_rules = [rule for rule in CRACK_CONF['rules']]
        hc_words = [word for word in CRACK_CONF['wordlists']]
        hc_maskfiles = [maskfile for maskfile in CRACK_CONF['masks']]
        hc_modes = dict(hash_modes.HModes.modes_dict())
        hc_att_modes = {
            '0': 'Straight',
            '1': 'Combination',
            '3': 'Brute-Force',
            '6': 'Hybrid Wordlist + Mask',
            '7': 'Hybrid Mask + Wordlist',
            }
        if 'jobtimeout' in CRACK_CONF:
            timeout_info = CRACK_CONF['jobtimeout']
        else:
            timeout_info = {
                'Value': 1814400,
                'Modify': False,
                }
        hc_dict = {
            'Rules': hc_rules,
            'Wordlists': hc_words,
            'Mask Files': hc_maskfiles,
            'Hash Modes': hc_modes,
            'Attack Modes': hc_att_modes,
            'timeout': timeout_info,
            }
        return hc_dict, 200


class Adder(MethodView):
    """
    Separate class for adding jobs

    """
    def __init__(self):
        self.crack_q = crackqueue.Queuer()
        self.q = self.crack_q.q_connect()
        self.log_dir = CRACK_CONF['files']['log_dir']
        rconf = CRACK_CONF['redis']
        self.redis_con = Redis(rconf['host'], rconf['port'])
        self.speed_q = Queue('speed_check', connection=self.redis_con,
                             serializer=JSONSerializer)

    def mode_check(self, mode):
        """
        Mode to check supplied hash mode is supported by Hashcat

        Arguments
        ---------
        mode: int
            hashcat mode number to check

        Returns
        -------
        mode: int/boolean
            returns mode if found else false

        """
        modes_dict = dict(hash_modes.HModes.modes_dict())
        logger.debug('Checking hash mode is supported: {}'.format(mode))
        if str(mode) in modes_dict.keys():
            return int(mode)
        else:
            return False

    def get_restore(self, log_dir, job_id):
        """
        Get restore number from CrackQ json status file
        Arguments
        ---------
        log_dir: str
            log directory
        job_id: str
            job ID string
        Returns
        -------
        restore: int
            Restore number to be used with hashcat skip
            returns 0 on error
        """
        logger.debug('Checking for restore value')
        if job_id.isalnum():
            job_file = valid.val_filepath(path_string=self.log_dir,
                                          file_string='{}.json'.format(job_id))
            logger.debug('Using session file: {}'.format(job_file))
            try:
                with open(job_file) as fh_job_file:
                    try:
                        status_json = json.loads(fh_job_file.read())
                        logger.debug('Restoring job details: {}'.format(status_json))
                        return status_json
                    except IOError as err:
                        logger.warning('Invalid job ID: {}'.format(err))
                        return False
                    except TypeError as err:
                        logger.warning('Invalid job ID: {}'.format(err))
                        return False
            except IOError as err:
                logger.warning('Restore file Error: {}'.format(err))
                return False
            #except json.decoder.JSONDecodeError as err:
            ###***make explicit
            except Exception as err:
                logger.warning('Restore file Error: {}'.format(err))
                return False
        else:
            logger.warning('Invalid job ID')
            return False

    def session_check(self, log_dir, job_id):
        """
        Check for existing session and return the ID if present
        else False

        Arguments
        ---------
        log_dir: str
            directory containing cracker log and session files
        job_id: str
            job/session id string (alnum)
        Returns
        -------
        sess_id: bool
            True if session/job ID is valid and present
        """
        logger.debug('Checking for existing session')
        log_dir = Path(log_dir)
        sess_id = False
        if job_id.isalnum():
            try:
                for f in Path.iterdir(log_dir):
                    if job_id in str(f):
                        sess_id = True
                        break
            except ValueError as err:
                logger.debug('Invalid session ID: {}'.format(err))
                sess_id = False
            except Exception as err:
                logger.warning('Invalid session: {}'.format(err))
                sess_id = False
        else:
            logger.debug('Invalid session ID provided')
            sess_id = False
        if sess_id is not False:
            logger.debug('Existing session found')
        return sess_id

    def speed_check(self, q_args=None):
        """
        Method to run initial speed/show check in hashcat

        This will get information related to estimated speed
        for brain enablement, but also check for any quick wins
        in the pot file before the job actually gets to the top
        of the queue.

        It takes the job ID queues a separate job in a separate
        queue that will pause any current hashcat jobs and briefly
        run the speed/show checks, then resumes the job.
        ####***UPDATE THIS DOCUMENTATION

        Arguments
        ---------
        job_id: uuid
            Job ID to update

        Returns
        ------
        ret: boolean
            Success/Fail
        """
        logger.debug('Running speed check')
        if q_args:
            speed_args = {}
            speedq_args = {}
            speed_args['hash_file'] = q_args['kwargs']['hash_file']
            speed_session = '{}_speed'.format(q_args['kwargs']['session'])
            speed_args['speed_session'] = speed_session
            speed_args['session'] = q_args['kwargs']['session']
            speed_args['wordlist'] = q_args['kwargs']['wordlist']
            speed_args['wordlist2'] = q_args['kwargs']['wordlist2']
            speed_args['hash_mode'] = q_args['kwargs']['hash_mode']
            speed_args['username'] = q_args['kwargs']['username']
            speed_args['name'] = q_args['kwargs']['name']
            speed_args['brain'] = q_args['kwargs']['brain']
            speed_args['attack_mode'] = q_args['kwargs']['attack_mode']
            speed_args['mask'] = '?a?a?a?a?a?a' if q_args['kwargs']['mask'] else None
            speed_args['pot_path'] = q_args['kwargs']['pot_path']
            speedq_args['kwargs'] = speed_args
            speedq_args['job_id'] = speed_session
            self.crack_q.q_add(self.speed_q, speedq_args, timeout=600)
            logger.debug('Queuing speed check')
            return True
        return False

    def queue_job(self, args, job_id=None):
        """
        Method to check sanity of job arguments and add
        job to redis queue
        """
        # Check for existing session info
        if job_id:
            if job_id.isalnum():
                if self.session_check(self.log_dir, job_id):
                    logger.debug('Valid session found')
                    started = rq.registry.StartedJobRegistry(queue=self.q)
                    cur_list = started.get_job_ids()
                    q_dict = self.crack_q.q_monitor(self.q)
                    if job_id in cur_list:
                        logger.error('Job is already running')
                        return jsonify({'msg': 'Job is already running'}), 500
                    if job_id in q_dict['Queued Jobs'].keys():
                        logger.error('Job is already queued')
                        return jsonify({'msg': 'Job is already queued'}), 500
                    outfile = str(valid.val_filepath(path_string=self.log_dir,
                                                     file_string='{}.cracked'.format(job_id)))
                    hash_file = str(valid.val_filepath(path_string=self.log_dir,
                                                       file_string='{}.hashes'.format(job_id)))
                    pot_path = str(valid.val_filepath(path_string=self.log_dir,
                                                      file_string='crackq.pot'))
                    job_deets = self.get_restore(self.log_dir, job_id)
                    job = self.q.fetch_job(job_id)  # lgtm
                    if not job_deets:
                        logger.debug('Job restor error. Never started')
                        return jsonify({'msg': 'Error restoring job'}), 500
                    elif not job_deets['restore']:
                        logger.debug('Job not previously started, restore = 0')
                        job_deets['restore'] = 0
                    elif job_deets['restore'] == 0:
                        logger.debug('Job not previously started, restore = 0')
                    wordlist = None
                    wordlist2 = None
                    rules = None
                    if 'wordlist' in job_deets:
                        if job_deets['wordlist'] in CRACK_CONF['wordlists']:
                            wordlist = CRACK_CONF['wordlists'][job_deets['wordlist']]
                    if 'wordlist2' in job_deets:
                        if job_deets['wordlist2']:
                            if job_deets['wordlist2'] in CRACK_CONF['wordlists']:
                                wordlist2 = CRACK_CONF['wordlists'][job_deets['wordlist2']]
                    if 'rules' in job_deets:
                        rules = check_rules(job_deets['rules'])
                        if rules is False:
                            return jsonify({'msg': 'Invalid rules selected'}), 500
                    mask_file = check_mask(job_deets['mask'])
                    # this is just set to use the first mask file in the list for now
                    mask = mask_file if mask_file else job_deets['mask']
                    try:
                        ###***make this (timeout - running time) for restored jobs??
                        timeout = job_deets['timeout']
                    except KeyError as err:
                        logger.warning('No timeout info in job details, using default')
                        timeout = 1814400
                    hc_args = {
                        'hash_file': hash_file,
                        'session': job_id,
                        'wordlist': wordlist,
                        'wordlist2': wordlist2,
                        'mask': mask,
                        'mask_file': True if mask_file else False,
                        'attack_mode': int(job_deets['attack_mode']),
                        'hash_mode': int(job_deets['hash_mode']),
                        'outfile': outfile,
                        'rules': rules,
                        'restore': job_deets['restore'],
                        'username': job_deets['username'] if 'user' in job_deets else None,
                        'increment': job_deets['increment'] if 'increment' in job_deets else None,
                        'increment_min': job_deets['increment_min'] if 'increment_min' in job_deets else None,
                        'increment_max': job_deets['increment_max'] if 'increment_max' in job_deets else None,
                        'brain': False if 'disable_brain' in job_deets else True,
                        'name': job_deets['name'] if 'name' in job_deets else None,
                        'pot_path': pot_path,
                        }
                    job = self.q.fetch_job(job_id)
                    job.meta['CrackQ State'] = 'Run/Restored'
                    job.save_meta()
                else:
                    return jsonify(ERR_INVAL_JID), 500
            else:
                return jsonify(ERR_INVAL_JID), 500
        else:
            logger.debug('Creating new session')
            job_id = uuid.uuid4().hex
            add_jobid(job_id)
            outfile = str(valid.val_filepath(path_string=self.log_dir,
                                             file_string='{}.cracked'.format(job_id)))
            hash_file = str(valid.val_filepath(path_string=self.log_dir,
                                               file_string='{}.hashes'.format(job_id)))
            pot_path = str(valid.val_filepath(path_string=self.log_dir,
                                              file_string='crackq.pot'))
            try:
                attack_mode = int(args['attack_mode'])
            except TypeError:
                attack_mode = None
            try:
                logger.debug('Writing hashes to file: {}'.format(hash_file))
                with open(hash_file, 'w') as hash_fh:
                    for hash_l in args['hash_list']:
                        hash_fh.write(hash_l.rstrip() + '\n')
            except KeyError as err:
                logger.debug('No hash list provided: {}'.format(err))
                return jsonify({'msg': 'No hashes provided'}), 500
            except IOError as err:
                logger.debug('Unable to write to hash file: {}'.format(err))
                return jsonify({'msg': 'System error'}), 500
            try:
                args['hash_mode']
                check_m = self.mode_check(args['hash_mode'])
            except KeyError:
                check_m = False
            logger.debug('Hash mode check: {}'.format(check_m))
            ###***change to if check_m
            if check_m is not False:
                try:
                    mode = int(check_m)
                except TypeError as err:
                    logger.error('Incorrect type supplied for hash_mode:'
                                 '\n{}'.format(err))
                    return jsonify({'msg': 'Invalid hash mode selected'}), 500
            else:
                return jsonify({'msg': 'Invalid hash mode selected'}), 500
            if attack_mode != 3:
                if args['wordlist'] in CRACK_CONF['wordlists']:
                    wordlist = CRACK_CONF['wordlists'][args['wordlist']]
                else:
                    return jsonify({'msg': 'Invalid wordlist selected'}), 500
            if attack_mode == 1:
                if 'wordlist2' in args:
                    if args['wordlist2'] in CRACK_CONF['wordlists']:
                        wordlist2 = CRACK_CONF['wordlists'][args['wordlist2']]
                    else:
                        return jsonify({'msg': 'Combinator mode requires 2 wordlists'}), 500
            else:
                wordlist2 = None
            try:
                mask_file = check_mask(args['mask_file'])
            except KeyError:
                mask_file = None
            try:
                mask = args['mask']
            except KeyError:
                mask = None
            ####***this is just set to use the first mask file in the list for now
            mask = mask_file[0] if mask_file else mask
            rules = check_rules(args['rules'])
            if rules is False:
                return {'msg': 'Invalid rules selected'}, 500
            try:
                username = args['username']
            except KeyError as err:
                logger.debug('Username value not provided')
                username = False
            try:
                increment = args['increment']
            except KeyError as err:
                logger.debug('Increment value not provided')
                increment = False
            try:
                increment_min = args['increment_min']
            except KeyError as err:
                logger.debug('Increment min value not provided')
                increment_min = None
            try:
                increment_max = args['increment_max']
            except KeyError as err:
                logger.debug('Increment max value not provided')
                increment_max = None
            try:
                if args['disable_brain']:
                    logger.debug('Brain disabled')
                    brain = False
                else:
                    brain = True
            except KeyError as err:
                logger.debug('Brain not disabled: {}'.format(err))
                brain = True
            try:
                name = args['name']
            except KeyError as err:
                logger.debug('Name value not provided')
                name = None
            try:
                potcheck = args['potcheck']
            except KeyError as err:
                logger.debug('Potcheck value not provided')
                potcheck = False
            timeout = 1814400
            if 'jobtimeout' in CRACK_CONF:
                if not CRACK_CONF['jobtimeout']['Modify']:
                    logger.debug('Timeout modification not permitted')
                    timeout = CRACK_CONF['jobtimeout']['Value']
                else:
                    if 'timeout' in args:
                        timeout = args['timeout']
            hc_args = {
                'hash_file': hash_file,
                'session': job_id,
                'wordlist': wordlist if attack_mode != 3 else None,
                'wordlist2': wordlist2 if attack_mode == 1 else None,
                'mask': mask if attack_mode > 2 else None,
                'mask_file': True if mask_file else False,
                'attack_mode': attack_mode,
                'hash_mode': mode,
                'outfile': outfile,
                'rules': rules,
                'username': username,
                'increment': increment,
                'increment_min': increment_min,
                'increment_max': increment_max,
                'brain': brain,
                'name': name,
                'pot_path': pot_path,
                'restore': 0,
                'potcheck': potcheck
            }
        q_args = {
            'job_id': job_id,
            'kwargs': hc_args,
            }
        try:
            q = self.crack_q.q_connect()
            try:
                if hc_args['restore'] > 0:
                    job = self.q.fetch_job(job_id)
                    if job.meta['brain_check']:
                        logger.debug('Brain check previously complete')
                    elif job.meta['brain_check'] is None:
                        self.speed_check(q_args=q_args)
                        time.sleep(3)
                    else:
                        logger.debug('Restored job, disabling speed check')
                else:
                    logger.debug('Job not a restore, queuing speed_check')
                    self.speed_check(q_args=q_args)
                    time.sleep(3)
            ###***remove below now?
            except KeyError as err:
                logger.debug('Job not a restore, queuing speed_check')
                self.speed_check(q_args=q_args)
                time.sleep(3)
            self.crack_q.q_add(q, q_args, timeout=timeout)
            logger.debug('API Job {} added to queue'.format(job_id))
            logger.debug('Job Details: {}'.format(q_args))
            job = self.q.fetch_job(job_id)
            if 'task_id' in args:
                job.meta['task_id'] = args['task_id']
            job.meta['email_count'] = 0
            if 'notify' in args:
                job.meta['notify'] = args['notify']
            else:
                job.meta['notify'] = False
            if current_user.email:
                if email_check(current_user.email):
                    job.meta['email'] = str(current_user.email)
                    job.meta['last_seen'] = str(current_user.last_seen)
                elif email_check(current_user.username):
                    job.meta['email'] = current_user.username
                    job.meta['last_seen'] = str(current_user.last_seen)
            job.meta['CrackQ State'] = 'Run/Restored'
            job.meta['Speed Array'] = []
            job.save_meta()
            return job_id, 202
        except KeyError as err:
            logger.warning('Key missing from meta data:\n{}'.format(err))
            return job_id, 202
        except TypeError as err:
            logger.warning('Type error in job meta data:\n{}'.format(err))
            return job_id, 202

    @login_required
    def post(self):
        """
        Method to post a new job to the queue

        job_id: str
            hex representation of uuid job ID

        Returns
        ------
        boolean
            True/False success failure
        HTTP_status: int
            HTTP status, 201  or 500

        """
        try:
            marsh_schema = parse_json_schema().load(request.json)
            args = marsh_schema
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        try:
            job_id = args['job_id'].hex
        except KeyError:
            logger.debug('No job ID provided')
            job_id = None
        except AttributeError:
            logger.debug('No job ID provided')
            job_id = None
        enqueue_result = self.queue_job(args, job_id=job_id)
        return enqueue_result

def reporter(cracked_path, report_path, hash_path, donut_path,
             complexity_length=8, policy_check=False, admin_list=None):
    """
    Simple method to call pypal and save report (html & json)
    """
    hash_path = '{}hashes'.format(cracked_path[:-7])
    report = pypal.Report(cracked_path=cracked_path,
                          hash_path=hash_path,
                          lang='EN',
                          lists='/opt/crackq/build/pypal/src/lists/')
    if policy_check:
        policy = {
                'length': complexity_length,
                }
    else:
        policy = None
    stats = report.get_stats(match=admin_list, policy=policy)
    donut = pypal.DonutGenerator(stats)
    donut = donut.gen_donut()
    donut.savefig(donut_path, bbox_inches='tight', dpi=500)
    report_json = report.report_gen()

    with open(report_path, 'w') as fh_report:
        fh_report.write(json.dumps(report_json))
    return True


class Reports(MethodView):
    """
    Class for creating and serving HTML password analysis reports

    Calls pypal with the location of the specified crackq output
    file for a given job_id, provided auth is accepted
    """
    def __init__(self):
        self.crack_q = crackqueue.Queuer()
        self.q = self.crack_q.q_connect()
        self.report_q = self.crack_q.q_connect(queue='reports')
        rconf = CRACK_CONF['redis']
        self.redis_con = Redis(rconf['host'], rconf['port'])
        self.report_dir = CRACK_CONF['reports']['dir']
        self.log_dir = CRACK_CONF['files']['log_dir']
        self.adder = Adder()

    @login_required
    def get(self, job_id=None):
        """
        Method to get report file

        Returns
        ------
        report: file
            HTML report file generated by Pypal
        """
        try:
            marsh_schema = parse_json_schema().load(request.args)
            args = marsh_schema
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        if 'job_id' not in args:
            logger.debug('Reports queue requested')
            failed = rq.registry.FailedJobRegistry(queue=self.report_q)
            comp = rq.registry.FinishedJobRegistry(queue=self.report_q)
            started = rq.registry.StartedJobRegistry(queue=self.report_q)
            reports_dict = {}
            reports_dict.update({j: 'Generated' for j in comp.get_job_ids()})
            reports_dict.update({j: 'Failed' for j in failed.get_job_ids()})
            reports_dict.update({j: 'Running' for j in started.get_job_ids()})
            return reports_dict, 200
        else:
            job_id = str(args['job_id'].hex)
        # Check for existing session info
        logger.debug('User requesting report')
        if job_id:
            if job_id.isalnum():
                check_job = check_jobid(job_id)
                if not check_job:
                    return abort(401)
                if self.adder.session_check(self.log_dir, job_id):
                    logger.debug('Valid session found')
                    report_path = valid.val_filepath(path_string=self.report_dir,
                                                     file_string='{}.json'.format(job_id))
                    donut_path = valid.val_filepath(path_string=self.report_dir,
                                                    file_string='{}.png'.format(job_id))
                    try:
                        with report_path.open('r') as rep:
                            report = json.loads(rep.read())
                        with donut_path.open('rb') as fh_donut:
                            donut_b64 = base64.b64encode(fh_donut.read()).decode('utf-8')
                            donut = 'data:image/png;base64,{}'.format(donut_b64)
                            report['donut'] = donut
                        logger.debug(report)
                        return jsonify(report), 200
                    except IOError as err:
                        logger.debug('Error reading report: {}'.format(err))
                        return {'msg': 'No report generated for'
                                       ' this job'}, 500
                    except Exception as err:
                        logger.debug('Error reading report: {}'.format(err))
                        return {'msg': 'Error reading report'}, 500
        else:
            return jsonify(ERR_INVAL_JID), 404

    @login_required
    def post(self):
        """
        Method to trigger report generation
        """
        logger.debug('User requesting report')
        try:
            marsh_schema = parse_json_schema().load(request.json)
            args = marsh_schema
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        try:
            job_id = args['job_id'].hex
        except KeyError as err:
            logger.debug('No job ID provided')
            job_id = None
        except AttributeError as err:
            logger.debug('No job ID provided')
            job_id = None
        except TypeError as err:
            logger.debug('No job ID provided')
            job_id = None
        # Check for existing session info
        if job_id:
            self.adder = Adder()
            if job_id.isalnum():
                check_job = check_jobid(job_id)
                if not check_job:
                    return {'msg': 'Not Authorized'}, 401
                if self.adder.session_check(self.log_dir, job_id):
                    logger.debug('Valid session found')
                    cracked_path = str(valid.val_filepath(path_string=self.log_dir,
                                                          file_string='{}.cracked'.format(job_id)))
                    report_path = str(valid.val_filepath(path_string=self.report_dir,
                                                         file_string='{}.json'.format(job_id)))
                    hash_path = str(valid.val_filepath(path_string=self.log_dir,
                                                         file_string='{}.hashes'.format(job_id)))
                    donut_path = str(valid.val_filepath(path_string=self.report_dir,
                                                         file_string='{}.png'.format(job_id)))
                    job = self.q.fetch_job(job_id)
                    min_report = CRACK_CONF['misc']['min_report']
                    if job.meta['HC State']['Cracked Hashes'] < int(min_report):
                        return {'msg': 'Cracked password list too '
                                       'small for meaningful '
                                       'analysis'}, 500
                    try:
                        logger.debug('Generating report: {}'
                                     .format(cracked_path))
                        kwargs = {
                                'complexity_length': int(args['complexity_length']),
                                'admin_list': args['admin_list'],
                                'policy_check': args['policy_check'],
                                }
                        rep = self.report_q.enqueue_call(func=reporter,
                                                         job_id='{}_report'.format(job_id),
                                                         kwargs=kwargs, args=[cracked_path,
                                                                              report_path,
                                                                              hash_path,
                                                                              donut_path],
                                                         timeout=10080, result_ttl=604800)
                        if rep:
                            return {'msg': 'Successfully queued '
                                           'report generation'}, 202
                        else:
                            return {'msg': 'Error no report data '
                                           'returned'}, 500
                    except IOError:
                        logger.debug('No cracked passwords found for this job')
                        return {'msg': 'No report available for Job ID'}, 404
                    except Exception as err:
                        logger.error('Error queuing report: {}'.format(err))
                        return {'msg': 'Error queuing report'}, 500
        else:
            return jsonify(ERR_INVAL_JID), 404


class TemplatesView(MethodView):
    """Manages tasks creation and queuing"""

    def __init__(self):
        self.log_dir = CRACK_CONF['files']['log_dir']

    @login_required
    def get(self, temp_id):
        """
        List all currently registered job templates
        """
        result = []
        if temp_id:
            try:
                template = Templates.query.filter_by(id=temp_id).first()
                temp_file = valid.val_filepath(path_string='{}templates/'.format(self.log_dir),
                                               file_string='{}.json'.format(template.idi.hex))
                with temp_file.open('r') as fh_temp:
                    template = json.loads(fh_temp.read())
                    result.append(template)
            except AttributeError:
                abort(404)
            except Exception as err:
                logger.debug('Error getting job template details: {}'.format(err))
                return {'msg': 'API error fetching template details'}, 500
        else:
            try:
                for template in Templates.query.all():
                    temp_file = valid.val_filepath(path_string='{}templates/'.format(self.log_dir),
                                                   file_string='{}.json'.format(template.id.hex))
                    with temp_file.open('r') as fh_temp:
                        temp = json.loads(fh_temp.read())
                        temp_dict = {
                            'Name': template.name,
                            'ID': template.id,
                            'Details': temp
                            }
                        result.append(temp_dict)
            except AttributeError:
                abort(404)
            except Exception as err:
                logger.debug('Error getting job templates list: {}'.format(err))
                return {'msg': 'API error fetching template list'}, 500
        return jsonify(result), 200

    @login_required
    def put(self, temp_id):
        """
        Register a job template
        """
        try:
            marsh_schema = parse_json_schema().load(request.json)
            args = marsh_schema
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        result = {}
        try:
            args_needed = ['job_id', 'name']
            if all(arg in args for arg in args_needed):
                if not args['job_id']:
                    return {'msg': 'API error invalid job_id'}, 500
                template = Templates(name=args['name'])
                if not template:
                    return {'msg': 'API error generating template id'}, 500
                db.session.add(template)
                db.session.commit()
                result['template_id'] = template.id.hex
                temp_file = str(valid.val_filepath(path_string='{}templates/'.format(self.log_dir),
                                                   file_string='{}.json'.format(template.id.hex)))
                job_file = valid.val_filepath(path_string=self.log_dir,
                                              file_string='{}.json'.format(args['job_id'].hex))
                save_keys = ['attack_mode',
                             'increment',
                             'increment_max',
                             'increment_min',
                             'mask',
                             'rules',
                             'wordlist',
                             'wordlist2',
                             'timeout',
                             'stats']
                template_dict = {}
                with job_file.open('r') as fh_job_file:
                    job_dict = json.loads(fh_job_file.read())
                    job_keys = job_dict.keys()
                    for key in save_keys:
                        # temporary handling of stats field until that functionarlity is used
                        if key == 'stats':
                            template_dict[key] = []
                        elif key in job_keys:
                            template_dict[key] = job_dict[key]
                        else:
                            template_dict[key] = None
                    write_res = write_template(template_dict, temp_file)
                if not write_res:
                    db.session.delete(template)
                    db.session.commit()
                    return {'msg': 'API error creating template'}, 500
            else:
                return {'msg': 'API error valid job_id and name required'}, 500
        except AttributeError as err:
            logger.error('Error creating template: {}'.format(err))
            abort(404)
        except FileNotFoundError as err:
            logger.debug('Error creating template: {}'.format(err))
            return {'msg': 'API error creating template'}, 500
        except Exception as err:
            logger.debug('Error creating job templates list: {}'.format(err))
            return {'msg': 'API error creating template'}, 500
        return jsonify(result), 200

    @login_required
    def delete(self, temp_id):
        """
        Delete templates

        Arguments
        --------
        temp_id: uuid/None
            Template ID to delete or None to delete all
        """
        if temp_id:
            try:
                template = Templates.query.filter_by(id=temp_id).first()
                if not template:
                    logger.debug('No such template found')
                    abort(404)
                logger.debug('Deleting template: {}'.format(template.id.hex))
                temp_file = valid.val_filepath(path_string='{}templates/'.format(self.log_dir),
                                               file_string='{}.json'.format(template.id.hex))
                temp_file.unlink()
                db.session.delete(template)
                db.session.commit()
            except AttributeError as err:
                logger.debug('Error deleting template file: {}'.format(err))
                abort(404)
            except FileNotFoundError as err:
                logger.debug('Error deleting template file: {}'.format(err))
                return {'msg': 'API error deleting template file'}, 500
            except Exception as err:
                logger.debug('Error getting job template details: {}'.format(err))
                return {'msg': 'API error deleting template'}, 500
        else:
            for template in Templates.query.all():
                db.session.delete(template)
                db.session.commit()
                temp_file.unlink()
        return jsonify({'msg': 'Template deleted'}), 200


class TasksView(MethodView):
    """Manages tasks creation and queuing"""

    def __init__(self):
        self.log_dir = CRACK_CONF['files']['log_dir']
        self.crack_q = crackqueue.Queuer()
        self.q = self.crack_q.q_connect()
        rconf = CRACK_CONF['redis']
        self.redis_con = Redis(rconf['host'], rconf['port'])
        self.speed_q = Queue('speed_check', connection=self.redis_con,
                             serializer=JSONSerializer)
        self.adder = Adder()

    def add_taskid(self, task_id):
        """Add task_id to task_ids column in user table"""
        user = User.query.filter_by(username=current_user.username).first()
        if user.task_ids:
            logger.debug('Current registered task_ids: {}'.format(user.task_ids))
            tasks = json.loads(user.task_ids)
        else:
            logger.debug('No task_ids registered with current user')
            tasks = None
        logger.debug('Registering new task_id to current user: {}'.format(task_id))
        if isinstance(tasks, list):
            if task_id not in tasks:
                tasks.append(task_id)
            else:
                logger.warning('task_id already registered to user: {}'.format(task_id))
        else:
            tasks = [task_id]
        user.task_ids = json.dumps(tasks)
        db.session.commit()
        logger.debug('user.task_ids: {}'.format(user.task_ids))

    def del_taskid(self, task_id):
        """Delete task_id from task_ids column in user table"""
        with crackq.app.app_context():
            for user in User.query.all():
                if user.task_ids and task_id in user.task_ids:
                    tasks = json.loads(user.task_ids)
                    logger.debug('Registered tasks: {}'.format(tasks))
                    if isinstance(tasks, list):
                        logger.debug('Unregistering task_id: {}'.format(task_id))
                        if task_id in tasks:
                            tasks.remove(task_id)
                            user.task_ids = json.dumps(tasks)
                            db.session.commit()
                            logger.debug('user.task_ids: {}'.format((user.task_ids)))
                            return True
                    else:
                        logger.error('Error removing task_id')
                else:
                    logger.debug('Task ID not registered with user')
            return False

    @login_required
    def get(self):
        """
        List all tasks registered to user
        """
        result = []
        try:
            user = User.query.filter_by(username=current_user.username).first()
            if user.task_ids:
                logger.debug('Current registered task_ids: {}'.format(user.task_ids))
                tasks = json.loads(user.task_ids)
            else:
                logger.debug('No task_ids registered with current user')
                tasks = None
            if tasks:
                for task_id in tasks:
                    task_dict = {}
                    try:
                        task = Tasks.query.filter_by(id=task_id).first()
                        task_dict['task_id'] = task_id
                        task_dict['name'] = task.name
                        job_list = []
                        for job_id in json.loads(task.job_ids):
                            job_deets = {}
                            if session:
                                if check_jobid(job_id):
                                    job = self.q.fetch_job(job_id)
                                else:
                                    job = None
                            if job:
                                job_deets = get_jobdetails(job.description)
                                job_deets['job_id'] = job_id
                                job_list.append(job_deets)
                        task_dict['jobs'] = job_list
                        result.append(task_dict)
                    except AttributeError as err:
                        logger.debug('Task does not exist: {}'.format(err))
        except AttributeError as err:
            logger.debug('Error getting task list: {}'.format(err))
            abort(404)
        except Exception as err:
            logger.debug('Error getting task list: {}'.format(err))
            return {'msg': 'API error fetching task list'}, 500
        return jsonify(result), 200

    @login_required
    def post(self):
        """
        Create a new task
        """
        try:
            marsh_schema = parse_json_schema().load(request.json)
            args = marsh_schema
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        result = {}
        try:
            args_needed = ['jobs', 'name']
            if all(arg in args for arg in args_needed):
                if len(args['jobs']) < 1:
                    return {'msg': 'API error jobs list required'}, 500
                result_jobs = []
                result['jobs'] = result_jobs
                for job in args['jobs']:
                    job_res = self.adder.queue_job(job)
                    result_jobs.append(job_res[0])
                task = Tasks(name=args['name'],
                             job_ids=json.dumps(result_jobs))
                if not task:
                    return {'msg': 'API error generating taskid'}, 500
                db.session.add(task)
                db.session.commit()
                task_id = task.id.hex
                result['task_id'] = task_id
                self.add_taskid(task_id)
            else:
                result = {'msg': 'API error jobs list required'}, 500
        except AttributeError as err:
            logger.error('Error queuing task: {}'.format(err))
            abort(404)
        except Exception as err:
            logger.debug('Error queuing task: {}'.format(err))
            return {'msg': 'API error queuing'}, 500
        return jsonify(result), 202


class Profile(MethodView):
    """Flask User/profile management"""

    @login_required
    def get(self):
        """
        View user profile
        """
        result = {}
        try:
            result['user'] = current_user.username
            result['admin'] = current_user.is_admin
            result['email'] = current_user.email
        except AttributeError:
            abort(404)
        return jsonify(result), 200

    @login_required
    def post(self):
        """
        Update current user profile

        Arguments
        ---------
        password: string
            Current Password
        new_password: string
            New Password
        confirm_password: string
            New Password
        email: string
            Email address

        Returns
        -------
        result: JSON
            message, HTTP code
        """
        try:
            marsh_schema = parse_json_schema().load(request.json)
            args = marsh_schema
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        logger.debug('Updating user details')
        user = User.query.filter_by(id=current_user.id).first()
        ret = []
        if isinstance(user, User) and 'password' in args:
            if args['password']:
                if 'new_password' in args and 'confirm_password' in args:
                    if args['confirm_password'] and args['new_password']:
                        if args['new_password'] != args['confirm_password']:
                            return {'msg': 'Passwords do not match'}, 400
                        if bcrypt.check_password_hash(user.password, args['password']):
                            pass_hash = bcrypt.generate_password_hash(args['new_password'])
                            user.password = pass_hash.decode('utf-8')
                            logger.debug('Updating password')
                            ret.append({'msg': 'Password updated'})
                            crackq.app.session_interface.regenerate(session)
                        else:
                            return {'msg': 'Invalid Password'}, 401
                if 'email' in args:
                    if args['email'] and email_check(args['email']):
                        if bcrypt.check_password_hash(user.password, args['password']):
                            user.email = args['email']
                            logger.debug('Updating email')
                            ret.append({'msg': 'Email updated'})
                        else:
                            return {'msg': 'Invalid Password'}, 401
                    #else:
                    #    return {'msg': 'Invalid Email'}, 500
            if ret:
                db.session.commit()
                return jsonify(ret), 200
        return {'msg': 'Invalid Request'}, 500


class Admin(MethodView):
    """Flask Admin and user management"""
    @admin_required
    @login_required
    def get(self, user_id):
        """
        View list of users or details of a single user

        Arguments
        ---------
        user_id: uuid/None
            User's ID to view details (if None show all)
        """
        if user_id:
            result = {}
            try:
                user = User.query.filter_by(id=user_id).first()
                result['user_id'] = str(user.id)
                result['user'] = user.username
                result['admin'] = user.is_admin
                result['email'] = user.email
            except AttributeError:
                abort(404)
        else:
            result = []
            users = User.query.all()
            for user in users:
                entry = {}
                entry['user_id'] = str(user.id)
                entry['user'] = user.username
                entry['admin'] = user.is_admin
                entry['email'] = user.email
                result.append(entry)
        return jsonify(result), 200

    @admin_required
    @login_required
    def post(self):
        """
        Creates a new user

        Arguments
        ---------
        user: string
            Username to create
        password: string
            Password
        email: string
            Email address

        Returns
        -------
        result: tuple
            message, HTTP code
        """
        try:
            marsh_schema = parse_json_schema().load(request.json)
            args = marsh_schema
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        args_needed = ['password', 'confirm_password', 'user']
        if all(arg in args for arg in args_needed):
            if args['password'] != args['confirm_password']:
                return {'msg': 'Passwords do not match'}, 400
            logger.debug('Creating User: {}'.format(args['user']))
            pass_hash = bcrypt.generate_password_hash(args['password']).decode('utf-8')
            email = args['email'] if args['email'] else None
            create_user(username=args['user'],
                        password=pass_hash, email=email)
            return {'msg': 'User created'}, 200
        return {'msg': 'Error'}, 500

    @admin_required
    @login_required
    def delete(self, user_id):
        """
        Deletes a user account

        Arguments
        ---------
        user: string
            Username to make admin

        Returns
        -------
        result: boolean
            Function success or failure

        """
        if del_user(user_id):
            return {'msg': 'User deleted'}, 200
        abort(404)

    @admin_required
    @login_required
    def put(self, user_id):
        """
        Toggle admin privs for selected user

        Arguments
        ---------
        user_id: 1
            User ID to make admin

        Returns
        -------
        result: boolean
            Function success or failure
        """
        user = User.query.filter_by(id=user_id).first()
        if isinstance(user, User):
            user.is_admin = not user.is_admin
            db.session.commit()
            return 'OK', 200
        return 404

    @admin_required
    @login_required
    def patch(self, user_id):
        """
        Update selected user profile

        Arguments
        ---------
        new_password: string
            New Password
        confirm_password: string
            New Password
        email: string
            Email address

        Returns
        -------
        result: JSON
            message, HTTP code
        """
        try:
            marsh_schema = parse_json_schema().load(request.json)
            args = marsh_schema
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        logger.debug('Updating user details')
        user = User.query.filter_by(id=user_id).first()
        if isinstance(user, User):
            ret = []
            if 'email' in args:
                if email_check(args['email']):
                    logger.debug('Adding email address: {}'.format(args['email']))
                    user.email = args['email']
                    ret.append({'msg': 'Email updated'})
            if 'new_password' in args and 'confirm_password' in args:
                if args['confirm_password'] and args['new_password']:
                    if args['new_password'] != args['confirm_password']:
                        return {'msg': 'Passwords do not match'}, 400
                    pass_hash = bcrypt.generate_password_hash(args['new_password']).decode('utf-8')
                    user.password = pass_hash
                    ret.append({'msg': 'Password updated'})
            if ret:
                db.session.commit()
                ###***logout any sessions belonging user here
                return jsonify(ret), 200
            return {'msg': 'Nothing to update'}, 200
        return {'msg': 'Error'}, 500


class Benchmark(MethodView):
    """Run and display Hashcat Benchmarks"""

    def __init__(self):
        self.log_dir = CRACK_CONF['files']['log_dir']
        self.bench_file = valid.val_filepath(path_string=self.log_dir,
                                             file_string='sys_benchmark.json')
        self.crack_q = crackqueue.Queuer()
        self.q = self.crack_q.q_connect()

    @login_required
    def get(self):
        """
        View benchmark data
        """
        result = {}
        try:
            with open(self.bench_file, 'rb') as bench_fh:
                result = json.loads(bench_fh.read())
        except IOError as err:
            logger.error('Unable to open benchmark file: {}'.format(err))
            abort(404)
        except Exception as err:
            logger.error('Benchmark read erorr: {}'.format(err))
        return jsonify(result), 200

    @login_required
    def post(self, benchmark_all=False):
        """
        Run benchmark

        Arguments
        ---------
        benchmark_all: boolean
            Run full benchmark (--benchmark-all)

        Returns
        -------
        result: JSON
            Message, HTTP code
        """
        try:
            marsh_schema = parse_json_schema().load(request.json)
            args = marsh_schema
        except ValidationError as errors:
            logger.debug('Validation error: {}'.format(errors))
            return errors.messages, 500
        logger.debug('Queuing benchmark job')
        job_id = uuid.uuid4().hex
        add_jobid(job_id)
        q = self.crack_q.q_connect()
        hc_args = {}
        if 'benchmark_all' in args:
            hc_args['benchmark_all'] = args['benchmark_all']
        hc_args['benchmark'] = True
        hc_args['name'] = 'Benchmark'
        hc_args['session'] = job_id
        try:
            q_args = {
                'job_id': job_id,
                'kwargs': hc_args,
                }
            self.crack_q.q_add(q, q_args)
            logger.debug('API Job {} added to queue'.format(job_id))
            logger.debug('Job Details: {}'.format(q_args))
            job = self.q.fetch_job(job_id)
            job.meta['email_count'] = 0
            job.meta['notify'] = True
            if current_user.email:
                if email_check(current_user.email):
                    job.meta['email'] = str(current_user.email)
                    job.meta['last_seen'] = str(current_user.last_seen)
                elif email_check(current_user.username):
                    job.meta['email'] = current_user.username
                    job.meta['last_seen'] = str(current_user.last_seen)
            job.meta['CrackQ State'] = 'Run/Restored'
            job.meta['Speed Array'] = []
            job.save_meta()
            return job_id, 202
        except Exception as err:
            logger.error('Error running benchmark: {}'.format(err))
        return {'msg': 'Invalid Request'}, 500
