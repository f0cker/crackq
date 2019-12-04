from flask import Flask, jsonify, request
import ldap
from getpass import getpass
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

app = Flask(__name__)

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'dhsnu3r2788hsnjGDhbjfdio190243ifnchDGhjsdkfdasfhj3jhbhj$53f2q4b3hjb'  # Change this!
jwt = JWTManager(app)
#ldap_uri = 'ldaps://127.0.0.1'
ldap_uri = 'ldap://ldap.crackq.org'

# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.route('/login', methods=['POST', 'GET'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    ###***validate
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return json.dumps({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    auth = authenticate(ldap_uri, username, password)
    if auth is "Success":
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    elif auth is "Invalid Credentials":
        return jsonify({"msg": "Bad username or password"}), 401
    else:
        return jsonify({"msg": "Bad username or password", "error": auth}), 401

    # Identity can be any data that is json serializable
    ###•••change identity, username is probably not good
    #access_token = create_access_token(identity=username)
    #return jsonify(access_token=access_token), 200

"""
@app.route('/logout', methods=['POST'])
@jwt_required
def logout():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    ###***validate
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return json.dumps({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    auth = authenticate(ldap_uri, username, password)
    if auth is "Success":
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    elif auth is "Invalid Credentials":
        return jsonify({"msg": "Bad username or password"}), 401
    else:
        return jsonify({"msg": "Bad username or password", "error": auth}), 401
"""

# Protect a view with jwt_required, which requires a valid access token
# in the request to access.
@app.route('/queuing/all', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200



def authenticate(uri, username, password):
    try:
        username = ldap.dn.escape_dn_chars(username)
        password = ldap.dn.escape_dn_chars(password)
        conn = ldap.initialize(uri)
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.protocol_version = 3
        ###***duplication ehre, review
        #conn.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
        #conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        #conn.set_option(ldap.OPT_X_TLS_DEMAND, True )
        conn.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        #conn.start_tls_s()
        bind = conn.simple_bind_s("cn={},dc=example,dc=org".format(username), password)
        print(bind)
        conn.unbind_s()
        ###***check this is ok
        return "Success" if 97 in bind else "Failed"
    except ldap.INVALID_CREDENTIALS:
        return "Invalid Credentials"
    except ldap.SERVER_DOWN:
        return "Server down"
    except ldap.LDAPError as err:
        return "Other LDAP error: {}".format(err)
    return "Error" 

if __name__ == '__main__':
    app.run('192.168.0.59', port=5000, debug=True)
