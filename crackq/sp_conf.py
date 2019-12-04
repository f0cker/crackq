from crackq.conf import hc_conf
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
NAME_FORMAT_URI = 'None'

CRACK_CONF = hc_conf()
BASE = CRACK_CONF['auth']['entity_id']
KEY = CRACK_CONF['auth']['sp_key_file']
CERT = CRACK_CONF['auth']['sp_cert_file']


CONFIG = {
    "entityid": BASE,
    "name": "CrackQ",
    "description": "CrackQ",
    "service": {
        "sp": {
            "endpoints": {
                "assertion_consumer_service": [(BASE + "/api/sso",
                                            BINDING_HTTP_POST)],
                "single_logout_service": [(BASE + "/api/logout",
                                            BINDING_HTTP_REDIRECT)],
            },
            "required_attributes": ["surname", "givenname",
                                    "name", "group"],
        }
    },
    "debug": 1,
    "key_file": KEY,
    "cert_file": CERT,
    "organization": {
        "name": "CrackQ",
        "display_name": [("CrackQ")],
        "url": BASE,
    },
    #"xmlsec_binary":"/opt/local/bin/xmlsec1",
    "logger": {
        "rotating": {
            "filename": "/var/crackq/logs/sp.log",
            "maxBytes": 100000,
            "backupCount": 5,
        },
        "loglevel": "debug",
    }
}
