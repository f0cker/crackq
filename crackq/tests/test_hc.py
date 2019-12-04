from crackq import run_hashcat
from time import sleep
import uuid

job_id = uuid.uuid4().hex
hash_file = '/opt/crackq/build/crackq/crackq/tests/deadbeef.hashes'
outfile = '/tmp/' + job_id + '.cracked'
crack = run_hashcat.Crack()
hc_args = {
    #'crack': crack,
    'hash_mode': 1000,
    'hash_file': hash_file,
    'session': job_id,
    'wordlist': '/opt/crackq/build/crackq/tests/rockyou50k.txt',
    'rules': ['/opt/crackq/build/crackq/tests/d3ad0ne.rule'],
    'attack_mode': 0,
    'outfile': outfile,
    }


#hcat = crack.hc_worker(**hc_args)
hcat = crack.runner(**hc_args)
try:
    crack.cracked_callback(hcat)
    while True:
        hc_state = hcat.status_get_status_string()
        sleep(10)
        # added manual status update as callback doesn't get triggere
        # in some cases, see issue #1
        #self.cracked_callback(hcat)
        #if hc_state == 'ANY':
        #crack.cracked_callback(hcat)

except KeyboardInterrupt:
    hcat.hashcat_session_quit()
    exit(0)

"""
hc_args = {
         'crack': crack,
         'hash_mode': 1000,
         'hash_file': hash_file,
         'session': job_id,
         'outfile': outfile,
         'attack_mode': 3,
         'mask': '?a?a?a?a?a?a?a',
         }
q_args = {
        'func': crack.hc_worker,
        'job_id': job_id,
        'kwargs': hc_args,
        }
"""
