from crackq import cq_api, crackqueue
import json
import logging
import rq
import crackq.run_hashcat
import sys
import time
import uuid

from logging.config import fileConfig
from redis import Redis
from rq import use_connection, Queue
from rq.registry import StartedJobRegistry

#Setup logging
fileConfig('log_config.ini')
logger = logging.getLogger()

CRACK_CONF = crackq.conf.hc_conf()

crack_q = crackqueue.Queuer()
crack = crackq.run_hashcat.Crack()
rconf = CRACK_CONF['redis']
redis_con = Redis(rconf['host'], rconf['port'])
                               # password=rconf['password'])
q = crack_q.q_connect()
#redis_con = Redis()
log_dir = '/var/crackq/logs/'



def test_wl():
    job_id = '0b7b91482fc24274b7d04fc0d6e61a96'
    hash_file = '/opt/crackq/build/crackq/crackq/crackq/tests/deadbeef.hashes'
    outfile = job_id + '.cracked'
    hc_args = {
        'crack': crack,
        'hash_mode': 1000,
        'hash_file': hash_file,
        'session': job_id,
        'wordlist': '/opt/crackq/build/crackq/tests/rockyou50k.txt',
        'rules': ['/opt/crackq/build/crackq/tests/d3ad0ne.rule'],
        'attack_mode': 0,
        'outfile': outfile,
        }
    q_args = {
        'func': crack.hc_worker,
        'job_id': job_id,
        'kwargs': hc_args,
        }
    crack_q.q_add(q, q_args)
    started_list = rq.registry.StartedJobRegistry('default',
                                                  connection=redis_con).get_job_ids()
    print(started_list)





if __name__ == '__main__':
    test_wl()
#    TestQ.test_bf()
#    TestQ.test_stop('restoretest_bf')

    #restore_write(restore_file, '0')
    #restore = restore_read(restore_file)
    #logger.debug('Hashcat restore point: {:s}'.format(restore))


    #crack_q.add(job)
    #cur_q = crack_q.checker()
    #print(cur_q)

