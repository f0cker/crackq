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



def test_init_check():
    """Check the queue is empty first"""
    cur_list = rq.registry.StartedJobRegistry('default',
                                              connection=redis_con).get_job_ids()
    if len(cur_list) > 0:
        try:
            job_id = cur_list[0]
            print(cur_list)
            logger.info('Deleting job: {:s}'.format(job_id))
            job = q.fetch_job(job_id)
            job.meta['CrackQ State'] = 'Stop'
            job.save_meta()
            time.sleep(5)
            counter = 0
            while len(cur_list) > 0 and counter < 9:
                cur_list = rq.registry.StartedJobRegistry('default',
                                                          connection=redis_con).get_job_ids()
                time.sleep(5)
                counter += 2
            print(cur_list)
            job.delete()
            time.sleep(11)
            comp_list = crack_q.check_complete()
            assert job_id not in comp_list
            assert len(cur_list) < 1
        except AttributeError as err:
            logger.error('Failed to delete job: {}'.format(err))
    assert len(cur_list) < 1


def test_bf():
    job_id = '63ece9904eb8478896baf3300a2c9513'
    hash_file = 'tests/deadbeef.hashes'
    outfile = job_id + '.cracked'
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
    crack_q.q_add(q, q_args)
    time.sleep(20)
    started_list = rq.registry.StartedJobRegistry('default',
                                                  connection=redis_con).get_job_ids()
    assert job_id in started_list


def test_stop():
    job_id = '63ece9904eb8478896baf3300a2c9513'
    try:
        logger.info('Stopping job: {:s}'.format(job_id))
        job = q.fetch_job(job_id)
        started = rq.registry.StartedJobRegistry('default',
                                                 connection=redis_con)
        cur_list = started.get_job_ids()
        wait_counter = 0
        if job_id in cur_list:
            job.meta['CrackQ State'] = 'Stop'
            job.save_meta()
        time.sleep(20)
        while wait_counter < 5 and not cur_list:
            time.sleep(15)
            cur_list = started.get_job_ids()
            wait_counter += 1
            if len(cur_list) > 0:
                assert job_id not in cur_list
        #assert job_id not in cur_list
    except AttributeError as err:
        logger.error('Failed to stop job: {}'.format(err))


def test_del():
    job_id = '63ece9904eb8478896baf3300a2c9513'
    try:
        logger.info('Deleting job: {:s}'.format(job_id))
        job = q.fetch_job(job_id)
        started = rq.registry.StartedJobRegistry('default',
                                                 connection=redis_con)
        cur_list = started.get_job_ids()
        if job_id in cur_list:
            job.meta['CrackQ State'] = 'Stop'
            job.save_meta()
            time.sleep(10)
        cur_list = started.get_job_ids()
        assert job_id not in cur_list
        job.delete()
        time.sleep(2)
        comp_list = crack_q.check_complete()
        assert job_id not in comp_list
    except AttributeError as err:
        logger.error('Failed to delete job: {}'.format(err))


def test_wl():
    job_id = '0b7b91482fc24274b7d04fc0d6e61a96'
    hash_file = 'tests/deadbeef.hashes'
    outfile = job_id + '.cracked'
    hc_args = {
        'crack': crack,
        'hash_mode': 1000,
        'hash_file': hash_file,
        'session': job_id,
        'wordlist': 'tests/rockyou50k.txt',
        'rules': ['tests/d3ad0ne.rule'],
        'attack_mode': 0,
        'outfile': outfile,
        }
    q_args = {
        'func': crack.hc_worker,
        'job_id': job_id,
        'kwargs': hc_args,
        }
    crack_q.q_add(q, q_args)
    time.sleep(15)
    started_list = rq.registry.StartedJobRegistry('default',
                                                  connection=redis_con).get_job_ids()
    print(started_list)
    assert job_id in started_list


def test_stop_wl():
    job_id = '0b7b91482fc24274b7d04fc0d6e61a96'
    try:
        logger.info('Stopping job: {:s}'.format(job_id))
        job = q.fetch_job(job_id)
        started = rq.registry.StartedJobRegistry('default',
                                                 connection=redis_con)
        cur_list = started.get_job_ids()
        if job_id in cur_list:
            job.meta['CrackQ State'] = 'Stop'
            job.save_meta()
        wait_counter = 0
        while wait_counter < 5:
            time.sleep(15)
            cur_list = started.get_job_ids()
            wait_counter += 1
        cur_list = started.get_job_ids()
        assert job_id not in cur_list
    except AttributeError as err:
        logger.error('Failed to stop job: {}'.format(err))

def test_restore():
    log_dir = '/var/crackq/logs/'
    job_id = '0b7b91482fc24274b7d04fc0d6e61a96'
    # check job id is sane
    if job_id.isalnum():
        if crackq.cq_api.Adder().session_check(log_dir, job_id):
            print('Valid session found')
            restore = crackq.cq_api.Adder().get_restore(log_dir, job_id)
    else:
        print('Invalid Job ID')
    print('Attempting restore, please wait')
    try:
        outfile = '{}{}.cracked'.format(log_dir, job_id)
        hash_file = '{}{}.hashes'.format(log_dir, job_id)
        pot_path = '{}crackq.pot'.format(log_dir)
        job_deets = crackq.cq_api.Adder().get_restore(log_dir, job_id)
        assert job_deets != 0
        hc_args = {
            'crack': crack,
            'hash_file': hash_file,
            'session': job_id,
            'wordlist': job_deets['wordlist'],
            'mask': job_deets['mask'],
            'attack_mode': int(job_deets['attack_mode']),
            'hash_mode': int(job_deets['hash_mode']),
            'outfile': outfile,
            'rules': job_deets['rules'],
            'restore': job_deets['restore'],
            'username': job_deets['username'],
            'name': job_deets['name'],
            'pot_path': pot_path,
            }
        job = q.fetch_job(job_id)
        job.meta['CrackQ State'] = 'Run/Restored'
        job.save_meta()
        hcat = crack.hc_worker(hc_args)
        #hcat = crack.hc_worker(crack=crack, hash_file=hash_file,
        #E                       session=job_id, wordlist=wordlist, restore=restore,
        #E                       outfile=outfile, attack_mode=0, hash_mode=1000)
        started = rq.registry.StartedJobRegistry('default',
                                                 connection=redis_con)
        time.sleep(7)
        cur_list = started.get_job_ids()
        print(cur_list)
        assert job_id in cur_list
        print(dir(hcat))

    except:
        print('exception')

def test_stop_wl():
    job_id = '0b7b91482fc24274b7d04fc0d6e61a96'
    try:
        logger.info('Stopping job: {:s}'.format(job_id))
        job = q.fetch_job(job_id)
        started = rq.registry.StartedJobRegistry('default',
                                                 connection=redis_con)
        cur_list = started.get_job_ids()
        if job_id in cur_list:
            job.meta['CrackQ State'] = 'Stop'
            job.save_meta()
        wait_counter = 0
        while wait_counter < 5:
            time.sleep(15)
            cur_list = started.get_job_ids()
            wait_counter += 1
        cur_list = started.get_job_ids()
        assert job_id not in cur_list
    except AttributeError as err:
        logger.error('Failed to stop job: {}'.format(err))

def test_wl_del():
    job_id = '0b7b91482fc24274b7d04fc0d6e61a96'
    try:
        logger.info('Deleting job: {:s}'.format(job_id))
        job = q.fetch_job(job_id)
        started = rq.registry.StartedJobRegistry('default',
                                                 connection=redis_con)
        cur_list = started.get_job_ids()
        if job_id in cur_list:
            job.meta['CrackQ State'] = 'Stop'
            job.save_meta()
            time.sleep(16)
        cur_list = started.get_job_ids()
        assert job_id not in cur_list
        job.delete()
        time.sleep(10)
        comp_list = crack_q.check_complete()
        assert job_id not in comp_list
    except AttributeError as err:
        logger.error('Failed to delete job: {}'.format(err))

if __name__ == '__main__':
    test_bf()
    test_stop()
    test_del()
    test_wl()
    test_wl_del()
    test_stop_wl()
#    TestQ.test_bf()
#    TestQ.test_stop('restoretest_bf')

    #restore_write(restore_file, '0')
    #restore = restore_read(restore_file)
    #logger.debug('Hashcat restore point: {:s}'.format(restore))


    #crack_q.add(job)
    #cur_q = crack_q.checker()
    #print(cur_q)

