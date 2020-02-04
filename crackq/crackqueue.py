import logging
import rq
#import crackq.run_hashcat
import sys
import time
import uuid

from crackq import run_hashcat, cq_api
from crackq.conf import hc_conf
from logging.config import fileConfig
from redis import Redis
from rq import use_connection, Queue
from rq.registry import StartedJobRegistry

# Setup logging
fileConfig('log_config.ini')
logger = logging.getLogger()

CRACK_CONF = hc_conf()


class Queuer(object):
    """
    Queue handler class used to build and manage a queue of hashcat jobs
    """
    ###***move all of this class to api.py?
    def __init__(self):
        rconf = CRACK_CONF['redis']
        self.redis_con = Redis(rconf['host'], rconf['port'])
        # password=rconf['password'])
        #self.redis_con = Redis()

    def q_add(self, q_obj, arg_dict):
        """
        This method adds a new crack job to the queue

        Parameters
        ---------
        job_id: str
                uuid string corresponding to job ID
        q_obj: object
                queue object to use (returned from q_connect)
        q_post: int?
        new position for job in queue

        Returns
        -------
        boolean
            Success or failure
        """
        logger.info('Adding task to job queue: '
                    '{:s}'.format(arg_dict['job_id']))
        q_obj.enqueue_call(func=arg_dict['func'], job_id=arg_dict['job_id'],
                           kwargs=arg_dict['kwargs'], ttl=-1, timeout=1209600,
                           result_ttl=-1)
        return

    def q_monitor(self, q_obj, *kwargs):
        """
        Method to monitor jobs in queue

        Query the queue and return the results of all jobs..

        Parameters
        ---------
        job_id: str
                uuid string corresponding to job ID (optional)
                if not provided this will return data for all jobs
        q_obj: object
                queue object to use (returned from q_connect)

        Returns
        -------
        qstate_dict: dictionary
                dictionary containing job details and hashcat status
        """
        jobstate_dict = {job.id: self.q_jobstate(q_obj, job) for job in
                         q_obj.jobs}
        #print('jobstate')
        #print(jobstate_dict)
        cur_jobs = StartedJobRegistry('default',
                                      connection=self.redis_con).get_job_ids()
        #print(cur_jobs)
        cur_job_dict = {job: self.q_jobstate(q_obj,
                                             q_obj.fetch_job(job)) for job in cur_jobs}
        qstate_dict = {
                       'Queue Size': q_obj.count,
                       'Queued Jobs': jobstate_dict,
                       'Current Job': cur_job_dict,
                      }
        return qstate_dict

    def q_jobstate(self, q_obj, job, hcat_obj=None):
        """
        Method to pull info for specified job

        Parameters
        ---------
        job_id: str
                uuid string corresponding to job ID
        q_obj: object
                queue object to use (returned from q_connect)

        Returns
        -------
        job_dict: dictionary
            dictionary containing job stats and meta data
        """
        #status_dict = 'None'
        job_dict = {
                    'Status': job.get_status(),
                    'Time started': str(job.started_at),
                    'Time finished': str(job.ended_at),
                    #'State': status_dict,
                    'Result': job.result,
                    #'Description': job.description,
                    'State': job.meta,
                   }
        return job_dict

    def q_connect(self, queue='default'):
        """
        Method to setup redis connection

        Parameters
        ----------
        redis_conn : str
            redis connection url/string
        queue: str
            queue to connect to. default is 'default'

        Returns
        -------
        object
            redis connection object
        """
        #redis_con = Redis()
        # use default queue for now
        rqueue = Queue(queue, connection=self.redis_con)
        return rqueue

    def check_failed(self):
        """
        This method checks the failed queue and print info to a log file

        Parameters
        ---------
        log_file : str
            log file name to write to

        Returns
        -------
        success : boolean
        """
        ###***finish this
        try:
            failed_dict = {}
            failed_reg = rq.registry.FailedJobRegistry('default',
                                                       connection=self.redis_con)
            if failed_reg.count > 0:
                q = failed_reg.get_queue()
                for job in failed_reg.get_job_ids():
                    failed_dict[job] = {}
                    j = q.fetch_job(job)
                    ###***make this better, use some other method for splitting
                    if j is not None:
                        err_split = j.exc_info.split('\n')
                        logger.debug('Failed job {}: {}'.format(job, j.exc_info))
                        if 'Traceback' in err_split[0]:
                            failed_dict[job]['Error'] = j.exc_info.split(':')[-1].strip()
                        else:
                            failed_dict[job]['Error'] = err_split[0]
                        try:
                            failed_dict[job]['Name'] = cq_api.get_jobdetails(j.description)['name']
                        except KeyError:
                            failed_dict[job]['Name'] = 'No name'
                        except AttributeError:
                            failed_dict[job]['Name'] = 'No name'
            logger.debug('Failed dict: {}'.format(failed_dict))
            return failed_dict
        except AttributeError as err:
            logger.warning('Error getting failed queue: {}'.format(err))
            return {}

    def check_complete(self):
        """
        This method checks the completed queue and print info to a log file

        Parameters
        ---------

        Returns
        -------
        comp_list: rq.registry
            Finished job registry
        """
        comp_list = rq.registry.FinishedJobRegistry('default',
                                                    connection=self.redis_con).get_job_ids()
        return comp_list


if __name__ == '__main__':
    crack_q = Queuer()
    crack = run_hashcat.Crack()
    job_id = uuid.uuid4().hex 
    #hash_file = job_id + '.hashes'
    hash_file = 'deadbeef.hashes'
    outfile = job_id + '.cracked'
    hc_args = {
             'crack': crack,
             'hash_file': hash_file,
             'session': job_id,
             'wordlist': '/home/dan/tw_leaks.txt',
             'attack_mode': '0',
             'outfile': outfile,
             }
    q_args = {
            'func': crack.hc_worker,
            'job_id': job_id,
            'kwargs': hc_args,
            }
    wordlist = hc_args['wordlist']
    q = crack_q.q_connect()
    #print(q_args)
    #print(q)
    crack_q.q_add(q, q_args)
    #print(dir(q))
    #redis_con = Redis()
    #print(dir(redis_con))
    #qee = Queue(connection=redis_con) 
    job_id = uuid.uuid4().hex 
    hc_args = {
             'crack': crack,
             'hash_file': hash_file,
             'session': job_id,
             'outfile': outfile,
             'attack_mode': '3',
             'mask': '?a?a?a?a?a?a?a',
             }
    q_args = {
            'func': crack.hc_worker,
            'job_id': job_id,
            'kwargs': hc_args,
            }
    crack_q.q_add(q, q_args)
    try:
        while True:
            time.sleep(10)
            #print('started:')
            #print(rq.registry.StartedJobRegistry('default',
            #      connection=redis_con).get_job_ids())
            print('monitor')
            print(crack_q.q_monitor(q))
            #print(crack_q.check_failed())
    except KeyboardInterrupt:
        print('User exit')
        exit(0)

    #restore_write(restore_file, '0')
    #restore = restore_read(restore_file)
    #logger.debug('Hashcat restore point: {:s}'.format(restore))


    #crack_q.add(job)
