#!/usr/bin/env python
from crackq import crackqueue, hash_modes, cq_api
import logging
import json
import os
import time
#import uuid

from crackq.conf import hc_conf
from pathlib import Path
from time import sleep
from logging.config import fileConfig
from pyhashcat import Hashcat
from redis import Redis
from rq import use_connection, Queue

# set perms
os.umask(0o077)

# Setup logging
fileConfig('log_config.ini')
logger = logging.getLogger()

CRACK_CONF = hc_conf()


class Crack(object):
    """
        Class to interface with libhashcat through pyhashcat
    """
    def __init__(self):
        self.log_dir = CRACK_CONF['files']['log_dir']
        self.rconf = CRACK_CONF['redis']
        #self.redis_con = Redis(self.rconf['host'], self.rconf['port'])
        #self.redis_q = Queue(connection=self.redis_con)

    def status(self, sender):
        status_data = sender.hashcat_status_get_status()
        if status_data == -1:
            status_data = 'Waiting'
        #status_data['Requeue Count'] = 0
        return status_data

    def runner(self, hash_file=None, hash_mode=1000,
               attack_mode=0, rules=None,
               mask=None, wordlist=None, session=None,
               outfile=None, restore=None, username=False,
               pot_path=None, show=False, brain=True):
        logger.info('Running hashcat')
        hc = Hashcat()
        logger.debug('Hashcat object ID: {}'.format(id(hc)))
        hc.potfile_disable = False
        hc.restore_disable = True
        hc.show = show
        if pot_path:
            hc.potfile_path = pot_path
        hc.quiet = False
        hc.session = session
        hc.brain_client = brain
        hc.brain_client_features = 3
        hc.optimized_kernel_enable = True
        hc.workload_profile = 4
        ###***replace with random string
        hc.brain_password = '425dafbb8e87fe18'
        if username is True:
            hc.username = True
        #hc.remove = True
        #hc.remove_timer = 20
        ###*** update this to config file path and try/except
        hc.markov_hcstat2 = "/var/crackq/files/crackq.hcstat"
        hc.custom_charset_1 = '?l?d'
        hc.custom_charset_2 = '?l?d?u'
        hc.custom_charset_3 = '?l?d?s'
        hc.hash = hash_file
        hc.attack_mode = attack_mode
        if rules:
            hc.rules = rules
            hc.rp_files_cnt = len(rules)
        hc.hash_mode = hash_mode
        if wordlist:
            hc.dict1 = wordlist
        if mask:
            hc.mask = mask
        hc.outfile = outfile
        logger.debug('HC. Hashcat Rules: {}'.format(hc.rules))
        logger.debug('HC. Hashcat rp_files_cnt: {}'.format(hc.rp_files_cnt))

        if restore:
            hc.skip = int(restore)
        hc.hashcat_session_execute()
        return hc

    def cracked_callback(self, sender):
        """
        Callback function to take action on hashcat signal.
        Action is to write the latest cracked hashes
        """
        ###***rename this method
        logger.debug('Callback Triggered: Cracked')
        status_dict = self.status(sender)
        logger.debug('Hashcat status: {}'.format(status_dict))
        if isinstance(status_dict, dict):
            self.write_result(status_dict)
        else:
            self.write_result('Hashcat: {}'.format(status_dict))

    def finished_callback(self, sender):
        """
        Callback function to take action on hashcat finished signal.
        Action is to reset hashcat???
        #changed to just writing restul file for now
        """
        logger.debug('Callback Triggered: Cracking Finished')
        status_dict = self.status(sender)
        logger.debug(status_dict)
        self.write_result(status_dict)
        #self.set_rq_state(sender.session, 'finished')
        #time.sleep(6)
        #sender.reset()

    ###***remove this??
    def set_rq_state(self, job_id, value):
        """
        Method to set state of rq job

        Used to notify/update rq job when hashcat finished or the runner
        function will never return and leave the job hanging

        """
        logger.debug('Updating job state')
        redis_con = Redis(self.rconf['host'], self.rconf['port'])
        redis_q = Queue(connection=redis_con)
        job = redis_q.fetch_job(job_id)
        job.set_status(value)
        try:
            job.is_finished = True
        except AttributeError as err:
            logger.debug('Redis job state update failed: {}'.format(err))

    def circulator(self, circList, entry, limit):
        """
        This method will wrap a list overwriting at the 
        beginning when limit is reached.

        Args
        ----
        circList: list
            initial list
        entry: any
            item to add to list
        limit: int
            size limit for circular list

        Returns
        -------
        circList: list
            updated list
        """
        circList.append(entry)
        if len(circList) > limit:
            circList.pop(0)
        return circList

    def write_result(self, hcat_status):
        """
        Method to write cracking results to file in json format

        When executed, this will open the corresponding session.crack file and
        load the data into a results file with other meta data relating to the 
        job

        Arguments
        ---------
        hcat_status: dict 
            Hashcat status dict (from self.status()), containing hashcat data
            form the cracking session
        redis_con: object
            redis connection object initiated  ***by
        Returns
        -------


        """
        ###***ADD PATH VALIDATION??
        ###***refactor to remove file use
        ###**fix meta data shitness
        if 'Waiting' in hcat_status:
            hcat_status = {'HC State': 'Loading'}
            logger.warning('Status update failure')
            return
        elif 'Progress' in hcat_status:
            hcat_status['Progress'] = int(hcat_status['Progress'])
        logger.debug('Updating job metadata')
        redis_con = Redis(self.rconf['host'], self.rconf['port'])
        redis_q = Queue(connection=redis_con)
        logger.debug('Creating results file')
        cracked_file = '{}{}.cracked'.format(self.log_dir, hcat_status['Session'])
        result_file = '{}{}.json'.format(self.log_dir, hcat_status['Session'])
        try:
            with open(cracked_file, 'r') as cracked_fh:
                cracked_list = [cracked.rstrip() for cracked in cracked_fh]
            hcat_status['Cracked'] = cracked_list
        except IOError as err:
            logger.debug('Cracked file does not exist: {}'.format(err))
        with open(result_file, 'w') as result_fh:
            #result_fh.write(json.dumps(hcat_status))
            try:
                job = redis_q.fetch_job(hcat_status['Session'])
                job.meta['HC State'] = hcat_status
                job.meta['Speed Array'] = self.circulator(job.meta['Speed Array'], int(hcat_status['Speed Raw']), 180)
                job.save_meta()
                job_details = cq_api.get_jobdetails(job.description)
                job_details['restore'] = hcat_status['Restore Point']
                job_details = json.dumps(job_details)
                result_fh.write(job_details)
            except AttributeError as err:
                logger.warning('Status update failure: {}'.format(err))

    def hc_worker(self, crack=None, hash_file=None, session=None,
                  wordlist=None, outfile=None, hash_mode=1000,
                  attack_mode=None, mask=None, rules=None, name=None,
                  username=False, pot_path=None, restore=None,
                  brain=True, mask_file=False):
        """
        Method to load a rq worker to take jobs from redis queue for execution

        ###***finish this
        Arguments
        ---------
        crack: object
            Hashcat execution python object for rq to execute
        hash_file: string
            File containing hashes to feed to hashcat
        session: Hashcat session
        wordlist: Wordlist to feed Hashcat
        Returns
        -------
        """

        if attack_mode:
            if isinstance(attack_mode, int):
                pass
            else:
                attack_mode = None
        if restore:
            show = False
        else:
            show = True
        hcat = crack.runner(hash_file=hash_file, mask=mask,
                            session=session, wordlist=wordlist,
                            outfile=outfile, attack_mode=attack_mode,
                            hash_mode=hash_mode, rules=rules,
                            username=username, pot_path=pot_path,
                            restore=restore, show=show, brain=False)
        hcat.event_connect(callback=self.finished_callback,
                           signal="EVENT_CRACKER_FINISHED")
        #hcat.event_connect(callback=self.cracked_callback,
        #                   signal="EVENT_CRACKER_HASH_CRACKED")
        #print(dir(hcat.event_connect(callback=self.cracked_callback,
        #                   signal="ANY")))
        ###***EDITED HERE TESTING POLLING STATUS WHILE NULL
        #hcat.event_connect(callback=self.cracked_callback,
        #                   signal="ANY")
        ###***restructure this when queue reorder is implemented
        #then move the show to run earlier, i.e. when the initial job
        #request comes in. This needs reordering to work
        if hcat.show is True:
            mode_info = dict(hash_modes.HModes.modes_dict())[str(hash_mode)]
            time.sleep(5)
            salts = hcat.status_get_salts_cnt()
            logger.debug('Salts Count: {}'.format(salts))
            logger.debug('Relative estimated speed: {}'.format(int(mode_info[2])))
            if salts > 0:
                if int(mode_info[2]) / salts < 500000:
                    logger.debug('Brain engaged!')
                    brain = True
                else:
                    brain = False
                    logger.debug('Brain disabled due to bottleneck (fast candidates)')
            else:
                brain = False
                logger.debug('Brain disabled due to bottleneck (fast candidates)')
            hcat.hashcat_session_quit()
            hcat.soft_reset()
            hcat = crack.runner(hash_file=hash_file, mask=mask,
                                session=session, wordlist=wordlist,
                                outfile=outfile, attack_mode=attack_mode,
                                hash_mode=hash_mode, rules=rules,
                                username=username, pot_path=pot_path,
                                restore=restore, brain=brain)
            hcat.event_connect(callback=self.finished_callback,
                               signal="EVENT_CRACKER_FINISHED")
        try:
            counter = 0
            redis_con = Redis(self.rconf['host'], self.rconf['port'])
            redis_q = Queue(connection=redis_con)
            while True:
                hc_state = hcat.status_get_status_string()
                sleep(10)
                counter += 10
                # added manual status update as callback doesn't get triggere
                # in some cases, see issue #1
                #self.cracked_callback(hcat)
                if hc_state == 'Exhausted' and not mask_file:
                    self.cracked_callback(hcat)
                    return 'Exhausted'
                if hc_state == 'Exhausted' and mask_file:
                    self.cracked_callback(hcat)
                    # workaround for mask files
                    ###***this needs to be better, some cases could exit early
                    sleep(30)
                    if hc_state == 'Exhausted':
                        logger.info('checking mask file')
                        if hc_state == 'Exhausted':
                            return 'Exhausted'
                elif hc_state == 'Cracked':
                    self.cracked_callback(hcat)
                    return 'Cracked'
                elif hc_state == 'Aborted':
                    ###***this seems to hang - look into it
                    raise ValueError('Aborted: Invalid Hashcat input')
                elif counter > 1200 and hc_state != 'Running' and mask_file == False:
                    #return 'Error: Hashcat hung - input error?'
                    logger.debug('Reseting job, seems to be hung')
                    raise ValueError('Error: Hashcat hung - Initialize timeout')
                ###***need to catch other error types here
                ###***fix this to update current job state while loading
                elif 'Initializing' not in hc_state:
                    logger.debug('Initialized: {}'.format(hc_state))
                    self.cracked_callback(hcat)
                    job = redis_q.fetch_job(str(hcat.session))
                    try:
                        if job.meta['CrackQ State'] == 'Stop':
                            logger.info('Stopping Job: {}'.format(hcat.session))
                            hcat.hashcat_session_quit()
                            # beow will move job to failed queue
                            # raise SystemExit('Job cancelled by user')
                            return # 'User Cancelled'
                        else:
                            job.meta['CrackQ State'] == 'Run'
                            job.save_meta()
                    except Exception as err:
                        job.meta['CrackQ State'] == 'Loading'
                        logger.warning('No CrackQ State set: {}'.format(err))
                else:
                    ###***cleanup and move all job/redis stuff to init and remove from other areas
                    logger.debug('Fell through')
                    logger.debug('HC State {}'.format(hc_state))
                    #redis_con = Redis(self.rconf['host'], self.rconf['port'])
                    #redis_q = Queue(connection=redis_con)
                    job = redis_q.fetch_job(str(hcat.session))
                    ###***print this better 
                    ###***fix zombie? job here when Nonetype***
                    try:
                        job.meta['HC State'] = hc_state
                        job.meta['CrackQ State'] == 'Loading'
                        job.save_meta()
                    except AttributeError as err:
                        logger.error('Failed to update meta: {}'.format(err))
                        break

        except KeyboardInterrupt:
            hcat.hashcat_session_quit()
            exit(0)
