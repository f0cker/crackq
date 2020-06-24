#!/usr/bin/env python
import email.utils
import logging
import json
import os
import time
import rq
import smtplib
import ssl

from crackq import crackqueue, hash_modes, cq_api
from crackq.conf import hc_conf
from crackq.models import User
from datetime import datetime, timedelta
from email.mime.text import MIMEText
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

    def send_email(self, mail_server, port, src, dest, sub, tls):
        """
        Simple email notification

        Arguments
        --------
        mail_server: str
            email server hostname/ip
        port: int
            port to use
        src: str
            email from address
        dest: str
            email to address
        tls: boolean
            use encryption for SMTP

        Returns
        -------
        """
        if os.environ['MAIL_USERNAME']:
            mail_username = os.environ['MAIL_USERNAME']
        if os.environ['MAIL_PASSWORD']:
            mail_password = os.environ['MAIL_PASSWORD']
        msg = MIMEText('')
        msg['To'] = email.utils.formataddr(('CrackQ', dest))
        msg['From'] = email.utils.formataddr(('CrackQ', src))
        msg['Subject'] = sub
        try:
            if tls:
                server = smtplib.SMTP(mail_server, port)
                server.starttls()
                if mail_username and mail_password:
                    server.login(mail_username, mail_password)
                #server.set_debuglevel(True)
                server.sendmail(src, [dest],
                                msg.as_string())
                server.quit()
            else:
                server = smtplib.SMTP(mail_server, port)
                #server.set_debuglevel(True)
                server.sendmail(src, [dest],
                                msg.as_string())
                server.quit()
        except TimeoutError:
            logger.error('SMTP connection error - timeout')
            server.quit()
        except ssl.SSLError as err:
            logger.debug(err)
            logger.error('SMTP SSL/TLS error')
            server.quit()

    def status(self, sender):
        status_data = sender.hashcat_status_get_status()
        if status_data == -1:
            status_data = 'Waiting'
        # hide cracked passwords
        #elif isinstance(status_data, dict):
        #    del status_data['Cracked']
        return status_data

    def runner(self, hash_file=None, hash_mode=1000,
               attack_mode=0, rules=None,
               mask=None, wordlist=None, session=None,
               outfile=None, restore=None, username=False,
               pot_path=None, show=False, brain=True,
               increment=False, increment_min=None,
               increment_max=False):
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
        if increment is True:
            hc.increment = True
        if increment_min:
            if isinstance(increment_min, int):
                hc.increment_min = increment_min
        if increment_max:
            if isinstance(increment_max, int):
                hc.increment_max = increment_max
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
        logger.debug('Callback Triggered: Cracked')
        status_dict = self.status(sender)
        logger.debug('Hashcat status: {}'.format(status_dict))
        if CRACK_CONF['notify']:
            mail_server = CRACK_CONF['notify']['mail_server']
            mail_port = CRACK_CONF['notify']['mail_port']
            email_src = CRACK_CONF['notify']['src']
            inactive_time = CRACK_CONF['notify']['inactive_time']
            tls = CRACK_CONF['notify']['tls']
        rconf = CRACK_CONF['redis']
        redis_con = Redis(rconf['host'], rconf['port'])
        redis_q = Queue(connection=redis_con)
        started = rq.registry.StartedJobRegistry('default',
                                                 connection=redis_con)
        session = started.get_job_ids()[0]
        job = redis_q.fetch_job(session)
        if 'notify' in job.meta.keys():
            if job.meta['notify']:
                if 'email' in job.meta.keys():
                    user_email = job.meta['email']
                    try:
                        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        now = datetime.strptime(now,
                                                '%Y-%m-%d %H:%M:%S')
                        last = datetime.strptime(job.meta['last_seen'],
                                                 '%Y-%m-%d %H:%M:%S')
                        inactive_time = timedelta(minutes=int(inactive_time))
                        activity = now - last
                        if (activity > inactive_time
                                        and job.meta['email_count'] < 1):
                            sub = 'CrackQ: Hash cracked notification'
                            self.send_email(mail_server, mail_port,
                                            email_src, user_email, sub, tls)
                            job.meta['email_count'] += 1
                            job.save()
                    ###***update to specific exceptions
                    except ssl.SSLError as err:
                        logger.error('Failed to connect to mail server')
                        logger.error(err)
                    except Exception as err:
                        logger.error('Failed to connect to mail server')
                        logger.error(err)
                else:
                    job.meta['Warning'] = "No email address in profile"
                    job.save()
        else:
            job.meta['Warning'] = "Notification settings error"
            job.save()
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
        if CRACK_CONF['notify']:
            mail_server = CRACK_CONF['notify']['mail_server']
            mail_port = CRACK_CONF['notify']['mail_port']
            email_src = CRACK_CONF['notify']['src']
            inactive_time = CRACK_CONF['notify']['inactive_time']
            tls = CRACK_CONF['notify']['tls']
        rconf = CRACK_CONF['redis']
        redis_con = Redis(rconf['host'], rconf['port'])
        redis_q = Queue(connection=redis_con)
        started = rq.registry.StartedJobRegistry('default',
                                                 connection=redis_con)
        #try:
        #    session = started.get_job_ids()[0]
        #except KeyError:
            #logger.debug('Problem getting stopped session for notify')
        session = sender.session
        logger.debug('Sending notification')
        job = redis_q.fetch_job(session)
        if 'notify' in job.meta.keys():
            if job.meta['notify']:
                if 'email' in job.meta.keys():
                    user_email = job.meta['email']
                    try:
                        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        now = datetime.strptime(now,
                                                '%Y-%m-%d %H:%M:%S')
                        last = datetime.strptime(job.meta['last_seen'],
                                                 '%Y-%m-%d %H:%M:%S')
                        inactive_time = timedelta(minutes=int(inactive_time))
                        activity = now - last
                        if (activity > inactive_time
                                and job.meta['email_count'] < 2):
                            sub = 'CrackQ: Job complete notification'
                            self.send_email(mail_server, mail_port,
                                            email_src, user_email, sub, tls)
                            job.meta['email_count'] += 1
                            job.save()
                    ###***update to specifica exceptions
                    except Exception as err:
                        logger.error('Failed to connect to mail server')
                        logger.error(err)
                else:
                    job.meta['Warning'] = "No email address in profile"
                    job.save()
        else:
            job.meta['Warning'] = "Notification settings error"
            job.save()
        if isinstance(status_dict, dict):
            self.write_result(status_dict)
        else:
            self.write_result('Hashcat: {}'.format(status_dict))

    def init_callback(self, sender):
        """
        Callback function to take action on hashcat signal.
        Action is to write the latest cracked hashes
        """
        logger.debug('Callback Triggered: Init')
        status_dict = self.status(sender)
        logger.debug('Hashcat status: {}'.format(status_dict))
        if isinstance(status_dict, dict):
            self.write_result(status_dict)
        else:
            self.write_result('Hashcat: {}'.format(status_dict))

    def warning_callback(self, sender):
        """
        Callback function to take action on hashcat warning event
        """
        logger.warning('Callback Triggered: WARNING')
        msg_buf = sender.hashcat_status_get_log()
        logger.warning('{}'.format(msg_buf))
        rconf = CRACK_CONF['redis']
        redis_con = Redis(rconf['host'], rconf['port'])
        redis_q = Queue(connection=redis_con)
        started = rq.registry.StartedJobRegistry('default',
                                                 connection=redis_con)
        session = started.get_job_ids()[0]
        logger.warning('{}: {}'.format(session, msg_buf))
        job = redis_q.fetch_job(session)
        if sender.username and 'Separator unmatched' in msg_buf:
            job.meta['TIP'] = 'This algorithm probably doesn\'t' \
                              ' support the username flag'
        if CRACK_CONF['misc']['user_warnings'] is True:
            job.meta['WARNING'] = msg_buf
        job.save_meta()

    def error_callback(self, sender):
        """
        Callback function to take action on hashcat error event
        """
        logger.debug('Callback Triggered: ERROR')
        msg_buf = sender.hashcat_status_get_log()
        logger.debug('{}'.format(msg_buf))
        rconf = CRACK_CONF['redis']
        redis_con = Redis(rconf['host'], rconf['port'])
        redis_q = Queue(connection=redis_con)
        started = rq.registry.StartedJobRegistry('default',
                                                 connection=redis_con)
        session = started.get_job_ids()[0]
        job = redis_q.fetch_job(session)
        job.meta['ERROR'] = msg_buf
        job.save_meta()

    def abort_callback(self, sender):
        """
        Callback function to take action following Hashcat aborting
        """
        logger.info('Callback Triggered: Aborted')
        #msg_buf = sender.hashcat_status_get_log()
        #logger.debug('{}'.format(msg_buf))
        #rconf = CRACK_CONF['redis']
        #redis_con = Redis(rconf['host'], rconf['port'])
        #redis_q = Queue(connection=redis_con)
        #started = rq.registry.StartedJobRegistry('default',
        #                                         connection=redis_con)
        #session = started.get_job_ids()[0]
        #job = redis_q.fetch_job(session)
        #job.meta['ERROR'] = msg_buf
        #job.save_meta()
        event_log = sender.hashcat_status_get_log()
        raise ValueError('Aborted: {}'.format(event_log))

    def any_callback(self, sender):
        """
        Callback function to take action following Hashcat aborting
        """
        logger.debug('Callback Triggered: Any')
        hc_state = sender.status_get_status_string()
        if hc_state == "Aborted":
            event_log = sender.hashcat_status_get_log()
            raise ValueError('Aborted: {}'.format(event_log))

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
            redis connection object initiated 
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
        rconf = CRACK_CONF['redis']
        redis_con = Redis(rconf['host'], rconf['port'])
        redis_q = Queue(connection=redis_con)
        logger.debug('Creating results file')
        #cracked_file = '{}{}.cracked'.format(self.log_dir, hcat_status['Session'])
        result_file = '{}{}.json'.format(self.log_dir, hcat_status['Session'])
        #try:
        #    with open(cracked_file, 'r') as cracked_fh:
        #        cracked_list = [cracked.rstrip() for cracked in cracked_fh]
        #    hcat_status['Cracked'] = cracked_list
        #except IOError as err:
        #    logger.debug('Cracked file does not exist: {}'.format(err))
        with open(result_file, 'w') as result_fh:
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
                logger.debug('Status update failure: {}'.format(err))
            except KeyError as err:
                logger.debug('Status update failure: {}'.format(err))

    def hc_worker(self, crack=None, hash_file=None, session=None,
                  wordlist=None, outfile=None, hash_mode=1000,
                  attack_mode=None, mask=None, rules=None, name=None,
                  username=False, pot_path=None, restore=None,
                  brain=True, mask_file=False, increment=False,
                  increment_min=None, increment_max=None):
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
            if not isinstance(attack_mode, int):
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
        hcat.event_connect(callback=self.cracked_callback,
                           signal="EVENT_CRACKER_HASH_CRACKED")
        hcat.event_connect(callback=self.any_callback,
                           signal="ANY")
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
            hcat.event_connect(callback=self.cracked_callback,
                               signal="EVENT_CRACKER_HASH_CRACKED")
            hcat.event_connect(callback=self.error_callback,
                               signal="EVENT_LOG_ERROR")
            hcat.event_connect(callback=self.warning_callback,
                               signal="EVENT_LOG_WARNING")
        try:
            counter = 0
            rconf = CRACK_CONF['redis']
            redis_con = Redis(rconf['host'], rconf['port'])
            redis_q = Queue(connection=redis_con)
            while True:
                hc_state = hcat.status_get_status_string()
                sleep(10)
                counter += 10
                # added manual status update as callback doesn't get triggere
                # in some cases, see issue #1
                if hc_state == 'Exhausted' and not mask_file:
                    self.finished_callback(hcat)
                    return 'Exhausted'
                if hc_state == 'Exhausted' and mask_file:
                    # workaround for mask files
                    ###***this needs to be better, some cases could exit early
                    sleep(30)
                    if hc_state == 'Exhausted':
                        logger.info('checking mask file')
                        if hc_state == 'Exhausted':
                            self.finished_callback(hcat)
                            return 'Exhausted'
                elif hc_state == 'Cracked':
                    self.cracked_callback(hcat)
                    return 'Cracked'
                elif hc_state == 'Aborted':
                    # add error check from hc here
                    ###***this seems to hang - look into it
                    event_log = hcat.hashcat_status_get_log()
                    #raise ValueError('Aborted: Invalid Hashcat input')
                    raise ValueError('Aborted: {}'.format(event_log))
                elif counter > 1200 and hc_state != 'Running' and mask_file == False:
                    #return 'Error: Hashcat hung - input error?'
                    logger.debug('Reseting job, seems to be hung')
                    raise ValueError('Error: Hashcat hung - Initialize timeout')
                ###***need to catch other error types here
                ###***fix this to update current job state while loading
                elif 'Initializing' not in hc_state:
                    logger.debug('Initialized: {}'.format(hc_state))
                    self.init_callback(hcat)
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
                        job.meta = {'CrackQ State': 'Loading'}
                        job.save_meta()
                        logger.warning('No CrackQ State set: {}'.format(err))
                else:
                    ###***cleanup and move all job/redis stuff to init and remove from other areas
                    logger.debug('Fell through')
                    logger.debug('HC State {}'.format(hc_state))
                    #redis_con = Redis(self.rconf['host'], self.rconf['port'])
                    #redis_q = Queue(connection=redis_con)
                    job = redis_q.fetch_job(str(hcat.session))
                    try:
                        job.meta['HC State'] = hc_state
                        job.meta['CrackQ State'] == 'Loading'
                        job.save_meta()
                    except KeyError:
                        job.meta = {'CrackQ State': 'Loading'}
                        job.save_meta()
                    except AttributeError as err:
                        logger.error('Failed to update meta: {}'.format(err))
                        break

        except KeyboardInterrupt:
            hcat.hashcat_session_quit()
            exit(0)
