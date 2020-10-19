"""This module handles the PyHashcat integration"""
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
        return status_data

    def runner(self, hash_file=None, hash_mode=1000,
               attack_mode=0, rules=None,
               mask=None, wordlist=None, session=None,
               outfile=None, restore=None, username=False,
               pot_path=None, show=False, brain=True,
               increment=False, increment_min=None,
               increment_max=False, speed=False, benchmark=False,
               benchmark_all=False):
        logger.info('Running hashcat')
        rconf = CRACK_CONF['redis']
        redis_con = Redis(rconf['host'], rconf['port'])
        redis_q = Queue(connection=redis_con)
        hc = Hashcat()
        logger.debug('Hashcat object ID: {}'.format(id(hc)))
        hc.session = session
        if benchmark:
            logger.debug('Running in benchmark mode')
            hash_mode = None
            hc.benchmark = True
            if benchmark_all:
                hc.benchmark_all = True
            hc.hashcat_session_execute()
            return hc
        hc.potfile_disable = False
        hc.restore_disable = True
        hc.show = show
        if pot_path:
            hc.potfile_path = pot_path
        hc.quiet = False
        hc.optimized_kernel_enable = True
        hc.workload_profile = 4
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
        if speed:
            hc.speed_only = True
            hc.hashcat_session_execute()
            return hc
        if brain:
            speed_q = Queue('speed_check', connection=redis_con)
            speed_session = '{}_speed'.format(session)
            speed_job = speed_q.fetch_job(speed_session)
            job = redis_q.fetch_job(session)
            wait_count = 0
            if speed_job:
                while len(speed_job.meta) < 1 and wait_count < 310:
                    logger.debug('RUNNER loop')
                    logger.debug('Speed meta not populated, waiting...')
                    if speed_job:
                        if 'failed' in speed_job.get_status():
                            logger.error('Speed check failed: {}'.format(speed_job.exc_info))
                            raise ValueError('Aborted, speed check failed: {}'.format(speed_job.exc_info))
                        elif 'finished' in speed_job.get_status():
                            logger.debug('Breaking runner loop speed check job has finished')
                            break
                    time.sleep(5)
                    wait_count += 5
                    speed_job = speed_q.fetch_job(speed_session)
                logger.debug('RUNNER loop finished')
                if 'Mode Info' in speed_job.meta:
                    mode_info = speed_job.meta['Mode Info']
                    salts = mode_info[3]
                    speed = int(mode_info[2])
                    brain = self.brain_check(speed, salts)
                    hc.brain_client = brain
                    hc.brain_client_features = 3
                    ###***replace with random string
                    hc.brain_password = '425dafbb8e87fe18'
                else:
                    logger.error('Speed check error, disabling brain')
                    hc.brain = False
                    job.meta['CrackQ State'] == 'Run/Restored'
                    job.save_meta()
            else:
                logger.error('No speed job to check')
                hc.brain = False
        ###*** update this to config file path and try/except
        hc.markov_hcstat2 = "/var/crackq/files/crackq.hcstat"
        hc.custom_charset_1 = '?l?d'
        hc.custom_charset_2 = '?l?d?u'
        hc.custom_charset_3 = '?l?d?s'
        hc.outfile = outfile
        logger.debug('HC. Hashcat Rules: {}'.format(hc.rules))
        logger.debug('HC. Hashcat rp_files_cnt: {}'.format(hc.rp_files_cnt))
        if restore:
            hc.skip = int(restore)
        hc.hashcat_session_execute()
        speed_started = rq.registry.StartedJobRegistry('speed_check',
                                                       connection=redis_con)
        cur_speed = speed_started.get_job_ids()
        ###***this needs checking for holes
        if len(cur_speed) > 0:
            logger.debug('Speed job running, setting new job to Paused')
            ###*** re-add this
            #hc.hashcat_session_pause()
            job = redis_q.fetch_job(session)
            if job:
                job.meta['CrackQ State'] = 'Pause'
                job.save_meta()
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
        if job:
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
        else:
            logger.error('Job error')
        if isinstance(status_dict, dict):
            self.write_result(status_dict)
        else:
            self.write_result('Hashcat: {}'.format(status_dict))

    def bench_callback(self, sender):
        """
        Callback function to create benchmark dictionary
        """
        logger.debug('Callback Triggered: Benchmark')
        rconf = CRACK_CONF['redis']
        redis_con = Redis(rconf['host'], rconf['port'])
        redis_q = Queue(connection=redis_con)
        status_dict = self.status(sender)
        session = str(sender.session)
        job = redis_q.fetch_job(session)
        if job:
            speed_raw = int(status_dict['Speed Raw']) * 1000
            speed_format = status_dict['Speed All']
            hash_mode = str(sender.hash_mode).strip()
            if 'Benchmarks' not in job.meta:
                job.meta['Benchmarks'] = {}
            job.meta['Benchmarks'].update({
                hash_mode: [speed_raw, speed_format]
                })
            job.save_meta()
            log_dir = CRACK_CONF['files']['log_dir']
            bench_file = Path(log_dir).joinpath('sys_benchmark.json')
            with open(bench_file, 'w') as bench_fh:
                logger.debug('Writing results to benchmark file')
                bench_fh.write(json.dumps(job.meta))
        else:
            logger.error('Failed to write benchmark job meta: {}'.format(session))

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
        session = sender.session
        logger.debug('Sending notification')
        job = redis_q.fetch_job(session)
        if job:
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
        else:
            logger.error('Job error')
        if isinstance(status_dict, dict):
            self.write_result(status_dict)
        else:
            self.write_result('Hashcat: {}'.format(status_dict))
        if sender.benchmark:
            sender.status_reset()

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
        logger.warning('{}'.format(msg_buf))
        if len(started.get_job_ids()) > 0:
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
        logger.error('{}'.format(msg_buf))
        if len(started.get_job_ids()) > 0:
            session = started.get_job_ids()[0]
            logger.error('{}: {}'.format(session, msg_buf))
            job = redis_q.fetch_job(session)
            job.meta['ERROR'] = msg_buf
            job.save_meta()

    def abort_callback(self, sender):
        """
        Callback function to take action following Hashcat aborting
        """
        logger.info('Callback Triggered: Aborted')
        event_log = sender.hashcat_status_get_log()
        raise ValueError('Aborted: {}'.format(event_log))

    def any_callback(self, sender):
        """
        Callback function to take action following Hashcat aborting
        """
        logger.debug('Callback Triggered: Any')
        hc_state = sender.status_get_status_string()
        logger.debug('Hashcat status: {}'.format(hc_state))
        #if hc_state == "Aborted":
        #    event_log = sender.hashcat_status_get_log()
        #    raise ValueError('Aborted: {}'.format(event_log))

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

    def brain_check(self, speed, salts):
        """
            Method to decide whether or not to enable the brain

            Arguments
            ---------
            speed: int
                estimated speed, taken from speed_check()
            salts: int
                number of salts in hashcat session
            Returns
            -------
            brain: boolean
                enable or disable
        """
        logger.debug('Running brain check')
        logger.debug('Salts Count: {}'.format(salts))
        logger.debug('Relative estimated speed: {}'.format(speed))
        if salts > 0:
            if speed / salts < 500000:
                logger.debug('Brain engaged!')
                brain = True
            else:
                brain = False
                logger.debug('Brain disabled due to bottleneck (fast candidates)')
        else:
            if speed < 500000:
                logger.debug('Brain engaged!')
                brain = True
            else:
                brain = False
                logger.debug('Brain disabled due to bottleneck (fast candidates)')
        return brain

    def hc_worker(self, crack=None, hash_file=None, session=None,
                  wordlist=None, outfile=None, hash_mode=1000,
                  attack_mode=None, mask=None, rules=None, name=None,
                  username=False, pot_path=None, restore=None,
                  brain=True, mask_file=False, increment=False,
                  increment_min=None, increment_max=None, speed=True,
                  benchmark=False, benchmark_all=False):
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
        redis_con = Redis(self.rconf['host'], self.rconf['port'])
        redis_q = Queue('default', connection=redis_con)
        job = redis_q.fetch_job(session)
        hcat = crack.runner(hash_file=hash_file, mask=mask,
                            session=session, wordlist=wordlist,
                            outfile=outfile, attack_mode=attack_mode,
                            hash_mode=hash_mode, rules=rules,
                            username=username, pot_path=pot_path,
                            restore=restore, brain=brain,
                            benchmark=benchmark, benchmark_all=benchmark_all)
        hcat.event_connect(callback=self.error_callback,
                           signal="EVENT_LOG_ERROR")
        hcat.event_connect(callback=self.warning_callback,
                           signal="EVENT_LOG_WARNING")
        if benchmark:
            hcat.event_connect(callback=self.bench_callback,
                               signal="EVENT_CRACKER_FINISHED")
            hcat.event_connect(callback=self.finished_callback,
                               signal="EVENT_OUTERLOOP_FINISHED")
            hcat.event_connect(callback=self.any_callback,
                               signal="ANY")
        else:
            hcat.event_connect(callback=self.finished_callback,
                               signal="EVENT_CRACKER_FINISHED")
            hcat.event_connect(callback=self.cracked_callback,
                               signal="EVENT_CRACKER_HASH_CRACKED")
        try:
            main_counter = 0
            rconf = CRACK_CONF['redis']
            redis_con = Redis(rconf['host'], rconf['port'])
            redis_q = Queue(connection=redis_con)
            while True:
                hc_state = hcat.status_get_status_string()
                logger.debug('MAIN loop')
                # added manual status update as callback doesn't get triggered
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
                    logger.debug('Hashcat Abort status returned')
                    event_log = hcat.hashcat_status_get_log()
                    raise ValueError('Aborted: {}'.format(event_log))
                elif main_counter > 1200 and hc_state != 'Running' and mask_file == False:
                    logger.debug('Reseting job, seems to be hung')
                    raise ValueError('Error: Hashcat hung - Initialize timeout')
                elif 'Initializing' not in hc_state:
                    logger.debug('Initialized: {}'.format(hc_state))
                    self.init_callback(hcat)
                    job = redis_q.fetch_job(str(hcat.session))
                    if job:
                        try:
                            if job.meta['CrackQ State'] == 'Stop':
                                logger.info('Stopping Job: {}'.format(hcat.session))
                                hcat.hashcat_session_quit()
                                return
                            elif job.meta['CrackQ State'] == 'Delete':
                                logger.info('Deleting Job: {}'.format(hcat.session))
                                hcat.hashcat_session_quit()
                                hcat.reset()
                                started = rq.registry.StartedJobRegistry('default',
                                                                         connection=redis_con)
                                job.delete()
                                started.cleanup()
                                return
                            elif job.meta['CrackQ State'] == 'Pause':
                                hcat.hashcat_session_pause()
                                pause_counter = 0
                                logger.debug('Pausing job: {}'.format(hcat.session))
                                while pause_counter < 400:
                                    logger.debug('PAUSE loop')
                                    if hcat.status_get_status_string() == 'Paused':
                                        logger.info('Job Paused: {}'.format(hcat.session))
                                        break
                                    pause_counter += 1
                                if hcat.status_get_status_string() != 'Paused':
                                    logger.error('Failed to pause job')
                                # catch potential stale paused jobs
                                speed_started = rq.registry.StartedJobRegistry('speed_check',
                                                                               connection=redis_con)
                                cur_speed = speed_started.get_job_ids()
                                if len(cur_speed) < 1:
                                    job.meta['CrackQ State'] == 'Run/Restored'
                                    job.save_meta()
                            elif hc_state == 'Bypass':
                                logger.debug('Error: Bypass not cleared')
                            else:
                                try:
                                    logger.info('Resuming Job: {}'.format(hcat.session))
                                    hcat.hashcat_session_resume()
                                except:
                                    ###***make try/excep more specific
                                    logger.debug('Already running')
                                job.meta['CrackQ State'] == 'Run/Restored'
                                job.save_meta()
                        except Exception as err:
                            ###***make try/excep more specific
                            job.meta = {'CrackQ State': 'Loading'}
                            job.save_meta()
                            logger.warning('No CrackQ State set: {}'.format(err))
                    else:
                        logger.debug('Error finding redis job')
                elif hc_state == 'Initializing':
                    logger.debug('Fell through')
                    logger.debug('HC State {}'.format(hc_state))
                    job = redis_q.fetch_job(str(hcat.session))
                    # catch potential stale paused jobs
                    if job.meta['CrackQ State'] == 'Pause':
                        speed_started = rq.registry.StartedJobRegistry('speed_check',
                                                                       connection=redis_con)
                        cur_speed = speed_started.get_job_ids()
                        if len(cur_speed) < 1:
                            job.meta['CrackQ State'] == 'Run/Restored'
                            job.save_meta()
                    #if job:
                    #    try:
                    #        job.meta['HC State'] = hc_state
                    #        job.meta['CrackQ State'] = 'Loading'
                    #        job.save_meta()
                    #    except KeyError:
                    #        job.meta = {'CrackQ State': 'Loading'}
                    #        job.save_meta()
                    #    except AttributeError as err:
                    #        logger.error('Failed to update meta: {}'.format(err))
                sleep(10)
                main_counter += 10
        except KeyboardInterrupt:
            hcat.hashcat_session_quit()
            exit(0)
        except Exception as err:
            logger.error('MAIN loop closed: {}'.format(err))

    def show_speed(self, crack=None, hash_file=None, session=None,
                   wordlist=None, hash_mode=1000, speed_session=None,
                   attack_mode=None, mask=None, rules=None,
                   pot_path=None, brain=False, username=False):
        """
        Method to run hashcat with 'show' and 'speed_only' options to
        gather information relevant to brain use, and also for quick wins
        to skip the queue. It will pause the current job then run in the
        above modes to get passwords from the potfile and an estimated speed.

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
        ###***move these to init/self
        rconf = CRACK_CONF['redis']
        redis_con = Redis(rconf['host'], rconf['port'])
        redis_q = Queue('default', connection=redis_con)
        started = rq.registry.StartedJobRegistry('default',
                                                 connection=redis_con)
        cur_list = started.get_job_ids()
        if len(cur_list) > 0:
            job = redis_q.fetch_job(cur_list[0])
            if job:
                if any(s in job.meta['CrackQ State'] for s in ['Stop', 'Delete']):
                    logger.debug('Job stop already requested, not pausing')
                    time.sleep(10)
                else:
                    job.meta['CrackQ State'] = 'Pause'
                    logger.debug('Pausing active job')
                    job.save_meta()
            else:
                logger.debug('Failed to pause current job')
                raise ValueError('Speed check error')
        if attack_mode:
            if not isinstance(attack_mode, int):
                attack_mode = None
        # run --show first
        outfile = Path('{}{}.cracked'.format(self.log_dir, speed_session[:-6]))
        hcat = self.runner(hash_file=hash_file, mask=mask,
                           session=speed_session, wordlist=wordlist,
                           outfile=str(outfile), attack_mode=attack_mode,
                           hash_mode=hash_mode,
                           username=username, pot_path=pot_path,
                           show=True, brain=False)
        hcat.event_connect(callback=self.finished_callback,
                           signal="EVENT_POTFILE_HASH_SHOW")
        hcat.event_connect(callback=self.any_callback,
                           signal="ANY")
        counter = 0
        ###***reduce this?
        while counter < 100:
            if hcat is None or isinstance(hcat, str):
                return hcat
            hc_state = hcat.status_get_status_string()
            logger.debug('SHOW loop')
            if hc_state == 'Running':
                break
            if hc_state == 'Paused':
                break
            elif hc_state == 'Aborted':
                event_log = hcat.hashcat_status_get_log()
                raise ValueError('Speed check error: {}'.format(event_log))
            time.sleep(1)
            counter += 1
        logger.debug('SHOW loop complete, quitting hashcat')
        hcat.hashcat_session_quit()
        hcat.reset()
        if brain:
            speed_q = Queue('speed_check', connection=redis_con)
            hcat = self.runner(hash_file=hash_file, mask=mask,
                               wordlist=wordlist, speed=True,
                               attack_mode=attack_mode,
                               hash_mode=hash_mode, rules=rules,
                               pot_path=pot_path, show=False,
                               brain=False, session=speed_session)
            hcat.event_connect(callback=self.any_callback,
                               signal="ANY")
            mode_info = dict(hash_modes.HModes.modes_dict())[str(hash_mode)]
            logger.debug('Mode info: {}'.format(mode_info))
            salts = hcat.status_get_salts_cnt()
            logger.debug('Salts Count: {}'.format(salts))
            speed_counter = 0
            while counter < 180:
                logger.debug('SPEED loop')
                if hcat is None or isinstance(hcat, str):
                    return hcat
                hc_state = hcat.status_get_status_string()
                ###***LOOKS LIKE IT'S FAILNG HERE
                if hc_state:
                    speed_job = speed_q.fetch_job(hcat.session)
                    logger.debug('Speed job:\n{}'.format(speed_job))
                    if hc_state == 'Bypass':
                        if speed_job and mode_info:
                            logger.debug('Populating speed meta')
                            speed_info = int(hcat.status_get_hashes_msec_all() * 1000)
                            mode_info.append(speed_info)
                            mode_info.append(salts)
                            speed_job.meta['Mode Info'] = mode_info
                            speed_job.save_meta()
                            hc_state = hcat.status_get_status_string()
                        cur_list = started.get_job_ids()
                        job = redis_q.fetch_job(cur_list[0])
                        if job:
                            job.meta['CrackQ State'] = 'Run/Restored'
                            job.save_meta()
                            logger.debug('Resuming active job: {}'.format(job.id))
                        else:
                            logger.debug('No job to resume')
                        hcat.status_reset()
                        hcat.hashcat_session_quit()
                        hcat.reset()
                        hc_state = hcat.status_get_status_string()
                        return hc_state
                    elif 'Aborted' in hc_state:
                        event_log = hcat.hashcat_status_get_log()
                        raise ValueError('Aborted: {}'.format(event_log))
                    else:
                        job = redis_q.fetch_job(session)
                        if job:
                            if job.meta['CrackQ State'] == 'Stop':
                                ###***update this to let speed check finish
                                # otherwise there will be no speed check when
                                # resuming
                                event_log = hcat.hashcat_status_get_log()
                                raise ValueError('Speed check stopped by user: {}'.format(event_log))
                            elif job.meta['CrackQ State'] == 'Delete':
                                ###***add meta entry showing speed job stopped
                                event_log = hcat.hashcat_status_get_log()
                                raise ValueError('Speed check stopped by user: {}'.format(event_log))
                logger.debug('No hc_state')
                time.sleep(1)
                speed_counter += 1
            logger.debug('SPEED counter expired')
            event_log = hcat.hashcat_status_get_log()
            hcat.status_reset()
            hcat.hashcat_session_quit()
            hcat.reset()
            job = redis_q.fetch_job(session)
            if job:
                job.meta['CrackQ State'] = 'Run/Restored'
                job.save_meta()
                logger.debug('Resuming active job')
            raise ValueError('Speed check error: {}'.format(event_log))
        else:
            logger.debug('Brain user-disabled')
            job = redis_q.fetch_job(session)
            if job:
                job.meta['CrackQ State'] = 'Run/Restored'
                job.save_meta()
                logger.debug('Resuming active job')
        return hc_state
