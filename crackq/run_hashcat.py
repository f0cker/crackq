"""This module handles the PyHashcat integration"""
#!/usr/bin/env python
import email.utils
import json
import os
import time
import rq
import smtplib
import ssl

from crackq import crackqueue, hash_modes, cq_api
from crackq.conf import hc_conf
from crackq.logger import logger
from crackq.validator import FileValidation as valid
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from pathlib import Path
from time import sleep
from pyhashcat import Hashcat
from redis import Redis
from rq import use_connection, Queue
from rq.serializers import JSONSerializer

# set perms
os.umask(0o077)

CRACK_CONF = hc_conf()
log_dir = CRACK_CONF['files']['log_dir']
rconf = CRACK_CONF['redis']
redis_con = Redis(rconf['host'], rconf['port'])
redis_q = Queue('default', connection=redis_con, serializer=JSONSerializer)
speed_q = Queue('speed_check', connection=redis_con,
                serializer=JSONSerializer)


def del_check(job):
    """
    Check if job is marked for delete/stop
    """
    try:
        #logger.debug('Checking for Stop/Delete notification')
        if any(s in job.meta['CrackQ State'] for s in ['Stop',
                                                       'Delete']):
            return True
    except KeyError:
        logger.debug('Del check failed, no CrackQ state')
    return False


def write_template(template_dict, job_id):
    """
    Write a CrackQ json state file

    This could be a job template or a current
    job state file.

    Arguments
    ---------
    template_dict: dict
        JSON job details in dict format
    job_id: uuid
        ID to store the file under

    Returns
    """
    logger.debug('Writing template/status file')
    log_dir = CRACK_CONF['files']['log_dir']
    temp_file = valid.val_filepath(path_string=log_dir,
                                   file_string='{}.json'.format(job_id))
    try:
        with open(temp_file, 'x') as fh_temp:
            fh_temp.write(json.dumps(template_dict))
    except FileExistsError as err:
        logger.debug('Status/Template file already exists {}'.format(err))

def send_email(mail_server, port, src, dest, sub, tls):
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

def status(sender):
    status_data = sender.hashcat_status_get_status()
    if status_data == -1:
        status_data = 'Waiting'
    return status_data

def runner(hash_file=None, hash_mode=1000,
           attack_mode=0, rules=None,
           mask=None, wordlist=None, session=None,
           outfile=None, restore=None, username=False,
           pot_path=None, show=False, brain=True,
           increment=False, increment_min=None,
           increment_max=False, speed=False, benchmark=False,
           benchmark_all=False, wordlist2=None):
    logger.info('Running hashcat')
    hc = Hashcat()
    logger.debug('Hashcat object ID: {}'.format(id(hc)))
    hc.session = session
    if benchmark:
        logger.debug('Running in benchmark mode')
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
    if wordlist2:
        hc.dict2 = wordlist2
    if mask:
        hc.mask = mask
    if speed:
        hc.speed_only = True
        hc.hashcat_session_execute()
        return hc
    if brain:
        speed_session = '{}_speed'.format(session)
        job = redis_q.fetch_job(session)
        if 'brain_check' in job.meta:
            logger.debug('Restored job already has brain check state')
            speed_job = None
            if job.meta['brain_check'] is True:
                hc.brain_client = brain
                hc.brain_client_features = 3
                ###***replace with random string
                hc.brain_password = '425dafbb8e87fe18'
                speed_job = None
            else:
                speed_job = speed_q.fetch_job(speed_session)
        else:
            speed_job = speed_q.fetch_job(speed_session)
        wait_count = 0
        if speed_job:
            while len(speed_job.meta) < 1 and wait_count < 410:
                logger.debug('RUNNER loop')
                logger.debug('Speed meta not populated, waiting...')
                if job:
                    if del_check(job):
                        return hc
                if 'failed' in speed_job.get_status():
                    crack_q = crackqueue.Queuer()
                    err_msg = crack_q.error_parser(speed_job)
                    logger.error('Speed check failed: {}'.format(err_msg))
                    if job:
                        job.meta['brain_check'] = None
                        job.save_meta()
                    raise ValueError('Aborted, speed check failed: {}'.format(err_msg))
                elif 'finished' in speed_job.get_status():
                    logger.debug('Breaking runner loop speed check job has finished')
                    if job:
                        if del_check(job):
                            return hc
                elif 'CrackQ State' in speed_job.meta:
                    if del_check(speed_job):
                        return hc
                time.sleep(5)
                wait_count += 5
                speed_job = speed_q.fetch_job(speed_session)
            logger.debug('RUNNER loop finished')
            if 'Mode Info' in speed_job.meta:
                mode_info = speed_job.meta['Mode Info']
                salts = mode_info[-1]
                speed = int(mode_info[-2])
                brain = brain_check(speed, salts)
                hc.brain_client = brain
                hc.brain_client_features = 3
                ###***replace with random string
                hc.brain_password = '425dafbb8e87fe18'
                if brain is True:
                    if job:
                        job.meta['brain_check'] = True
                        job.save_meta()
                if brain is False:
                    if job:
                        job.meta['brain_check'] = False
                        job.save_meta()
            else:
                logger.error('Speed check error, disabling brain')
                if job:
                    job.meta['brain_check'] = None
                    if not del_check(job):
                        job.meta['CrackQ State'] = 'Run/Restored'
                        job.save_meta()
        else:
            logger.error('No speed job to check')
            if job and not del_check(job):
                job.meta['CrackQ State'] = 'Run/Restored'
                job.save_meta()
    log_dir = CRACK_CONF['files']['log_dir']
    markov_file = str(valid.val_filepath(path_string=log_dir,
                                         file_string='crackq.hcstat'))
    hc.markov_hcstat2 = markov_file
    hc.custom_charset_1 = '?l?d'
    hc.custom_charset_2 = '?l?d?u'
    hc.custom_charset_3 = '?l?d?s'
    hc.custom_charset_4 = '?u?d?s'
    hc.outfile = outfile
    logger.debug('HC. Hashcat Rules: {}'.format(hc.rules))
    logger.debug('HC. Hashcat rp_files_cnt: {}'.format(hc.rp_files_cnt))
    if restore:
        hc.skip = int(restore)
    hc.hashcat_session_execute()
    speed_started = rq.registry.StartedJobRegistry(queue=speed_q)
    cur_speed = speed_started.get_job_ids()
    if len(cur_speed) > 0:
        job = redis_q.fetch_job(session)
        if job:
            if not del_check(job):
                logger.debug('Speed job running, setting new job to Paused')
                job.meta['CrackQ State'] = 'Pause'
                job.save_meta()
    return hc


def cracked_callback(sender):
    """
    Callback function to take action on hashcat signal.
    Action is to write the latest cracked hashes
    """
    logger.debug('Callback Triggered: Cracked')
    status_dict = status(sender)
    logger.debug('Hashcat status: {}'.format(status_dict))
    if CRACK_CONF['notify']:
        mail_server = CRACK_CONF['notify']['mail_server']
        mail_port = CRACK_CONF['notify']['mail_port']
        email_src = CRACK_CONF['notify']['src']
        inactive_time = CRACK_CONF['notify']['inactive_time']
        tls = CRACK_CONF['notify']['tls']
    session = sender.session
    job = redis_q.fetch_job(session)
    if job:
        if 'notify' in job.meta.keys():
            logger.debug('Sending notification')
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
                            send_email(mail_server, mail_port,
                                            email_src, user_email, sub, tls)
                            job.meta['email_count'] += 1
                            job.save()
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
        logger.debug('No job yet')
    write_result(sender)

def bench_callback(sender):
    """
    Callback function to create benchmark dictionary
    """
    logger.debug('Callback Triggered: Benchmark')
    status_dict = status(sender)
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
        bench_file = valid.val_filepath(path_string=log_dir,
                                        file_string='sys_benchmark.json')
        with open(bench_file, 'w') as bench_fh:
            logger.debug('Writing results to benchmark file')
            bench_fh.write(json.dumps(job.meta))
    else:
        logger.error('Failed to write benchmark job meta: {}'.format(session))

def finished_callback(sender):
    """
    Callback function to take action on hashcat finished signal.
    Action is to reset hashcat???
    #changed to just writing restul file for now
    """
    logger.debug('Callback Triggered: Cracking Finished')
    #status_dict = status(sender)
    if CRACK_CONF['notify']:
        mail_server = CRACK_CONF['notify']['mail_server']
        mail_port = CRACK_CONF['notify']['mail_port']
        email_src = CRACK_CONF['notify']['src']
        inactive_time = CRACK_CONF['notify']['inactive_time']
        tls = CRACK_CONF['notify']['tls']
    session = sender.session
    job = redis_q.fetch_job(session)
    if job:
        if 'notify' in job.meta.keys():
            logger.debug('Sending notification')
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
                            send_email(mail_server, mail_port,
                                            email_src, user_email, sub, tls)
                            job.meta['email_count'] += 1
                            job.save()
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
        logger.debug('No job yet')
    write_result(sender)
    if sender.benchmark:
        sender.status_reset()


def init_callback(sender):
    """
    Callback function to take action on hashcat signal.
    Action is to write the latest cracked hashes
    """
    logger.debug('Callback Triggered: Init')
    status_dict = status(sender)
    logger.debug('Hashcat status: {}'.format(status_dict))
    write_result(sender)


def warning_callback(sender):
    """
    Callback function to take action on hashcat warning event
    """
    logger.warning('Callback Triggered: WARNING')
    msg_buf = sender.hashcat_status_get_log()
    logger.warning('{}'.format(msg_buf))
    started = rq.registry.StartedJobRegistry(queue=redis_q)
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


def error_callback(sender):
    """
    Callback function to take action on hashcat error event
    """
    logger.debug('Callback Triggered: ERROR')
    msg_buf = sender.hashcat_status_get_log()
    logger.debug('{}'.format(msg_buf))
    started = rq.registry.StartedJobRegistry(queue=redis_q)
    logger.error('{}'.format(msg_buf))
    if len(started.get_job_ids()) > 0:
        session = started.get_job_ids()[0]
        logger.error('{}: {}'.format(session, msg_buf))
        job = redis_q.fetch_job(session)
        job.meta['ERROR'] = msg_buf
        job.save_meta()


def abort_callback(sender):
    """
    Callback function to take action following Hashcat aborting
    """
    logger.info('Callback Triggered: Aborted')
    event_log = sender.hashcat_status_get_log()
    raise ValueError('Aborted: {}'.format(event_log))


def any_callback(sender):
    """
    Callback function to take action following Hashcat aborting
    """
    logger.debug('Callback Triggered: Any')
    hc_state = sender.status_get_status_string()
    logger.debug('Hashcat status: {}'.format(hc_state))
    #if hc_state == 'Bypass':
    #    sender.hashcat_session_quit()
    #if hc_state == "Aborted":
    #    event_log = sender.hashcat_status_get_log()
    #    raise ValueError('Aborted: {}'.format(event_log))

def circulator(circList, entry, limit):
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


def write_result(sender):
    """
    Method to write cracking results to file in json format

    When executed, this will open the corresponding session.crack file and
    load the data into a results file with other meta data relating to the
    job

    Arguments
    ---------
    hcat_status: dict
        Hashcat status dict (from status()), containing hashcat data
        form the cracking session
    redis_con: object
        redis connection object initiated
    Returns
    -------

    """
    logger.debug('Updating status file')
    hcat_status = status(sender)
    if '_speed' in sender.session:
        session = sender.session[:-6]
    else:
        session = sender.session
    result_file = valid.val_filepath(path_string=log_dir,
                                     file_string='{}.json'.format(session))
    if 'Progress' in hcat_status:
        hcat_status['Progress'] = int(hcat_status['Progress'])
    logger.debug('Updating job metadata')
    if not sender.benchmark:
        try:
            with open(result_file, 'r+') as result_fh:
                job = redis_q.fetch_job(session)
                if job and isinstance(hcat_status, dict):
                    job.meta['HC State'] = hcat_status
                    job.meta['Speed Array'] = circulator(job.meta['Speed Array'],
                                                         int(hcat_status['Speed Raw']), 180)
                    job.save_meta()
                    job_details = cq_api.get_jobdetails(job.description)
                    job_details['restore'] = hcat_status['Restore Point']
                    if 'brain_check' in job.meta:
                        job_details['brain_check'] = job.meta['brain_check']
                else:
                    result = result_fh.read()
                    job_details = json.loads(result.strip())
                job_details['Cracked Hashes'] = sender.status_get_digests_done()
                job_details['Total Hashes'] = sender.status_get_digests_cnt()
                job_details['timeout'] = job.timeout
                result_fh.seek(0)
                result_fh.write(json.dumps(job_details))
                result_fh.truncate()
        except AttributeError as err:
            logger.debug('Status update failure: {}'.format(err))
        except KeyError as err:
            logger.debug('Status update failure: {}'.format(err))
        except UnboundLocalError as err:
            logger.debug('Status update failure: {}'.format(err))


def brain_check(speed, salts):
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


def hc_worker(crack=None, hash_file=None, session=None,
              wordlist=None, outfile=None, hash_mode=1000,
              attack_mode=None, mask=None, rules=None, name=None,
              username=False, pot_path=None, restore=None,
              brain=True, mask_file=False, increment=False,
              increment_min=None, increment_max=None, speed=True,
              benchmark=False, benchmark_all=False, wordlist2=None):
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
    #job = redis_q.fetch_job(session)
    hcat = runner(hash_file=hash_file, mask=mask,
                  session=session, wordlist=wordlist,
                  outfile=outfile, attack_mode=attack_mode,
                  hash_mode=hash_mode, rules=rules,
                  username=username, pot_path=pot_path,
                  restore=restore, brain=brain, wordlist2=wordlist2,
                  benchmark=benchmark, benchmark_all=benchmark_all)
    hcat.event_connect(callback=error_callback,
                       signal="EVENT_LOG_ERROR")
    hcat.event_connect(callback=warning_callback,
                       signal="EVENT_LOG_WARNING")
    if benchmark:
        hcat.event_connect(callback=bench_callback,
                           signal="EVENT_CRACKER_FINISHED")
        hcat.event_connect(callback=finished_callback,
                           signal="EVENT_OUTERLOOP_FINISHED")
        hcat.event_connect(callback=any_callback,
                           signal="ANY")
    else:
        hcat.event_connect(callback=finished_callback,
                           signal="EVENT_CRACKER_FINISHED")
        hcat.event_connect(callback=cracked_callback,
                           signal="EVENT_CRACKER_HASH_CRACKED")
    try:
        main_counter = 0
        while True:
            hc_state = hcat.status_get_status_string()
            logger.debug('MAIN loop')
            if hc_state == 'Exhausted' and not mask_file:
                finished_callback(hcat)
                return 'Exhausted'
            if hc_state == 'Exhausted' and mask_file:
                # workaround for mask files
                ###***this needs to be better, some cases could exit early
                sleep(30)
                if hc_state == 'Exhausted':
                    logger.info('checking mask file')
                    if hc_state == 'Exhausted':
                        finished_callback(hcat)
                        return 'Exhausted'
            elif hc_state == 'Cracked':
                cracked_callback(hcat)
                return 'Cracked'
            elif hc_state == 'Aborted':
                logger.debug('Hashcat Abort status returned')
                event_log = hcat.hashcat_status_get_log()
                raise ValueError('Aborted: {}'.format(event_log))
            elif main_counter > 2000 and hc_state != 'Running' and mask_file == False:
                logger.debug('Reseting job, seems to be hung')
                raise ValueError('Error: Hashcat hung - Initialize timeout')
            else:
                logger.debug('HC State: {}'.format(hc_state))
                if 'Initializing' not in hc_state:
                    init_callback(hcat)
                    logger.debug('Hashcat initialized')
                job = redis_q.fetch_job(str(hcat.session))
                speed_started = rq.registry.StartedJobRegistry(queue=speed_q)
                cur_speed = speed_started.get_job_ids()
                if job:
                    if job.meta['CrackQ State'] == 'Stop':
                        logger.info('Stopping Job: {}'.format(hcat.session))
                        hcat.hashcat_session_quit()
                        return
                    elif job.meta['CrackQ State'] == 'Delete':
                        logger.info('Deleting Job: {}'.format(hcat.session))
                        speed_session = '{}_speed'.format(hcat.session)
                        speed_job = speed_q.fetch_job(speed_session)
                        if speed_job:
                            logger.debug('Deleting speed job')
                            speed_status = speed_job.get_status()
                            finished_states = ['finished',
                                               'failed']
                            del_count = 0
                            while (speed_status not in finished_states
                                   and del_count < 100):
                                logger.debug('DELETE wait loop')
                                speed_status = speed_job.get_status()
                                del_count += 1
                            logger.debug('Breaking runner loop speed check job has finished')
                            speed_job.delete()
                        hcat.hashcat_session_quit()
                        hcat.reset()
                        cq_api.del_jobid(hcat.session)
                        return
                    elif job.meta['CrackQ State'] == 'Pause':
                        hcat.hashcat_session_pause()
                        pause_counter = 0
                        logger.debug('Pausing job: {}'.format(hcat.session))
                        logger.debug('PAUSE loop begin')
                        while pause_counter < 400:
                            if hcat.status_get_status_string() == 'Paused':
                                logger.info('Job Paused: {}'.format(hcat.session))
                                break
                            elif del_check(job):
                                break
                            pause_counter += 1
                        logger.debug('PAUSE loop finished')
                        if hcat.status_get_status_string() != 'Paused':
                            logger.debug('Pause failed: {}'.format(hc_state))
                        ###***below not needed?
                        if len(cur_speed) < 1:
                            if not del_check(job):
                                logger.debug('Stale paused job caught, resuming')
                                job.meta['CrackQ State'] == 'Run/Restored'
                                job.save_meta()
                                hcat.hashcat_session_resume()
                    elif hc_state == 'Bypass':
                        logger.debug('Error: Bypass not cleared')
                    else:
                        logger.debug('Haschat state: {}'.format(hc_state))
                        if len(cur_speed) < 1:
                            if not del_check(job):
                                if hcat.status_get_status_string() == 'Paused':
                                    logger.debug('Stale paused job caught, resuming')
                                    job.meta['CrackQ State'] == 'Run/Restored'
                                    job.save_meta()
                                    hcat.hashcat_session_resume()
                else:
                    logger.error('Error finding redis job')
            sleep(10)
            main_counter += 10
    except KeyboardInterrupt:
        hcat.hashcat_session_quit()
        exit(0)
    except Exception as err:
        logger.error('MAIN loop closed: {}'.format(err))


def show_speed(crack=None, hash_file=None, session=None,
               wordlist=None, hash_mode=1000, speed_session=None,
               attack_mode=None, mask=None, rules=None,
               pot_path=None, brain=False, username=False,
               name=None, wordlist2=None):
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
    started = rq.registry.StartedJobRegistry(queue=redis_q)
    cur_list = started.get_job_ids()
    speed_job = speed_q.fetch_job(speed_session)
    if len(cur_list) > 0:
        cur_job = redis_q.fetch_job(cur_list[0])
        if cur_job:
            if del_check(cur_job):
                logger.debug('Job stop already requested, not pausing')
                time.sleep(10)
            else:
                cur_job.meta['CrackQ State'] = 'Pause'
                logger.debug('Pausing active job')
                cur_job.save_meta()
        else:
            logger.debug('Failed to pause current job')
            raise ValueError('Speed check error')
    if attack_mode:
        if not isinstance(attack_mode, int):
            attack_mode = None
    # run --show first
    # clear contents of previous cracked passwords file before running show
    outfile = valid.val_filepath(path_string=log_dir,
                                 file_string='{}.cracked'.format(speed_session[:-6]))
    try:
        with open(outfile, 'w') as fh_outfile:
            fh_outfile.truncate(0)
    except FileNotFoundError:
        logger.debug('No cracked file to clear')
    # create initial json state, run show check and create file
    job_dict = {}
    job_dict['hash_mode'] = hash_mode
    job_dict['attack_mode'] = attack_mode
    job_dict['mask'] = mask
    if wordlist:
        job_dict['wordlist'] = [wl for wl, path in CRACK_CONF['wordlists'].items() if path == wordlist][0]
    if wordlist2:
        job_dict['wordlist2'] = [wl for wl, path in CRACK_CONF['wordlists'].items() if path == wordlist2][0]
    if rules:
        job_dict['rules'] = [rl for rl, path in CRACK_CONF['rules'].items() if path == rules]
    job = redis_q.fetch_job(speed_session[:-6])
    if brain:
        job_dict['brain_check'] = None
    else:
        logger.debug('Writing brain_check')
        job_dict['brain_check'] = False
        if job:
            job.meta['brain_check'] = False
            speed_job.save_meta()
    if job:
        job_dict['timeout'] = job.timeout
    job_dict['name'] = name
    job_dict['restore'] = 0
    job_dict['Cracked Hashes'] = 0
    job_dict['Total Hashes'] = 0
    write_template(job_dict, speed_session[:-6])
    hcat = runner(hash_file=hash_file, mask=mask,
                  session=speed_session, wordlist=wordlist,
                  outfile=str(outfile), attack_mode=attack_mode,
                  hash_mode=hash_mode, wordlist2=wordlist2,
                  username=username, pot_path=pot_path,
                  show=True, brain=False)
    hcat.event_connect(callback=cracked_callback,
                       signal="EVENT_POTFILE_HASH_SHOW")
    hcat.event_connect(callback=any_callback,
                       signal="ANY")
    counter = 0
    while counter < 100:
        if hcat is None or isinstance(hcat, str):
            return hcat
        hc_state = hcat.status_get_status_string()
        logger.debug('SHOW loop')
        if speed_job:
            if 'CrackQ State' in speed_job.meta:
                if del_check(speed_job):
                    break
        if hc_state == 'Running':
            break
        if hc_state == 'Paused':
            break
        elif hc_state == 'Aborted':
            event_log = hcat.hashcat_status_get_log()
            raise ValueError(event_log)
        time.sleep(1)
        counter += 1
    logger.debug('SHOW loop complete, quitting hashcat')
    hcat.hashcat_session_quit()
    hcat.reset()
    if brain:
        logger.debug('Brain not disabled by user')
        hcat = runner(hash_file=hash_file, mask=mask,
                      wordlist=wordlist, speed=True,
                      attack_mode=attack_mode,
                      hash_mode=hash_mode, rules=rules,
                      pot_path=pot_path, show=False,
                      brain=False, session=speed_session,
                      wordlist2=wordlist2)
        hcat.event_connect(callback=any_callback,
                           signal="ANY")
        mode_info = dict(hash_modes.HModes.modes_dict())[str(hash_mode)]
        logger.debug('Mode info: {}'.format(mode_info))
        salts = hcat.status_get_salts_cnt()
        logger.debug('Salts Count: {}'.format(salts))
        speed_counter = 0
        logger.debug('SPEED loop')
        while counter < 180:
            if hcat is None or isinstance(hcat, str):
                return hcat
            if 'CrackQ State' in speed_job.meta:
                if del_check(speed_job):
                    return hcat
            hc_state = hcat.status_get_status_string()
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
                    cur_job = redis_q.fetch_job(cur_list[0])
                    if cur_job:
                        if not del_check(cur_job):
                            cur_job.meta['CrackQ State'] = 'Run/Restored'
                            cur_job.save_meta()
                            logger.debug('Resuming active job: {}'.format(cur_job.id))
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
                        if del_check(job):
                            hcat.hashcat_session_quit()
                            hcat.reset()
            logger.debug('No hc_state')
            time.sleep(1)
            speed_counter += 1
        logger.debug('SPEED loop finished')
        event_log = hcat.hashcat_status_get_log()
        hcat.status_reset()
        hcat.hashcat_session_quit()
        hcat.reset()
        #job = redis_q.fetch_job(session)
        if len(cur_list) > 0:
            cur_job = redis_q.fetch_job(cur_list[0])
        else:
            cur_job = None
        if cur_job:
            if cur_job.meta['CrackQ State'] == 'Pause':
                cur_job.meta['CrackQ State'] = 'Run/Restored'
                cur_job.save_meta()
                logger.debug('Resuming active job')
        raise ValueError('Speed check error: {}'.format(event_log))
    else:
        logger.debug('Brain user-disabled')
        job = redis_q.fetch_job(session)
        if job:
            job.meta['brain_check'] = False
        if len(cur_list) > 0:
            cur_job = redis_q.fetch_job(cur_list[0])
        else:
            cur_job = None
        if cur_job:
            cur_job.meta['CrackQ State'] = 'Run/Restored'
            cur_job.save_meta()
            logger.debug('Resuming active job')
    return hc_state
