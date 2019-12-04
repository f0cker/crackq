import datetime
import rq
import sys

from rq import use_connection, Queue
from redis import Redis

if len(sys.argv) < 2:
    print('Usage: ./{} <queue-name> <job_id>')
    exit(1)

redis_con = Redis('redis', 6379)
redis_q = Queue(sys.argv[1], connection=redis_con)

job = redis_q.fetch_job(sys.argv[2])

print('Description: {}'.format(job.description))
print('Result: {}'.format(job.result))
print('Execution info: {}'.format(job.exc_info))
print('Meta {}'.format(job.meta))
