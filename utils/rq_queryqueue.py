import datetime
import rq
import sys

from rq import Queue
from rq.serializers import JSONSerializer
from redis import Redis

if len(sys.argv) < 2:
    print('Usage: ./{} <queue-name>')
    exit(1)

redis_con = Redis('localhost', 6379)
redis_q = Queue(sys.argv[1], connection=redis_con,
                serializer=JSONSerializer)

base = rq.registry.BaseRegistry(sys.argv[1],
                                connection=redis_con, serializer=JSONSerializer)
started = rq.registry.StartedJobRegistry(sys.argv[1],
                                         connection=redis_con)
failed = rq.registry.FailedJobRegistry(sys.argv[1],
                                       connection=redis_con)
comp = rq.registry.FinishedJobRegistry(sys.argv[1],
                                       connection=redis_con)
comp_list = comp.get_job_ids()
cur_list = started.get_job_ids()
failed_list = failed.get_job_ids()
queue = redis_q.job_ids

print('Complete: {}'.format(comp_list))
print('Failed: {}'.format(failed_list))
print('Current: {}'.format(cur_list))
print('Queued: {}'.format(queue))
