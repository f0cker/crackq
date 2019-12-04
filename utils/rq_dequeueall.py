import rq
import sys

from rq import use_connection, Queue
from redis import Redis

redis_con = Redis('redis', 6379)
redis_q = Queue(connection=redis_con)


started = rq.registry.StartedJobRegistry('default',
                                         connection=redis_con)
failed = rq.registry.FailedJobRegistry('default',
                                       connection=redis_con)
comp = rq.registry.FinishedJobRegistry('default',
                                       connection=redis_con)
comp_list = comp.get_job_ids()
cur_list = started.get_job_ids()

job_id = sys.argv[1]
#job_id = '31d91dbde1c24e60a2c0e439a4ec43c3'
#job_id = '742714c1e70c4ba3a833dde4472ebbbc'

job = redis_q.fetch_job(job_id)
#comp.cleanup()
#comp.remove(job)
print(dir(job))
print(job.ttl)
job.set_status('finished')
job.save()
comp.add(job, -1)
job.cleanup(-1)
comp_list = comp.get_job_ids()

print(comp_list)
Queue.dequeue_any(redis_q, None, connection=redis_con)

#job = redis_q.fetch_job(job_id)
#print(job)





