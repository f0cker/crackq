import datetime
import rq
import sys

from rq import Queue
from redis import Redis

if len(sys.argv) < 2:
    print('Usage: ./{} <queue-name>')
    exit(1)

redis_con = Redis('redis', 6379)
redis_q = Queue(sys.argv[1], connection=redis_con)

class TestClass():

    def test_func(text):
        with open('/tmp/test_add.txt', 'w') as test_file:
            test_file.write(text)

testclass = TestClass()


redis_q.enqueue(testclass.test_func, 'test')
