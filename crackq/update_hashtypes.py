"""
script to update/create reference dictionary containing all hashcat hash modes
"""
#!/usr/bin/env python
import json
#import sys
from time import sleep
from pyhashcat import Hashcat

bench_dict = {}
finished = False
hc = Hashcat()
hc.hwmon_disable = True
hc.usage = True
hc.left = False
hc.logfile_disable = True
hc.spin_damp = 0
hc.potfile_disable = True
hc.show = False
hc.session = 'usage'
# Using backend_info at the moment as a small hack to get
# usage only with out full hc execution
hc.backend_info = True
hc.quiet = True

print("[+] Running hashcat")
if hc.hashcat_session_execute() >= 0:
    hashm_dict = hc.hashcat_list_hashmodes()
    if isinstance(hashm_dict, dict):
        print('[+] Hashmodes list gathered')

bench_file = '/var/crackq/files/sys_benchmark.txt'
print('[+] Reading System Benchmark Report from {}'.format(bench_file))
with open(bench_file, 'r') as fh_bench:
    bench_dict = json.loads(fh_bench.read())

print('[+] Updating Hash Modes dictionary')
missing_list = []
for k in hashm_dict:
    try:
        hashm_dict[k].append(bench_dict[str(k).strip()])
    except KeyError:
        missing_list.append(k)
if len(missing_list) > 0:
    print('[-] Some supported hash types are missing from system benchmarks')
    print('[+] The following are missing:\n{}'.format(missing_list))
    #print('[+] Adding {} missing benchmarks individually, please'
    #      'wait'.format(len(missing_list)))
print(hashm_dict)

hashm_file = '/var/crackq/files/hashm_dict.json'
print('[+] Writing dicitonary to file: {}'.format(hashm_file))
with open(hashm_file, 'w') as fh_hashm:
    fh_hashm.write(json.dumps(hashm_dict))
print('[+] Done')
