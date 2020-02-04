#!/bin/bash

if [ '$1' == '--force' ]
        then
                echo '[+] Force enabled - creating system benchmark report'
                python3 pyhashcat/pyhashcat/benchmark.py /var/crackq/files/sys_benchmark.txt;
		exit;
        else
            echo '[+] Checking for system benchmark report. This is used for tuning' \
                 'CrackQ and the Hashcat Brain.'
fi

if [ -f '/var/crackq/files/sys_benchmark.txt' ]
	then
		echo '[+] System benchmark report already present.'
                tput bold
                echo 'All done.'
	else
		echo '[-] Benchmark report not found.'
                tput bold
                echo 'Would you like to run a system benchmark now?'
                tput sgr0
                echo 'This will take approximately 30 minutes, but only needs to be run once per system.'
                tput bold
                echo '(y/n)'
                tput sgr0
	while true
		do
			read -n 1 ans
			case $ans in 
				[Yy]* ) python3 pyhashcat/pyhashcat/benchmark.py /var/crackq/files/sys_benchmark.txt;;
				[Nn]* ) tput bold
                                        echo '[-] WARNING: Using default system benchmark settings, ' \
                                             'this will cause inaccuracies when determining if the brain ' \
                                             'should be used when running each crack job\n'
                                        echo 'It is strongly recommended that you run this'
                                        tput sgr0 
                                        echo '[+] Using example system benchmark file'
                                        cp pyhashcat/pyhashcat/sys_benchmark.example /var/crackq/files/sys_benchmark.txt 
                                        echo 'NOTE: You can run this manually by executing /opt/crackq/build/benchmark.sh --force at any time\n'
	                                exit;;
			esac
		done
fi
exit;
