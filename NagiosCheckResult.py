#!/usr/bin/python
#
#Class that creates Nagios checkresult file and writes Passive checks to it
###########################################################################

import os
import tempfile
import time


class GenerateNagiosCheckResult:
    
    def __init__(self):
	self.return_codes = { 0 : 'OK', 1 : 'WARNING', 2 : 'CRITICAL', 3 : 'UNKNOWN' }
	

    #Creates a checkresult file
    def Create(self,nagios_result_dir):
	# Nagios is quite fussy about the filename, it must be
        # a 7 character name starting with 'c'
	tmp_file = tempfile.mkstemp(prefix='c',dir=nagios_result_dir) # specifies name and directory, check tempfile thoroughly
        self.fh = tmp_file[0]
        self.cmd_file = tmp_file[1]
        os.write(self.fh, "### Active Check Result File ###\n")
        os.write(self.fh, "file_time=" + str(int(time.time())) + "\n")
	
	
    # Writes to the checkresult file 
    def Build(self, host, service_name, last_seen, service_state, metric_value, metric_units):
	os.write(self.fh, "\n### Nagios Service Check Result ###\n")
        os.write(self.fh, "# Time: " + time.asctime() + "\n")
        os.write(self.fh, "host_name=" + host + "\n")
        os.write(self.fh, "service_description=" + service_name + "\n")
        os.write(self.fh, "check_type=0\n")
        os.write(self.fh, "check_options=0\n")
        os.write(self.fh, "scheduled_check=1\n")
        os.write(self.fh, "reschedule_check=1\n")
        os.write(self.fh, "latency=0.1\n")
        os.write(self.fh, "start_time=" + str(last_seen) + ".0\n")
        os.write(self.fh, "finish_time=" + str(last_seen) + ".0\n")
        os.write(self.fh, "early_timeout=0\n")
        os.write(self.fh, "exited_ok=1\n")
        os.write(self.fh, "return_code=" + str(service_state) + "\n")
        os.write(self.fh, "output=" + service_name + " " + self.return_codes[service_state] + "- " + service_name + " " +  str(metric_value) + " " + metric_units + "\\n\n")

    
    def Submit(self):
        os.close(self.fh)
        ok_filename = self.cmd_file + ".ok"
        ok_fh = file(ok_filename, 'a')
        ok_fh.close()

