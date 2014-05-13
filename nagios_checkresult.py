#!/usr/bin/python
#
# NagiosCheckResult- Class that creates Nagios checkresult file and 
# writes Passive Host and Service checks to it
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###########################################################################

import os
import tempfile
import time
import sys


class GenerateNagiosCheckResult:
    
    def __init__(self):
	self.service_state = {0: 'OK', 1: 'WARNING', 2: 'CRITICAL', 3: 'UNKNOWN'}
	self.host_state = {0: 'UP', 1: 'DOWN', 2: 'DOWN', 3: 'DOWN'}

    # Creates a checkresult file
    def create(self, nagios_result_dir):
	# Nagios is quite fussy about the filename, it must be
        # a 7 character name starting with 'c'
	try:
		tmp_file = tempfile.mkstemp(prefix='c',dir=nagios_result_dir) # specifies name and directory, check tempfile thoroughly
		self.fh = tmp_file[0]
        	self.cmd_file = tmp_file[1]
        	os.write(self.fh, "### Active Check Result File ###\n")
        	os.write(self.fh, "file_time=" + str(int(time.time())) + "\n")
	except OSError as e:
    		#print "OS error({0}): {1}".format(e.errno, e.strerror)
		print "Failed to create tempfile at", nagios_result_dir
		sys.exit(1)
        
    # Accepts host name, last seen time and return code for the host checkresult
    # Writes host checks to checkresult file
    def build_host(self, host, last_seen, host_return_code):
	os.write(self.fh, "\n### Nagios Host Check Result ###\n")
        os.write(self.fh, "# Time: " + time.asctime() + "\n")
        os.write(self.fh, "host_name=" + host + "\n")
        os.write(self.fh, "check_type=0\n")
        os.write(self.fh, "check_options=0\n")
        os.write(self.fh, "scheduled_check=1\n")
        os.write(self.fh, "reschedule_check=1\n")
        os.write(self.fh, "latency=0.1\n")
        os.write(self.fh, "start_time=" + str(last_seen) + ".0\n")
        os.write(self.fh, "finish_time=" + str(last_seen) + ".0\n")
        os.write(self.fh, "early_timeout=0\n")
        os.write(self.fh, "exited_ok=1\n")
        os.write(self.fh, "return_code=" + str(host_return_code) + "\n")
	os.write(self.fh, "output=" + " " + "Host (" + host + ")" + self.host_state[host_return_code] + "\\n\n")
   
    # Accepts host name, service name, last seen time, metric values and units and return code for the service checkresult
    # Writes service checks to the checkresult file 
    def build_service(self, host, service_name, last_seen, service_return_code, metric_value, metric_units):
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
        os.write(self.fh, "return_code=" + str(service_return_code) + "\n")
        os.write(self.fh, "output=" + service_name + " " + self.service_state[service_return_code] + "- " + service_name + " " +  str(metric_value) + " " + metric_units + "\\n\n")

    # Close the file handle and create an ok-to-go indicator file 
    def submit(self):
        os.close(self.fh)
        ok_filename = self.cmd_file + ".ok"
        ok_fh = file(ok_filename, 'a')
        ok_fh.close()

