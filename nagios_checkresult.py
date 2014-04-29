#!/usr/bin/python
#
# NagiosCheckResult- Class that creates Nagios checkresult file and 
# writes Passive checks to it
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


class GenerateNagiosCheckResult:
    
    def __init__(self):
	self.return_codes = {0: 'OK', 1: 'WARNING', 2: 'CRITICAL', 3: 'UNKNOWN'}

    #Creates a checkresult file
    def create(self, nagios_result_dir):
	# Nagios is quite fussy about the filename, it must be
        # a 7 character name starting with 'c'
	tmp_file = tempfile.mkstemp(prefix='c',dir=nagios_result_dir) # specifies name and directory, check tempfile thoroughly
        self.fh = tmp_file[0]
        self.cmd_file = tmp_file[1]
        os.write(self.fh, "### Active Check Result File ###\n")
        os.write(self.fh, "file_time=" + str(int(time.time())) + "\n")
	
    # Writes to the checkresult file 
    def build(self, host, service_name, last_seen, service_state, metric_value, metric_units):
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

    def submit(self):
        os.close(self.fh)
        ok_filename = self.cmd_file + ".ok"
        ok_fh = file(ok_filename, 'a')
        ok_fh.close()

