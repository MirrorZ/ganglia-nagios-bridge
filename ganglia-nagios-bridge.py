#!/usr/bin/python
#
# ganglia-nagios-bridge - transfer Ganglia XML to Nagios checkresults file
#
# Project page:  http://danielpocock.com/ganglia-nagios-bridge
#
# Copyright (C) 2010 Daniel Pocock http://danielpocock.com
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
############################################################################

import argparse
import re
import socket
import xml.sax
import nagios_checkresult

# wrapper class so that the SAX parser can process data from a network
# socket
class SocketInputSource:
    def __init__(self, socket):
        self.socket = socket
	
    def getByteStream(self):
        return self
	
    def read(self, buf_size):
        return self.socket.recv(buf_size)


# interprets metric values to generate service return codes
class PassiveGenerator:
    def __init__(self, force_dmax, tmax_grace):
        self.force_dmax = force_dmax
        self.tmax_grace = tmax_grace
        
    def process(self, metric_def, metric_value, metric_tn, metric_tmax, metric_dmax):
        effective_dmax = metric_dmax
        if(self.force_dmax > 0):
            effective_dmax = force_dmax
        effective_tmax = metric_tmax + self.tmax_grace
        if effective_dmax > 0 and metric_tn > effective_dmax:
            service_return_code = 3
        elif metric_tn > effective_tmax:
            service_return_code = 3
        elif isinstance(metric_value, str):
            service_return_code = 0
        elif 'crit_below' in metric_def and  metric_value < metric_def['crit_below']:
            service_return_code = 2
        elif 'warn_below' in metric_def and metric_value < metric_def['warn_below']:
	    service_return_code = 1
        elif 'crit_above' in metric_def and metric_value > metric_def['crit_above']:
            service_return_code = 2
        elif 'warn_above' in metric_def and metric_value > metric_def['warn_above']:
            service_return_code = 1
        else:
            service_return_code = 0
	return service_return_code
      

# SAX event handler for parsing the Ganglia XML stream
class GangliaHandler(xml.sax.ContentHandler):
    def __init__(self, clusters_c, value_handler, checkresult_file_handler):
        self.clusters_c = clusters_c
        self.value_handler = value_handler
	self.checkresult_file_handler = checkresult_file_handler
        self.clusters_cache = {}
        self.hosts_cache = {}
        self.metrics_cache = {}

    def startElement(self, name, attrs):

        # METRIC is the most common element, it is handled first,
        # followed by HOST and CLUSTER

        # handle common elements that we ignore
        if name == "EXTRA_ELEMENT":
            return
        if name == "EXTRA_DATA":
            return

        # handle a METRIC element in the XML
        if name == "METRIC" and self.metrics is not None:
            metric_name = attrs['NAME']
            cache_key = (self.cluster_idx, self.host_idx, metric_name)
            if cache_key in self.metrics_cache:
                metric_info = self.metrics_cache[cache_key]
                self.metric_idx = metric_info[0]
                service_name = metric_info[1]
                self.metric = self.clusters_c[self.cluster_idx][1][self.host_idx][1][self.metric_idx][1]
                self.handle_metric(metric_name, service_name, attrs)
                return
            for idx, metric_def in enumerate(self.metrics):
                match_result = metric_def[0].match(metric_name)
                if match_result:
                    service_name_tmpl = metric_def[1]['service_name']
                    if len(match_result.groups()) > 0:
                        service_name = match_result.expand(service_name_tmpl)
                    else:
                        service_name = service_name_tmpl
                    self.metrics_cache[cache_key] = (idx, service_name)
                    self.metric = metric_def[1]
                    self.handle_metric(metric_name, service_name, attrs)
                    return

        # handle a HOST element in the XML
        if name == "HOST" and self.hosts is not None:
            self.metrics = None
            self.host_name = attrs['NAME']
            self.host_reported = long(attrs['REPORTED'])
            if strip_domains:
                self.host_name = self.host_name.partition('.')[0]
            cache_key = (self.cluster_idx, self.host_name)
            if cache_key in self.hosts_cache:
                self.host_idx = self.hosts_cache[cache_key]
                self.metrics = self.clusters_c[self.cluster_idx][1][self.host_idx][1]
		self.handle_host(host_name, attrs)
                return
            for idx, host_def in enumerate(self.hosts):
                if host_def[0].match(self.host_name):
                    self.hosts_cache[cache_key] = idx
                    self.host_idx = idx
                    self.metrics = host_def[1]
		    self.handle_host(self.host_name, attrs)
                    return

        # handle a CLUSTER element in the XML
        if name == "CLUSTER":
            self.hosts = None
            self.cluster_name = attrs['NAME']
            self.cluster_localtime = long(attrs['LOCALTIME'])
            if self.cluster_name in self.clusters_cache:
                self.cluster_idx = self.clusters_cache[self.cluster_name]
                self.hosts = self.clusters_c[self.cluster_idx][1]
                return
            for idx, cluster_def in enumerate(self.clusters_c):
                if cluster_def[0].match(self.cluster_name):
                    self.clusters_cache[self.cluster_name] = idx
                    self.cluster_idx = idx
                    self.hosts = cluster_def[1]
                    return

    # checks the state of host by comaring tmax and tn for the host
    def handle_host(self, host_name, attrs):
        host_tn = int(attrs['TN'])
	host_tmax = int(attrs['TMAX'])
	host_last_seen = self.cluster_localtime - host_tn
	if host_tn > host_tmax*4 :
	    host_return_code = 1	#host down
	else:
	    host_return_code = 0	#host up
	# write host checks to Nagios checkresult file
	self.checkresult_file_handler.build_host(self.host_name, host_last_seen, host_return_code)

    def handle_metric(self, metric_name, service_name, attrs):
        # extract the metric attributes
        metric_value_raw = attrs['VAL']
        metric_tn = int(attrs['TN'])
        metric_tmax = int(attrs['TMAX'])
        metric_dmax = int(attrs['DMAX'])
        metric_type = attrs['TYPE']
	metric_units = attrs['UNITS']
        # the metric_value has a dynamic type:
        if metric_type == 'string':
            metric_value = metric_value_raw
        elif metric_type == 'double' or metric_type == 'float':
            metric_value = float(metric_value_raw)
        else:
            metric_value = int(metric_value_raw)
        service_last_seen = self.cluster_localtime - metric_tn
	
	#setting service return code as 0 by default
	service_return_code=0
        # call the handler to process the value and return service state after comparing metric value and threshold:
        service_return_code = self.value_handler.process(self.metric, metric_value, metric_tn, metric_tmax, metric_dmax)
	# write Passive service checks to checkresult file
	self.checkresult_file_handler.build_service(self.host_name, service_name, service_last_seen, service_return_code, metric_value, metric_units)

    
	
# main program code
if __name__ == '__main__':
    try:
        # parse command line
        parser = argparse.ArgumentParser(description='read Ganglia XML and generate Nagios check results file')
        parser.add_argument('config_file', nargs='?',
            help='configuration file', default='/etc/ganglia/nagios-bridge.conf')
        args = parser.parse_args()

        # read the configuration file, setting some defaults first
        force_dmax = 0
        tmax_grace = 60
        execfile(args.config_file)

        # compile the regular expressions
        clusters_c = []
        for cluster_def in clusters:
            cluster_c = re.compile(cluster_def[0])
            hosts = []
            for host_def in cluster_def[1]:
                host_c = re.compile(host_def[0])
                metrics = []
                for metric_def in host_def[1]:
                    metric_c = re.compile(metric_def[0])
                    metrics.append((metric_c, metric_def[1]))
                hosts.append((host_c, metrics))
            clusters_c.append((cluster_c, hosts))

        # connect to the gmetad or gmond
        sock = socket.create_connection((gmetad_host, gmetad_port))
        # set up the SAX parser
        parser = xml.sax.make_parser()
        pg = PassiveGenerator(force_dmax, tmax_grace)
	#Instantiate GenerateNagiosCheckResult class
	gn = nagios_checkresult.GenerateNagiosCheckResult()
	#Create CheckResultFile
	gn.create(nagios_result_dir)
        parser.setContentHandler(GangliaHandler(clusters_c, pg,gn))
        # run the main program loop
        parser.parse(SocketInputSource(sock))
	
        # write out for Nagios
        gn.submit()

        # all done
        sock.close()
    except socket.error as e:
        logging.warn('Failed to connect to gmetad: %s', e.strerror)


