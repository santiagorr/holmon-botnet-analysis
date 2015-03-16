#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright © 2014. Santiago Ruano Rincón <santiago.ruano-rincon@telecom-bretagne.eu>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# to use print () instead of print
from __future__ import print_function 

from sparqltools import *
from ipaddresstool import ipaddr_ntoa # with python3, ipaddress 
                                      # module could be used instead

import operator # needed to sort the ratio dictionary

import config_botnet_analysis as config

dnsIPNX = {}
dnsIPNoError = {}
dnsRatioIP = {}

tcpReports = {}

NXDOMAIN_THRESHOLD = 0.1
#ABORTED_CONN_THRESHOLD = 0
ABORTED_CONN_THRESHOLD = 200

dnsEndPointIP=config.dnsEndPointIP
dnsEndPointPort=config.dnsEndPointPort
dnsEndPointSource = dnsEndPointIP + ":" + str(dnsEndPointPort)

flowsEndPointIP=config.flowsEndPointIP
flowsEndPointPort=config.flowsEndPointPort

flowsEndPointSource = flowsEndPointIP + ":" + str(flowsEndPointPort)

dnsEndPoint = "http://" + dnsEndPointSource + "/sparql"
flowsEndPoint = "http://" + flowsEndPointSource + "/sparql"


dnsQueryPrefix = config.dnsQueryPrefix
dnsQueryNXDomain = dnsQueryPrefix + config.dnsQueryNXDomain
dnsQueryNOError = dnsQueryPrefix + config.dnsQueryNOError

flowsQueryPrefix = config.flowsQueryPrefix
flowsQuery = flowsQueryPrefix + config.flowsQuery

print ('DNS query\n')
dnsResultsNX = sparql_query(dnsEndPoint, dnsQueryNXDomain)
for result in dnsResultsNX["results"]["bindings"]:
    dnsIPNX[result["dest_addr"]["value"]] = int(result["no"]["value"])

dnsResultsNoErr = sparql_query(dnsEndPoint, dnsQueryNOError)
for result in dnsResultsNoErr["results"]["bindings"]:
    dnsIPNoError[result["dest_addr"]["value"]] = int(result["no"]["value"])

#for i in dnsIPNX.keys():
for i in dnsIPNoError.keys():
    if dnsIPNX.has_key(i):
        dnsRatioIP[i] = float(int(dnsIPNX[i]))/dnsIPNoError[i]
    else :
        dnsRatioIP[i] = 0.

# Sort by ratio, reverse.
sorted_dnsRatioIP = sorted(dnsRatioIP.iteritems(), key=operator.itemgetter(1), reverse=True)

# Print IPs and NXDomain/NoError ratios
print ("IP Address\tNXDomain/NoError ratio")
for ratio in sorted_dnsRatioIP:
    if ratio[1] >= NXDOMAIN_THRESHOLD:
        print (ipaddr_ntoa(int(ratio[0])), end="\t ")
        print (ratio[1])

print ('\nFlows query\n')

print ("IP Address\tNum. of incomplete TCP conn. requests ")

flowsResults = sparql_query(flowsEndPoint, flowsQuery)
for result in flowsResults["results"]["bindings"]:
    #tcpReports[result["srcip"]["value"]] = int(result["no"]["value"])

#for conn in tcpReports:
    #if conn[1] >= ABORTED_CONN_THRESHOLD:
        #print (ipaddr_ntoa(int(conn[0])), end="\t")
        #print (conn[1])
    print (ipaddr_ntoa(result["srcip"]["value"]), end="\t ")
    print (result["no"]["value"])

    tcpReports[result["srcip"]["value"]] = int(result["no"]["value"])


#for srcip, value in tcpReports.items():
    #print (srcip, value)
    #if i[1] >= NXDOMAIN_THRESHOLD:
        #print (ipaddr_ntoa(int(i[0])), end="\t ")
        #print (i[1])

print ('\nSummary\n')

print ("IP Address\t'Bot ratio'\tAborted TCP conn. ")

#TODO: To improve, store this into a data structure (and then print)
countHost = 0
for ratio in sorted_dnsRatioIP:
    countHost += 1
    tcpAbortConns = 0
    #if ratio[1] >= NXDOMAIN_THRESHOLD:
    if 1 == 1:
        print (countHost, end="\t")
        print (ipaddr_ntoa(int(ratio[0])), end="\t ")
        print (round(ratio[1], 3), end="\t\t ")
        if tcpReports.has_key(unicode(ratio[0])):
            tcpAbortConns = (tcpReports.__getitem__(ratio[0]))
        #else:
        #    tcpAbortConns = 0
        print (tcpAbortConns, end="\t")
        if ratio[1] >= NXDOMAIN_THRESHOLD and tcpAbortConns >= ABORTED_CONN_THRESHOLD :
            print ("SYN Flooding")
        elif ratio[1] >= NXDOMAIN_THRESHOLD :
            print ("Suspicious")
        else :
            print ("Unknown")
