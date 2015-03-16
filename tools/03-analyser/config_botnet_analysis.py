#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright © 2014. Santiago Ruano Rincón <santiago.ruano-rincon@telecom-bretagne.eu>
#

dnsEndPointIP="192.168.0.21"
dnsEndPointPort=2020

flowsEndPointIP="192.168.0.21"
flowsEndPointPort=2021

dnsQueryPrefix = """
    PREFIX holmon: <file:////home/santiago/research/PostDoc-AllInOne/botnet-dns-ipfix-scenario/DNS.owl>
    PREFIX db: <http://localhost:2020/resource/>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX holmondns: <http://localhost:2020/resource/holmondns/>
    PREFIX owl: <http://www.w3.org/2002/07/owl#>
    PREFIX map: <http://localhost:2020/resource/#>
    PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX MD: <http://www.fp7-moment.eu/Moment.owl>
"""

# To note: 
#            holmondns:DNSMessageHeader_R_code "11" .
# leads to faster queries than:
#            holmondns:DNSMessageHeader_R_code ?r_code .
#        FILTER (?r_code = "11")


dnsQueryNXDomain = dnsQueryPrefix + """
    SELECT (COUNT(DISTINCT ?instance) as ?no) ?dest_addr
    WHERE {
        ?instance a holmondns:DNSMessageHeader ;
            MD:DestinationIP ?dest_addr ;
            holmondns:DNSMessageHeader_QR_flag "1" ;
            holmondns:DNSMessageHeader_R_code "11" .
    }
    GROUP BY ?dest_addr
    ORDER BY DESC(?no)
"""


dnsQueryNOError = dnsQueryPrefix + """
    SELECT (COUNT(DISTINCT ?instance) as ?no) ?dest_addr
    WHERE {
        ?instance a holmondns:DNSMessageHeader ;
            MD:DestinationIP ?dest_addr ;
            holmondns:DNSMessageHeader_QR_flag "1" ;
            holmondns:DNSMessageHeader_R_code "0" .
    }
    GROUP BY ?dest_addr
    ORDER BY DESC(?no)
"""





flowsQueryPrefix = """
    PREFIX holmon: <file:////home/santiago/research/PostDoc-AllInOne/botnet-dns-ipfix-scenario/holmon-1.owl>
    PREFIX db: <http://localhost:2021/resource/>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX holmonflows: <http://localhost:2021/resource/holmonflows/>
    PREFIX owl: <http://www.w3.org/2002/07/owl#>
    PREFIX map: <http://localhost:2021/resource/#>
    PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX MD: <http://www.fp7-moment.eu/Moment.owl>
"""
flowsQuery = flowsQueryPrefix + """
    SELECT (COUNT(DISTINCT ?id) as ?no) ?srcip 
    WHERE {
        ?flowmsg holmonflows:flows_id ?id ;
            MD:SourceIP ?srcip ;
            holmonflows:flows_flowStartMilliseconds ?starttime ;
            holmonflows:flows_flowEndMilliseconds ?endtime . 
            FILTER ( ?starttime >= "2011-03-31T00:00:00"^^xsd:dateTime && ?endtime <= "2011-03-31T23:59:00"^^xsd:dateTime)
        ?tcpmsg holmonflows:tcp_id ?id ;
            holmonflows:tcp_initialTCPFlags "S" ;
            holmonflows:tcp_unionTCPFlags "" .
    }
    GROUP BY ?srcip
    ORDER BY DESC(?no)
"""

