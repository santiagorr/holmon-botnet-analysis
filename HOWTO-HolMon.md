How to reproduce use case: analyse botnet activity in local network
===================================================================

To detect botnets we inspect DNS packets and IPFIX reports through RDF trees.

The idea is to reproduce network traffic as if we had two heterogeneous sources
--MySQL data from PCAP and TCP info from IPFIX--, store their data in two databases and
access to them as semantic RDF trees, from a common point of view and from a
unifying ontology.

The scenario requires five functional devices, at least: one DNS probe-and-DB listening PCAP, one
IPFIX collector-and-DB, one IPFIX exporter if required, a central semantic interface, and one analyser.
You can also divide probe and DB functions in different hosts.

This can be seen from the architecture point of view:

    Analysis
        Hollistic analyser
    Semantic interface
        SPARQL endpoints: D2RQ, able to map reational DBs to RDF trees
    Probe and storage
        TCP/IPFIX:  YAF MySQL Mediator  | IPFIX Database
        DNS/PCap:   Blockmon            | DNS Database

We have tested this scenario with a saved capture set. The probes are able to
handle live traffic though.

This instructions focus on *Debian wheezy*, but it should be possible to run all
the software in different Linux flavours.

## Functional devices and their related tools

This is the list functional devices, and the software tools they rely on.

### Semantic interface

* [D2RQ](http://d2rq.org/): to map network data from relational databases to RDF
* MySQL client libraries

### DNS probe:

* Blockmon with app_dnsbotnet: our case use specific blockmon
* MySQL client and libraries: to insert data into the mysql database

### IPFIX exporter:

* [YAF (Yet Another Flowmeter)](http://tools.netsa.cert.org/yaf/) (version 2.5.0): to convert PCAP to IPFIX flow <http://tools.netsa.cert.org/yaf/>

### IPFIX collector and probe:

* [YAF SiLK MySQL Mediator](https://tools.netsa.cert.org/confluence/pages/viewpage.action?pageId=15958035) (1.4.1): to collect IPFIX flow and send it to the
  MySQL server 
<https://tools.netsa.cert.org/confluence/pages/viewpage.action?pageId=15958035>
* MySQL client and libraries: to insert data into the mysql database


## Central analysis point, relaying on D2RQ

#### Install dependencies:

You need to install unpack d2rq. d2rq needs the java
virtual machine:

    apt-get install mysql-server default-jre 

You can download d2rq from [http://d2rq.org/](http://d2rq.org/). Sources are
already built, so you just need to untar the .tar.gz.

    tar xzf d2rq-0.8.1.tar.gz

### Ontologies

In this scenario, we rely on ontologies that map the MySQL database to RDF
trees. D2RQ is in charge of this mapping, and you need to be sure he's able to
read the _ontologies_ dir from the SVN repository (or an exported version).
These ontologies are located in `$HOLMON_DIR/ontologies/holmon/`:

    holmon-mapping-dns.ttl
    holmon-mapping-flows.ttl

    DNS.owl
    IPFIX.owl
    holmon-1.owl

    sparql-query-r-code-1.sparql
    sparql-query-tcpflags-1.sparql
    sparql-query-tcpflags-2.sparql

## Databases

You will need to set up two databases for DNS and IPFIX data (for test
simplicity, they can run on the same probe host).  Create them and give
privileges to a "holmon" user, importing these SQL scripts located in
_databases/_:

Create databases:

    mysql -u root -p < holmon-flows-structure.sql
    mysql -u root -p < holmon-dns-structure.sql

Create holmon user and grant her privileges (*default password: holmon*):

    mysql -u root -p < privileges.sql

Your mysql server is ready to be used and get data from the future probes.


## DNS PCAP probe: read DNS data from PCAP and insert it into the database

Here you will build blockmon, and then, run the *app_dnsbotnet* application to
insert all the data from the PCAP files into the *holmondns* database in the
server.

### Blockmon (that includes app_dnsbotnet)

You need to build the specific blockmon included in this repository, and
configure the application usr/app_dnsbotnet/. 

#### Install dependencies:

    apt-get install build-essential \
    cmake \
    libboost-python-dev \
    python-dev \
    libprotobuf-dev \
    libpcap-dev \
    libmysqlcppconn-dev \
    libgeoip-dev \
    libidn11-dev \
    libboost-regex-dev 

**TODO: Verify that blockmon really needs libfixbuf.** You also need
*libfixbuf*, but it is not available in debian wheezy. However, you can install
the package I've build (backported for wheezy):

    cd debian/
    dpkg -i libfixbuf3_1.6.0+ds-1_amd64.deb libfixbuf3-dev_1.6.0+ds-1_amd64.deb

#### Build Blockmon

Build blockmon. You may follow the blockmon's INSTALL file, but in general, this would be enough.

    cd <blockmon dir>
    cmake -DWITH_NR_DNS_ANALYSIS=ON -DWITH_DAEMON=ON -DPYTHON_INCLUDE_DIR:PATH=/usr/include/python2.7 -DPYTHON_LIBRARY:FILEPATH=/usr/lib/x86_64-linux-gnu/libpython2.7.so .

(The . at the end is important, it means the current working directory)

    make

### Config blockmon.

Configure daemon. Use your preferred editor to set the blockmon's directory in bm_basepath (and MAIN section) in daemon/config. E.g.:

    bm_basepath = /usr/local/blockmon-dns-botnet

Configure the app_dnsbotnet application. A default scenario file is found in *usr/app_dnsbotnet/botnetanalysis.xml*. You will need to:

1. Configure PacketFilter blocks to listen DNS traffic only

You need two PacketFilter blocks to filter traffic incoming to and outgoing from
the DNS servers.

      <block id="filter" type="PacketFilter" invocation="direct"> 
        <params>
          <l3_protocol number="2048">
            <filter_mode behavior="accept"/>
          </l3_protocol>
          <!-- UDP -->
          <l4_protocol number="17">
            <filter_mode behavior="accept"/>
          </l4_protocol>
          <src_port number='53'>
            <filter_mode behavior='accept'/>
          </src_port>
        </params>
      </block>

      <block id="filterDst" type="PacketFilter" invocation="direct"> 
        <params>
          <l3_protocol number="2048">
            <filter_mode behavior="accept"/>
          </l3_protocol>
          <l4_protocol number="17">
            <filter_mode behavior="accept"/>
          </l4_protocol>
          <dst_port number='53'>
            <filter_mode behavior='accept'/>
          </dst_port>
        </params>
      </block>

2. Configure the DNSBotMapper block and how it must access the database:

        <block id="botmapper" type="DNSBotMapper" invocation="direct">
          <params>
            <db_name val = "holmondns" />
            <db_ip val = "localhost"/>
            <db_user val = "holmon"/>
            <db_passwd val = "holmon"/>
          </params>
        </block>

3. Configure the PcapSource (capture source).

If listening from a network interface (such as eth0). This would be the
configuration in a working environment:

        <block id="src" type="PcapSource" invocation="async" threadpool="src_thread">
          <params>
              <source type='live' name='eth0'/>
          </params>
        </block>

But, **for simplicity to reproduce this case use**, you can read **capture file(s)
**:

        <block id="src" type="PcapSource" invocation="async" threadpool="src_thread">
          <params>
              <source type='trace' name='path-to-capture.pcap' />
          </params>
        </block>

4. Connect the blocks

You need to connect the different filters and botmapper:

      <connection src_block="src" src_gate="source_out" dst_block="filter" dst_gate="in_pkt"/>
      <connection src_block="src" src_gate="source_out" dst_block="filterDst" dst_gate="in_pkt"/>
      <connection src_block="filter" src_gate="out_pkt" dst_block="botmapper" dst_gate="in_msg"/>
      <connection src_block="filterDst" src_gate="out_pkt" dst_block="botmapper" dst_gate="in_msg"/>


### Run Blockmon (usr/app_dnsbotnet) to insert DNS data into the database

Run the blockomon CLI (Command-line interface):

    cd daemon/
    sudo python cli.py

If everything is Ok, blockmon registers blocks existing in its current directory, and then, will
prompt the user with *BM shell*:


    BlockFactory: registering block CDFGenerator
    BlockFactory: registering block PacketOrFlowToObservation
    BlockFactory: registering block CDFGenerator
    BlockFactory: registering block FlowCounter
    BlockFactory: registering block FlowPrinter
    BlockFactory: registering block SerExporter 
    ...
    BlockFactory: registering block DNSBotMappingFilter
    BlockFactory: registering block DNSBotMapper
    ...
    BM shell:

In the blockmon console, run the application, reading the application file (e.g. the default botnetanalysis.xml):

    BM shell:start ../usr/app_dnsbotnet/botnetanalysis.xml

If blockmon is configured to read capture files, it will output something like this when it has finished to processed them:

    src warn    trace at EOF
    src warn    trace at EOF
    src warn    trace at EOF
    ...

Then, you can stop the application and quit blockmon with the `stop` and `exit`
commands.

    BM shell:stop
    ...
    BM shell:exit 

If everything went Ok (as it should be!), all the DNS data must be stored in the mysql database now.

### Test the DNS database

Change to the MySQL server and test the database:

    echo "SELECT * FROM DNSMessageHeader LIMIT 10 " | mysql -u holmon -p holmondns

Enter the password (default: holmon), and it should output the first 10 rows of
the most relevant database table (DNSMessageHeader.)


## Insert TCP info from IPFIX flow into the database

The IPFIX probe relays mainly on the *YAF MySQL Mediator* to collect IPFIX flow
and insert the data related to TCP (especially flags) into the SQL databases.

As well, if you do not count with an IPFIX exporter, you will needed to convert the PCAP files
sources into IPFIX (flow or files) using the YAF tool. 

Here you will build yaf and yaf_silk_mysql_mediator and insert the IPFIX data
into the *holmondflows* database. 

### YAF exporter and YAF MySQL Mediator

To simplify, we are going to install the same dependencies for both, IPFIX
exporter (YAF) and IPFIX collector-MySQL-mediator.

#### Install dependencies

    apt-get install cmake \
    libmysqlclient-dev \
    libglib2.0-dev \
    automake \
    autoconf \

You also need *libfixbuf*, but it is not available in debian wheezy. However, you can install the package I've build (backported for wheezy):

    cd debian/
    dpkg -i libfixbuf3_1.6.0+ds-1_amd64.deb libfixbuf3-dev_1.6.0+ds-1_amd64.deb

#### Build YAF (IPFIX exporter)

If you do not count with an IPFIX exporter, you will need a tool such as YAF. It builds through a standard procedure. Copy the sources to a work directory
and then:

    tar xzf yaf-2.5.0.tar.gz
    cd yaf-2.5.0/
    ./configure
    make
    make install

#### Build YAF MySQL Mediator

You can build yaf silk mysql mediator by a standard procedure (./configure &&
make) or by running *cmake*. Copy the mediator sources into a work directory
and: 


    tar xzf yaf_silk_mysql_mediator-1.4.1.tar.gz
    cd yaf_silk_mysql_mediator-1.4.1/
    cmake .
    make

### Collect reports and insert the TCP data into the database

#### Export IPFIX flow from a PCAP source

Again, if you lack an IPFIX exporter, you can use YAF. If you want to read a PCAP
file and create an IPFIX file:

    yaf --in $CAPTURES_DIR/capture0.pcap --out /tmp/capture0.ipfix --verbose

Or, to export IPFIX to a collector:

    yaf --in $CAPTURES_DIR/*.pcap --out $IPFIX_COLLECTOR_IP --ipfix-port 18000 --ipfix tcp --verbose
    [2014-05-20 09:10:49] yaf starting
    ...

YAF can also listen "live" traffic from a network interface (`--in eth0`).
You can find more information in the YAF man page, or in <http://tools.netsa.cert.org/yaf/yaf.html>

#### Insert flow data into the holmonflows database

If you have stored the IPFIX flow in a file:

    ./yaf_silk_mysql_mediator --in-file /tmp/capture0.ipfix --mysql-host localhost --name holmon --pass holmon --database holmonflows

If you want to collect the flow from the network (i.e. from YAF):

    ./yaf_silk_mysql_mediator --in-port 18000 --in-host $IPFIX_EXPORTER_IP --mysql-host localhost --name holmon --pass holmon --database holmonflows

It will output some stats:

    ----------OPTIONS - STATS----------
    Exported Flow Count is 83036
    Packet Total Count is 418746
    Dropped Packets 0
    Ignored Packets 9030
    Expired Fragment Count 0
    Assembled Fragment Count 0
    FlowTable Flush Events 541
    FlowTable Peak Count 15517
    Exporter IPv4 Address XXXX
    Exporting Process ID 0
    Mean Flow Rate 272
    Mean Packet Rate 1371
    ...
    *** Processed 160110 Flows ***
    *** Exported 0 Flows to SiLK ***
    *** Imported 160110 Flow to the MySQL Database ***
    *** Processed 2 Stats Records ***


More information in <https://tools.netsa.cert.org/confluence/pages/viewpage.action?pageId=15958035>

### Test the flows database

Change to the MySQL server and query the database:

    santiago@holmon:~$ echo "SELECT * FROM tcp LIMIT 10 " | mysql -u holmon -p holmonflows

## Access the data as a RDF semantic tree.

### D2RQ

As already explained, D2RQ makes it possible to access relational databases as
Resource Description Framework (RDF) graphs. Here, you have to run **two** d2rq
servers to access both dns and flows sparql endpoints. They will listen in port
2020 and 2021 respectively.

#### DNS mapping

    ./d2r-server --port 2020 --fast $HOLMON_DIR/ontologies/holmon/holmon-mapping-dns.ttl &

#### Flows mapping

    ./d2r-server --port 2021 --fast $HOLMON_DIR/ontologies/holmon/holmon-mapping-flows.ttl &

Now the system is ready to process SPARQL queries. Please, read the
documentation from <http://d2rq.org/>. You can query the D2RQ servers through
the "AJAX-based SPARQL explorer" (i.e. <http://192.168.0.21:2020/snorql/>) or
you can use a SPARQL client to query the endpoints <http://192.168.0.21:2020/sparql>.

**NOTE:** The d2r-server increases its speed x10 (in average) if it is called with
**--fast**. 

### Query the SPARQL endpoint

As I have explained, the semantic tools used here make it possible to
access data through a high and common conceptual level. In the scope of our case
use, we require to compare two different kinds of data.


#### DNS queries to calculate NXDomain/NoError per host ratios

First, we analyse DNS traffic, paying attention to the answers codes that each
client receives. We aim at comparing the number of "valid" requests
(corresponding to NOERROR answers) and the number of requests with Non-existing
domain (NXDomain answers), related to the search of a `C&C` or botnet rendezvous
point. We can translate a basic example into SPARQL like follows. 

Query the number of answers (QR_flag field in the DNS header = 1) for each
destination host (MD:DestinationIP) where the response code (R_code) represents
NOERROR (0)

    (Omiting PREFIX)

    SELECT (COUNT(DISTINCT ?instance) as ?no) ?dest_addr
    WHERE {
        ?instance a holmondns:DNSMessageHeader ;
            MD:DestinationIP ?dest_addr ;
            holmondns:DNSMessageHeader_QR_flag "1" ;
            holmondns:DNSMessageHeader_R_code "0" .
    }
    GROUP BY ?dest_addr
    ORDER BY ?dest_addr

**NOTE**: IP addresses are stored in "network numeric value". You have to
translate it to dots-and-numbers notation.
    
And then, query the number of answers for each destination host  where the
response code (R_code) represents NXDomain (11)

    SELECT (COUNT(DISTINCT ?instance) as ?no) ?dest_addr
    WHERE {
        ?instance a holmondns:DNSMessageHeader ;
            MD:DestinationIP ?dest_addr ;
            holmondns:DNSMessageHeader_QR_flag "1" ;
            holmondns:DNSMessageHeader_R_code "11" .
    }
    GROUP BY ?dest_addr
    ORDER BY ?dest_addr

You can copy theses queries in the D2RQ's SPARQL web explorer
<http://192.168.0.21:2020/snorql/> or you can use `d2r-query` that comes with
D2RQ. 

As I show below, I'll use python to access the SPARQL endpoint and
calculate the NXDomain/NoError ratio.

#### IPFIX queries to calculate the volume of abandoned TCP sessions requests

Second, we analyse IPFIX data, and more specifically TCP information, looking
for traces of TCP SYN-flood. This means, looking for incomplete (abandoned) TCP sessions. Using the same language (SPARQL) and concepts:

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


## Analyse both sources through an external tool

In the tools/03-analyser directory, you can find
`query-botnet-traffic.py`. You will need some dependencies:

    apt-get install python-sparqlwrapper

Open the script and configure the IP addresses and
ports of the SPARQL endpoints. Run the script:

    python query-roman-conficker

And you should get an output like this:

    DNS query

    IP Address	NXDomain/NoError ratio
    ...         ....

    Flows query

    IP Address	Num. of incomplete TCP conn. requests 
    ...     ...
        
The script calculates the NXDomain/NoError ratio according to the results of the
queries shown above. 

The second data set represents the number of incomplete TCP connection requests
per hosts. You can observe that the four hypothetical bots are found among the
highest sources of TCP only-SYN connections.


Appendix
========

A. Some problems building blockmon
----------------------------------

If you find messages such as:

    messages/../usr/app_nranalysis/blocks/ticket_dns.pb.h:17:2: error: #error This file was generated by an older version of protoc which is
     #error This file was generated by an older version of protoc which is
      ^
    /home/santiago/Escritorio/borrar-sin-piedad/blockmon-dns-botnet/messages/../usr/app_nranalysis/blocks/ticket_dns.pb.h:18:2: error: #error incompatible with your Protocol Buffer headers. Please
     #error incompatible with your Protocol Buffer headers.  Please
      ^
    /home/santiago/Escritorio/borrar-sin-piedad/blockmon-dns-botnet/messages/../usr/app_nranalysis/blocks/ticket_dns.pb.h:19:2: error: #error regenerate this file with a newer version of protoc.
     #error regenerate this file with a newer version of protoc.
    ...

It means that you need to regenerate the proto headers:

    apt-get install protobuf-compiler
    protoc --proto_path=/home/santiago/holmon/ /home/santiago/holmon/ticket_dns.proto --cpp_out=<path_to_DNSParser_dir>

<!---
# vim: set spell spelllang=en tw=80 :
-->
