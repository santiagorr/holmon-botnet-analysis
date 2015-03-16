To enable compilation of NoError DNS Analysis Application you need to add this
additional flag to cmake:

	cmake -DWITH_NR_DNS_ANALYSIS=ON

In order to *compile* this application requires the following libraries to be 
installed:

*libgeoip
*libidn11
*libmysqlcppconn
*libprotobuf
*libboost-regex-dev

On an Debian/Ubuntu system this can be done via: 

sudo apt-get install libgeoip-dev
sudo apt-get install libidn11-dev
sudo apt-get install libmysqlcppconn-dev
sudo apt-get install libprotobuf-dev
sudo apt-get install libboost-regex-dev

In order to *run* the application, you need to specify the path, in the block
configuration, to the following files:

 - tld_names_file => "effective_tld_names.dat": which contains a list on all
   the available Top Level Domain (get it using: wget
   'http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1'
   -O effective_tld_names.dat)
 - geoip_file => "GeoIPASNum.dat": which is required to know to which
   Autonomous System each IP belong (available at:
   http://www.maxmind.com/en/asnum)

 - geo_city_file => "GeoLiteCity.dat": which is required to know the geographical position
   of IP addresses (available at: http://geolite.maxmind.com/download/geoip/database/ )


You can start with the sample XML configuration in nranalysis.xml.

For using the DNSAggregator block that extracts overall statistics about the
DNS traffic, the following additional steps are required:

*** sudo apt-get install protobuf-compiler python-protobuf python-mysqldb

1. Setup a MySQL database to store the DNS statistics:
    Run "mysql -u root":

    create database nranalysis;
    grant usage on nranalysis.* to nranalysisuser@'%' identified by
    'my_password';
    grant all privileges on nranalysis.* to nranalysisuser@'%';

2. Setup the Python-based database broker:
    cd broker/dns_statistics_proto
    protoc --python_out=. dns_analysis_results.proto
    protoc --python_out=. dns_statistics.proto

3. Edit broker/write_db_part.py and set host, user, passwd, cn_db (=database
name) in the open_db function

4. Run two instances of the broker, one for collecting and storing the DNS
statistics, one for updating the stored records with detection scores:
    python broker.py --collect
    python broker.py --update

5. Edit nranalysis_plus_aggregation.xml, and run it.




Here it is a detailed description of the parameters to be set per each of the
main blocks:

*DNSMappingFilter*

-table_memory val => [required]
Specifies the filter memory. Is the interval in seconds during which the same
Domain:IP mapping will be passed to the following procession only once. 

-time_bin_complete_flush val => [required]
At the end of the period specified by this parameter the table that stores the
Domain:IP mappings will be completely flushed. In order to be coherent with the
definition this needs to be set to a value higher than "table_memory".

*DNSMappingAggregator*

-time_bin_aggregation val => [required] 
Set the periodicity of the "Aggregation period" in seconds.  At the end of each
of this period a list of domains and statistics will be printed to output.

-time_bin_printout => [required]
specifies the periodicity (in ѕeconds) for printing the current timestamp to
standard output.

-query_threshold val => [required]
The minimum number of DNS responses that a certain domain need to have observed
in order to be displayed in the output.

-enable_txt_output val => [required]
To enable/disable txt output

-output_file_prefix val => [required if enable_txt_output = "true"]
If enable_txt_output = "true", this specify the path and the prefix of
the file to output on. At the and of the aggregation period a new file name
will be used, with the following syntax:
	output_file_prefix + _ + current_timestamp

-enable_socket_output val => [required]
To enable/disable the output on a remote database with via a socket.

-server_ip val => [required if enable_socket_output = "true"]
If enable_socket_output = "true", this specify the ip of the remote db.

-server_port val => [required if enable_socket_output = "true"]
If enable_socket_output = "true", this specify the tcp port to be used to
connect with the remote db.

-enable_vis_buffer_output val => [required]
To enable/disable the output on the visualization buffer, in order to use the
visualization GUI.

-db_name val => [required if enable_vis_buffer_output = "true"]
If enable_vis_buffer_output = "true", this specify the name of the db.

-db_ip val => [required if enable_vis_buffer_output = "true"]
If enable_vis_buffer_output = "true", this specify the ip of the db.

-db_user val => [required if enable_vis_buffer_output = "true"]
If enable_vis_buffer_output = "true", this specify the user of the db.

-db_passwd val => [required if enable_vis_buffer_output = "true"]
If enable_vis_buffer_output = "true", this specify the passwd of the db.

*DNSMappingAnalyzer*

some *terminology* for the following

the DNSMap is the model we build from DNS name-to-IP mappings. it contains
IPBlocks, which have a start and an end IP address, and contain domains mapping
to them. These domains are clustered based on how similar they are. 

-time_bin_merge val => [required]
How often do we try to merge IPBlocks.  merging saves memory as less space is
needed to store duplicate domains at neighboring IPs/IPranges.

-time_bin_cleanup val => [required] 
How often do we split and remove unused domains/IPs from the DNSMap. Splitting
avoids that we consider two neighboring IPs/IPranges similar, just because they
were similar *once*.

-time_bin_printout => [required]
Specifies the periodicity for printing the current timestamp on the standard
output. 

-suspicious_file_prefix val => [required]
Specifies the path and the prefix of the "Suspicious file". This file contains
all the Domain:IP mapping that were judget to be suspicious by this block. This
mapping will be further analyzed by the following block. A different file will
be created at the and of each cleanup period, with this syntax:
	suspicious_file_prefix + _ + current_timestamp

-dump_file_prefix => [required]
Specify the path and the prefix of the dump file that will be created at the
and of each merge&split period exporting the collected mappings.

-load_config => [required] 
A flag. If set, the application will try to load the "load_file" at the
beginning, otherwise it will ignore it. For testing you can load the file
"stored_mapping.txt", obteined querying the most common web sites, as specified
by http://www.alexa.com/topsites.

-load_file => [required if load_config = "true"]
Specify the file that stores a previously exported file.

-max_cluster_size val => [required]
How many similar domains do we store per IPBlock before we stop remembering
every single one of them.

-max_num_clusters val => [required]
How many clusters do we allow per IP address. that means, each IPBlock can at
most contain max_num_clusters*numIPs. this simply avoids that we run out of
memory.

-clustering_threshold val =>[required]
What's the maximum domain distance (defined by us) that two domain names can
have in order to be considered similar.

-domain_count_threshold val => [required]
Use for merging/splitting blocks. this defines how similar two blocks need to
be in order to be merged. 0 means 'not similar at all', 1 means 'identical'. so
far, we only used the setting 0.5, i.e. 50% of the clusters of both blocks to
be merged must be similar to at least one cluster of the other block.

tld_names_file => [required]
Explained above. 

geoip_file => [required]
Explained above. 

*DNSSuspiciousMappingAnalyzer*

geoip_file => [required]
Explained above. 

-enable_txt_output val => [required]
To enable/disable txt output.

-malicious_file_prefix val => [required if enable_txt_output = "true"]
Specifies the path and the prefix of the "Malicious file". This will contain a
list of the malicious domain name with a score. A different file will be
created at the and of each cleanup period, with this syntax:
	malicious_file_prefix + _ + current_timestamp

-enable_socket_output val => [required]
To enable/disable the output on a remote database with via a socket.

-server_ip val => [required if enable_socket_output = "true"]
If enable_socket_output = "true", this specify the ip of the remote db.

-server_port val => [required if enable_socket_output = "true"]
If enable_socket_output = "true", this specify the tcp port to be used to
connect with the remote db.

-enable_vis_buffer_output val => [required]
To enable/disable the output on the visualization buffer, in order to use the
visualization GUI.

geoip_file => [required if enable_vis_buffer_output = "true"]
Explained above. 

-db_name val => [required if enable_vis_buffer_output = "true"]
If enable_vis_buffer_output = "true", this specify the name of the db.

-db_ip val => [required if enable_vis_buffer_output = "true"]
If enable_vis_buffer_output = "true", this specify the ip of the db.

-db_user val => [required if enable_vis_buffer_output = "true"]
If enable_vis_buffer_output = "true", this specify the user of the db.

-db_passwd val => [required if enable_vis_buffer_output = "true"]
If enable_vis_buffer_output = "true", this specify the passwd of the db.

-min_num_domains val => [required]
Report only groups of sites that involve at least min_num_domains domains.

-min_num_ips val => [required]
Report only groups of sites that involve at least min_num_ips IPs.

-min_num_ases val => [required]
Report only groups of sites that involve at least min_num_ases autonomous
systems.
