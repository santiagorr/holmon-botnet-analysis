#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.append('dns_statistics_proto')
import dns_statistics_pb2 as dns_stat_protobuf
import dns_analysis_results_pb2 as dns_analysis_protobuf
import multiprocessing
import socket
import base64
import write_db_part as write_db
import struct
import time

_db_conn = None
_db_curs = None
_db_type = None
_insert_tables = (write_db._STATS_TABLE_, write_db._A_REC_TABLE_, write_db._IP_TABLE_) 
_update_tables = (write_db._SCORES_,)
_max_length = 256 #max length for names (domain, or AS)
_delayed = []

def create_new_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1) #we need a connection from only one client
    return server_socket

def connect_to_database():
    global _db_conn, _db_curs
    success = True
    _db_conn, _db_curs = write_db.open_db(_db_type)
    if not (_db_conn and _db_curs):
        sys.stderr.write("Aborting...")
        success = False
    return success

def pydnstrack_data_recv(port, update=False):
    global _db_conn, _db_curs, _db_type
    if update: clean_up_tables = _update_tables
    else: clean_up_tables = _insert_tables
    HOST = ""
    PORT = port
    conn = addr = None
    server_socket = create_new_server(HOST, PORT)
    while True:
        try:
            conn, addr = server_socket.accept()
            print 'Connected by', addr
            try:
                data = conn.recv(4) #(x1, x2) where x1 is db_type and x2 is a flag for db formatting
                data = struct.unpack('>hh', data)
                _db_type, db_clean = data
            except:
                sys.stderr.write('Wrong sequence received. Aborting.\n')
                conn.close()
                return
            else:
                print "Initialization sequence received, host ", addr, " enabled to send."
                if connect_to_database():
                    if db_clean:
                        write_db.clean_up_these(_db_curs, clean_up_tables)
                        write_db.close_db(_db_curs, _db_conn)
                else:
                    conn.close()
                    exit(0)
                while True:
                    #receive a standard 4 bytes packet containing data length
                    data_size = conn.recv(4)
                    if not data_size:
                        print "No more data"
                        break
                    data_size = struct.unpack('>i', data_size)[0]
                    data = conn.recv(data_size)
                    #print data
                    if not data: 
                        print "No more data"
                        break
                    yield data
        except KeyboardInterrupt:
            sys.stderr.write("\nInterrupted by user\n")
            if conn: conn.close()
            return
        else:
            #no more data to receive, closing connections
            if conn: conn.close()
            continue
  
def pydnstrack_receiver(in_port):
    dns_record = dns_stat_protobuf.dns_statistics()
  
    no_error = True
    timestamp = None
    for data in pydnstrack_data_recv(in_port):
        if data != "":
            dns_record.ParseFromString(data)
            if dns_record.HasField("control"):
                buffered_dns_record=dns_record.control
                if buffered_dns_record.start == True:
                    print "START message received..."
                    if not connect_to_database():
                        sys.stderr.write("An error occurred on connecting to the database...\n")
                        no_error = False
                        continue
                    else:
                        timestamp = buffered_dns_record.timestamp
                        if not write_db.create_db_structure(_db_type, _db_curs, timestamp, _max_length, True):
                            sys.stderr.write("An error occurred while writing in the database...\n")
                            continue
                else:
                    print "END message received..."
                    write_db.close_db(_db_conn, _db_curs)
                    print "DB connection closed!"
            else:
                buffered_dns_record = dns_record.data
                dname = buffered_dns_record.name
                if _db_type == write_db._DNAME_TYPE and no_error: #if duplicate partition name, avoids to write duplicate records
                    write_db.insert_DNAME_values(_db_conn, _db_curs, dname, buffered_dns_record, timestamp, _max_length, True)
                else: continue

def DNSanalysis_receiver(in_port):
    global _delayed
    dns_record = dns_analysis_protobuf.dns_analysis_results()

    for data in pydnstrack_data_recv(in_port, update=True):
        if data != "":
            dns_record.ParseFromString(data)
            if dns_record.HasField("control"):
                buffered_dns_record=dns_record.control
                if buffered_dns_record.start == True:
                    print "START message received..."
                    if not connect_to_database():
                        sys.stderr.write("An error occurred on connecting to the database...\n")
                        no_error = False
                        continue
                    else:
                        timestamp = buffered_dns_record.timestamp
                        if not write_db.update_score(_db_curs, _max_length, create_structure=True, timestamp=timestamp):
                            sys.stderr.write("An error occurred while writing in the database...\n")
                            continue
                else:
                    print "END message received..."
                    write_db.close_db(_db_conn, _db_curs)
                    print "DB connection closed!"
           #print buffered_dns_record
            else:
                buffered_dns_record = dns_record.data
                dname = buffered_dns_record.dname
                timestamp = buffered_dns_record.timestamp
                whitelisted = buffered_dns_record.whitelisted
                score = buffered_dns_record.score
     
                if not write_db.update_score(_db_curs, _max_length, data=(timestamp, dname, score, whitelisted)):
                   print "An error occurred on writing into SCORE table"
    
def main():
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("--collect", dest="collect", help="Store data in the database", action="store_true")
    parser.add_option("--update", dest="update", help="Update existing data in the database", action="store_true")
    (options, args) = parser.parse_args()

    if not (options.collect or options.update):
        print options
        parser.print_help()
        exit(0)
    else:
        if options.collect:
            in_port = 50007
            pydnstrack_receiver(in_port)
        elif options.update:
            in_port = 60007
            DNSanalysis_receiver(in_port)

    if _db_conn and _db_curs:
        write_db.close_db(_db_conn, _db_curs)
    
if __name__ == '__main__':
	main()
