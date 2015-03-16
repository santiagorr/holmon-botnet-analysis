#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       write_db.py
#       Eduard Natale <natale@ftw.at>


#*************************** IMPORTANT ******************************#
#1. with utf8 you should necessarly set a varchar name length by 256#
#2. set MAX_ALLOWED_PACKET in my.cnf to 256M (this is for insert in dbDNStrack)

import sys
sys.path.append('dns_statistics_proto')
import os
import MySQLdb
import warnings
import time
import dns_statistics_pb2 as dns_stat_protobuf

_DNAME_TYPE=1
_AS_TYPE=2

_STATS_TABLE="statistical_values_"
_STATS_TABLE_=_STATS_TABLE[:-1]
_ALIAS_TABLE="alias_resolution_steps_"
_ALIAS_TABLE_=_ALIAS_TABLE[:-1]
_A_REC_TABLE="a_records_count_"
_A_REC_TABLE_=_A_REC_TABLE[:-1]
_CENTR_TABLE="ip_location_centroid_"
_CENTR_TABLE_=_CENTR_TABLE[:-1]
_IP_TABLE="ip_addresses_"
_IP_TABLE_=_IP_TABLE[:-1]
_SCORES_ = "scores"

def open_db(stats):
  try:
    host="localhost"
    user="nranalysisuser"
    passwd="my_password"
    cn_db="nranalysis"
    #as_db="AsStatsDB"
    try:
      if stats==_DNAME_TYPE:
        sys.stderr.write("Connecting '"+user+"@"+host+"' to '"+cn_db+"'...")
        conn = MySQLdb.connect (host, user, passwd, db = cn_db, charset = "utf8", use_unicode = True)
      #elif stats == _AS_TYPE:
      #  sys.stderr.write("Connecting '"+user+"@"+host+"' to '"+as_db+"'...")
      #  conn = MySQLdb.connect (host, user, passwd, db = as_db, charset = "utf8", use_unicode = True)
      else:
        sys.stderr.write("Needs a DB type...")
        return None, None
    except MySQLdb.Error, e:
      sys.stderr.write("\nError: "+str(e[0])+", "+str(e[1])+"\n")
      return None, None
    sys.stderr.write("[DONE!]\n")
    return conn, conn.cursor()
    
  except MySQLdb.Error, e:
    sys.stderr.write("Error: "+str(e[0])+", "+str(e[1]))
    sys.exit (1)
    
def close_db(cursor, conn):
  sys.stderr.write("Closing DB connection...")
  try:
    cursor.close ()
  except MySQLdb.Error, e:
    sys.stderr.write("Error: "+str(e))
    return
  #sys.stderr.write("Doing commit...")  
  #conn.commit ()
  conn.close ()
  conn = cursor = None
  sys.stderr.write("[DB CLOSED!]\n")
  return conn, cursor

def update_score(cursor, max_length=256, create_structure=False, timestamp=None, data=None):
  no_error=True
  with warnings.catch_warnings():
    warnings.simplefilter('error', MySQLdb.Warning)
    try:
      if create_structure:
        ts=str(timestamp)
        try:
          cursor.execute("""create table """+_SCORES_+""" (timestamp int unsigned not null, dname varchar("""+str(max_length)+"""), SCORE double, WHITELISTED bool, PRIMARY KEY (timestamp, dname)) ENGINE=MyISAM partition by range (timestamp) (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
        except MySQLdb.Error, e:
          if e[0]==1050:
            sys.stderr.write("New partition range: timestamp "+ts+"\n")
            try:
              cursor.execute("""alter table """+_SCORES_+""" add partition (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
            except MySQLdb.Error, e:
              sys.stderr.write("Error: %s\n" % str(e))
              no_error=False
          elif e[0]==1493:
            #error about partitioning range values (critical error)
            sys.stderr.write(str(e)+"\nTimestamp ignored")
            pass
          else:
            sys.stderr.write("Error: "+str(e)+"\n")
            no_error=False
      elif data:
        if len(data[1])>max_length:
          sys.stderr.write("Skipped '"+data[1]+"' longer than "+str(max_length)+"\n")
          pass
        else:
          try:
            sql = "INSERT INTO %s values" % _SCORES_
            sql += "(%s, %s, %s, %s)"
            cursor.execute(sql, data)
          except MySQLdb.Error, e:
            sys.stderr.write("Error: %s\n" % str(e))
            no_error = False
      else:
        sys.stderr.write("Error: Invalid invocation of function update_score\n" % str(e))
        no_error = False
    except MySQLdb.Warning, e:
      pass
  return no_error

def create_db_structure(db_type, cursor, timestamp, max_length=256, pydnstrack=None):
  no_error=True
  ts=str(timestamp)
  with warnings.catch_warnings():
    warnings.simplefilter('error', MySQLdb.Warning)
    try:
      if db_type==_DNAME_TYPE:

#TODO keep in mind that For MyISAM and BDB tables you can specify AUTO_INCREMENT on a secondary column in a multiple-column index. 
        cursor.execute("""create table """+_STATS_TABLE_+""" (id int auto_increment not null, timestamp int unsigned not null, dname varchar("""+str(max_length)+"""), dname_queries_weighted_cnt int, dname_queries_cnt int, as_count int, TTL_avg int, TTL_std int, unique_TTL_cnt int, IP_distances_avg double, PRIMARY KEY (timestamp, id)) ENGINE=MyISAM partition by range (timestamp) (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
        cursor.execute("""create table """+_A_REC_TABLE_+""" (id int auto_increment not null, timestamp int unsigned not null, DNAME_id int REFERENCES """+_STATS_TABLE_+"""(id) ON DELETE CASCADE, a_records_num int, PRIMARY KEY (timestamp, id)) ENGINE=MyISAM partition by range (timestamp) (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
        if pydnstrack:
          cursor.execute("""create table """+_IP_TABLE_+""" (timestamp int unsigned, DNAME_id int REFERENCES """+_STATS_TABLE_+"""(id) ON DELETE CASCADE, ip integer unsigned, AS_number int, score int, PRIMARY KEY (timestamp, DNAME_id, ip), index (DNAME_id), index (ip), index (AS_number)) ENGINE=MyISAM partition by range(timestamp) (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
      elif db_type==_AS_TYPE:
        #cursor.execute("""create table if not exists autonomous_systems_"""+ts+""" (id int not null auto_increment primary key, AS_desc varchar("""+str(max_length)+"""))""")
        cursor.execute("""create table """+_STATS_TABLE_+""" (id int not null auto_increment, timestamp int unsigned, AS_desc varchar("""+str(max_length)+"""), dname_queries_weighted_cnt int, dname_queries_cnt int, TTL_avg int, TTL_std int, unique_TTL_cnt int, IP_distances_avg double, AS_score double, LEV_dist_avg_2ld double, LEV_dist_avg_3ld double, PRIMARY KEY (timestamp, id))ENGINE=MyISAM partition by range (timestamp) (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
        cursor.execute("""create table """+_CENTR_TABLE_+""" (id int not null auto_increment, timestamp int unsigned, AS_id int REFERENCES """+_STATS_TABLE_+"""(id) ON DELETE CASCADE, loc_num_weight_LAT double, loc_num_weight_LON double, query_weight_LAT double, query_weight_LON double, PRIMARY KEY (timestamp, id)) ENGINE=MyISAM partition by range (timestamp) (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
    except MySQLdb.Error, e:
      if e[0]==1050:
        sys.stderr.write("New partition range: timestamp "+ts+"\n")
        try:
            if db_type==_DNAME_TYPE:
              cursor.execute("""alter table """+_STATS_TABLE_+""" add partition (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
              cursor.execute("""alter table """+_A_REC_TABLE_+""" add partition (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
              cursor.execute("""alter table """ +_IP_TABLE_ + """ add partition (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
            elif db_type==_AS_TYPE:
              cursor.execute("""alter table """+_STATS_TABLE_+""" add partition (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
              cursor.execute("""alter table """+_CENTR_TABLE_+""" add partition (partition p_"""+ts+""" values less than ("""+str(timestamp+1)+"""))""")
        except MySQLdb.Error, e:
            if e[0]==1517:
                sys.stderr.write("Error: "+e[1]+"\n")
                no_error=False
      elif e[0]==1493:
        #error about partitioning range values (critical error)
        sys.stderr.write(str(e)+"\nTimestamp ignored")
        pass
      else:
        sys.stderr.write("Error: "+str(e)+"\n")
        no_error=False
    except MySQLdb.Warning, e:
      pass
  return no_error


def clean_up_these(cursor, tables):
  for i in tables:
      try:
          cursor.execute("drop table %s" % i)
      except MySQLdb.Error, e:
          sys.stderr.write("Error: "+str(e[0])+", "+str(e[1]))
      else:
          sys.stderr.write("Table %s dropped...\n" % i)
  return

def clean_up(cursor, skip_check=None):
  if not skip_check: 
      sys.stderr.write("Warning: clean up the DB? [y,n]: ")
      yes_no = sys.stdin.readline()
  else: yes_no = 'y'
  if yes_no[0] == 'y':
    try:
      thrash_out = cursor.execute("show tables")
      tables = cursor.fetchall()
      for i in tables:
        trash_out = cursor.execute("drop table "+str(i[0]))
        sys.stderr.write("Table "+str(i[0])+" dropped...\n")
    except MySQLdb.Error, e:
      sys.stderr.write("Error: "+str(e[0])+", "+str(e[1]))
      return
  else:
    return

def insert_AS_values(conn, cursor, AS_name, dns_record, timestamp, max_length=256):
  
  #"""******************************"""
  
  
  #if dns_record.query_counter < 3:
    #return
  
  
  #"""*******************************"""
  
  query_count, centroids, ttl_avg, dist_avg, as_score, lev_2, lev_3 = \
  dns_record.query_counter, \
  dns_record.ip_location_centroid, \
  dns_record.ttl_mov_avg, \
  dns_record.ip_distance_mov_avg[0], \
  dns_record.as_score, \
  dns_record.lev_distance_avg[0], \
  dns_record.lev_distance_avg[1]
  
  unique_ttl_cnt=len(dns_record.a_record_ttl_dict)
  if len(ttl_avg) == 2:
    ttl_avg=[ttl_avg[0],0]
  if isinstance(query_count,int):
    query_count = [query_count, None]
  if centroids == (None, None) or not centroids:
    centroids = [(None, None), (None, None)]
  ts=str(timestamp)
  if not AS_name:
    AS_name = "UNKNOWN AUTONOMOUS SYSTEM"
    sys.stderr.write("\n\tWARNING: Unknown AS recognized\n")
  if len(AS_name) <= max_length:
    try:
      cursor.execute("""insert into """+_STATS_TABLE_+""" (AS_desc, timestamp, dname_queries_weighted_cnt,      dname_queries_cnt,  TTL_avg,    TTL_std,    unique_TTL_cnt, IP_distances_avg, AS_score, LEV_dist_avg_2ld, LEV_dist_avg_3ld) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""", \
                                                            (AS_name, timestamp, query_count[0], query_count[1], ttl_avg[0], ttl_avg[1], unique_ttl_cnt, dist_avg,         as_score, lev_2,            lev_3))
      #insert_id() takes the last auto_incremented id -> perfectly what we want
      AS_id=conn.insert_id()
      cursor.execute("""insert into """+_CENTR_TABLE_+""" (timestamp, AS_id, loc_num_weight_LAT, loc_num_weight_LON, query_weight_LAT, query_weight_LON) values (%s, %s, %s, %s, %s, %s)""", (timestamp, AS_id, centroids[0][0],centroids[0][1],centroids[1][0],centroids[1][1]))
    except MySQLdb.Error, e:
      sys.stderr.write("Error: "+str(e[0])+", "+str(e[1]))
      return
  else:
    sys.stderr.write("Skipped '"+str(AS_name)+"' longer than "+str(max_length)+"\n")

def insert_DNAME_values(conn, cursor, dname, dns_record, timestamp, max_length=256, pydnstrack=None):
  #dns_record is dns_stat.dns_statistics.data
  ts=str(timestamp)
  as_count = dns_record.as_counter
  query_count = [dns_record.a_queries_counter, dns_record.dname_queries_counter]
  unique_ttl_cnt = dns_record.unique_ttls_counter
  ttl_avg = [dns_record.ttl_moving_avg, dns_record.ttl_standard_dev]
  dist_avg = dns_record.ip_distance_moving_avg
  a_recs = dns_record.a_records_counter
  ip_list = dns_record.ip_address

  if dname:
    if len(dname) <= max_length:
      try:
        cursor.execute("""insert into """+_STATS_TABLE_+""" (timestamp, dname, dname_queries_weighted_cnt,      dname_queries_cnt,  as_count, TTL_avg,    TTL_std,    unique_TTL_cnt, IP_distances_avg) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)""", \
                                                           (timestamp, dname, query_count[0], query_count[1], as_count, ttl_avg[0], ttl_avg[1], unique_ttl_cnt, dist_avg))
        #insert_id() takes the last auto_incremented id -> perfectly what we want
        DNAME_id=conn.insert_id()
        if pydnstrack:
          for i in ip_list:
            cursor.execute("""insert into """+_IP_TABLE_+""" (timestamp, DNAME_id, ip) values (%s, %s, inet_aton(%s)) """, (timestamp, DNAME_id, i))
        for i in a_recs:
          cursor.execute("""insert into """+_A_REC_TABLE_+""" (timestamp, DNAME_id, a_records_num) values (%s, %s, %s)""", (timestamp, DNAME_id, i))
      except MySQLdb.Error, e:
        sys.stderr.write("Error: "+str(e[0]))
        return
    else:
      sys.stderr.write("Skipped '"+str(dname)+"' longer than "+str(max_length)+"\n")
  else:
    sys.stderr.write("Error: invalid dname %r. Skipped.\n" % dname)

def main():
  conn, cursor = open_db(1)
  #error = create_db_structure(cursor)
  #if error:
  #  sys.exit(1)
  close_db(cursor, conn)
if __name__ == '__main__':
	main()

