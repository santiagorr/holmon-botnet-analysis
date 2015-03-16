/* Copyright (c) 2011, NEC Europe Ltd, Consorzio Nazionale 
 * Interuniversitario per le Telecomunicazioni, Institut 
 * Telecom/Telecom Bretagne, ETH Zürich, INVEA-TECH a.s. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the names of NEC Europe Ltd, Consorzio Nazionale 
 *      Interuniversitario per le Telecomunicazioni, Institut Telecom/Telecom 
 *      Bretagne, ETH Zürich, INVEA-TECH a.s. nor the names of its contributors 
 *      may be used to endorse or promote products derived from this software 
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT 
 * HOLDERBE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
 */

/*
 * <blockinfo type="DNSPacketAggregator" invocation="direct" thread_exclusive="False">
 *   <humandesc>
 *   	This block receives as input NOERROR DNSPAcket messages, for each newly
 *   	observed dname stores into an hash table all the IP_address mapped with
 *   	this dname, and counts the occurrences of this dname. The content of
 *   	this hash table is periodically dumped into a database.
 *   </humandesc>
 *
 *   <shortdesc>
 *      Stores and aggregates information regarding DNSMessage, and dumps to a
 *      database. 
 *   </shortdesc>
 *
 *   <gates>
 *     <gate type="input" name="in_pkt" msg_type="DNSMessage" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *    element params {
 *    	element aggregation_period {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element printout_period {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element qname_analysis {
 *      	attribute val = {bool} 
 *      }
 *    	element query_threshold {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element output_destination {
 *      	attribute val = {string} 
 *      }
 *    	element server_ip {
 *      	attribute val = {string} 
 *      }
 *    	element server_port {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element file_name {
 *      	attribute val = {string} 
 *      }
 *    }
 *   </paramsschema>
 *
 *   <paramsexample>
 *     <params>
 *        <aggregation_period val = "3600"/>
 *        <printout_period val = "600"/>
 *        <qname_analysis val = "false"/>
 *        <query_threshold val = "0"/>
 *		  <output_destination val = "socket"/>
 *		  <server_ip val = "192.168.1.79"/>
 *		  <server_port val = "50007"/>
 *		  <file_name val = "/home/mirko/dns_output/dns_analysis.txt_"/>
 *     </params>
 *   </paramsexample>
 *
 *   <variables>
 *   </variables>
 *
 * </blockinfo>
 */
#include <iostream>
#include <unordered_map>
#include <string>
#include <set>
#include <Block.hpp>
#include <BlockFactory.hpp>
#include <Packet.hpp>
#include <ClassId.hpp>
#include <arpa/inet.h>
#include <sstream>
#include <sstream>
#include <fstream>
#include <arpa/inet.h>  
#include <sys/socket.h>
#include <idna.h>
#include "DNSMessage.hpp"
#include "dns_statistics.pb.h"
#include <time.h>

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/warning.h>
#include <cppconn/metadata.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/resultset_metadata.h>
#include <cppconn/statement.h>

#include <mysql_driver.h>
#include <mysql_connection.h>

#define PUNYCODE_SUPPORT 0

namespace blockmon
{
	/* Definiton of the hash table to store and aggregate information regarding
	 * DNS packets. */
	typedef struct {
		uint32_t cnt;
		std::set<uint32_t> a_rec_ip_addr;
	} dns_info;

	typedef std::unordered_map<std::string, dns_info> dns_hash_table;

   	class DNSPacketAggregator: public Block
   	{
    	/*
     	* simple helper function to print an ip address
     	* implemented by using inet_ntop.
     	*/
        static std::string ip_to_string(uint32_t ip)
        {
            
            char addr_buffer[INET_ADDRSTRLEN];
            //inet_ntop expects network byte order
            uint32_t flipped_ip=htonl(ip);
            
            if(!inet_ntop(AF_INET, &flipped_ip, addr_buffer, INET_ADDRSTRLEN))
                throw std::runtime_error("cannot convert ip address");
            return std::string (addr_buffer);
        }
                
        int m_ingate_id;

		dns_hash_table m_dns_ht;
		/* We need to different time reference: one for flushing the table,
		 * another for dumping into the database. */
		uint32_t m_timestamp;
		uint32_t m_timestamp_2;
		/* Counter increased at the end of every period. */
		uint32_t m_period_cnt;
		/* Interval of time after which the table is flushed. */
		uint32_t m_aggregation_period;
		/* Interval of time after which the content of the table is transfered
		 * into a database. */
		uint32_t m_printout_period;
		/* Minimum amount of query to see to output a certain dname into the
		 * database. */
		uint32_t m_query_threshold;
		/* Flag to specify if to analyze cname or qname from the DNSMessage. */
		bool m_qname_analysis;
		/* Output destination: 'file' of 'socket' */
		std::string m_output_destination;
		/* File name for output. */
		std::string m_file_name;
		/* File to output on. */
		std::ofstream m_output_file;
		/* Socket reference. */
		struct sockaddr_in m_serv_add;

		uint32_t m_dname_cnt;

        /* Driver Manager */
        sql::Driver *m_db_driver;
        std::shared_ptr<sql::Connection> m_con;
        std::string m_db_database;
        std::string m_db_host;
        std::string m_db_user;
        std::string m_db_passwd;

    public:
		/**
		  * @brief Constructor
		  * @param name			The name of the source block
		  * @param invocation	Invocation type of the block.
		  */
        DNSPacketAggregator(const std::string &name, invocation_type) : 
			Block(name, invocation_type::Direct),
        	m_ingate_id(register_input_gate("in_pkt")),
			m_dns_ht(),
			m_timestamp(0),
			m_timestamp_2(0),
			m_period_cnt(0),
			m_dname_cnt(0),
	        m_db_database("dnsAnalysis"),
	        m_db_host("192.168.0.55"),
	        m_db_user("mirko"),
	        m_db_passwd("mirko")   
        {
		}
		/**
		  * @brief Destructor
		  */
		~DNSPacketAggregator()
		{
			if (!m_output_file.is_open())
				m_output_file.close();
		}

		/**
		  * Configure the block
		  * @param n	The xml subtree.
		  */
		void _configure(const pugi::xml_node&  n) 
        {
            pugi::xml_node aggregation_period = n.child("aggregation_period");
            if(!aggregation_period) 
                throw std::runtime_error("missing aggregation period");
            m_aggregation_period = aggregation_period.attribute("val").as_uint();
				
            pugi::xml_node printout_period = n.child("printout_period");
            if(!printout_period) 
                throw std::runtime_error("missing printout period");
            m_printout_period = printout_period.attribute("val").as_uint();

            pugi::xml_node query_threshold = n.child("query_threshold");
            if(!query_threshold) 
                throw std::runtime_error("missing query threshold");
            m_query_threshold = query_threshold.attribute("val").as_uint();

            pugi::xml_node qname_analysis = n.child("qname_analysis");
            if(!qname_analysis) 
                throw std::runtime_error("missing qname analysis");
            m_qname_analysis = qname_analysis.attribute("val").as_bool();

            pugi::xml_node output_destination = n.child("output_destination");
            if(!output_destination) 
                throw std::runtime_error("missing output_destination");
            m_output_destination = output_destination.attribute("val").value();
			
            std::stringstream sql;
            /* Using the Driver to create a connection */
            m_db_driver = sql::mysql::get_driver_instance();
			std::shared_ptr<sql::Connection> con_tmp(m_db_driver->connect(m_db_host, 
				m_db_user, m_db_passwd));
            m_con = con_tmp;

			/* The usage of USE is not supported by the prepared statement protocol */
			std::shared_ptr<sql::Statement> stmt(m_con->createStatement());
			stmt->execute("USE " + m_db_database);
			
			stmt->execute("DROP TABLE IF EXISTS DnameCounter");
			stmt->execute("DROP TABLE IF EXISTS DnameAggregation");
            /* RESULTS TABLE*/
            //std::stringstream drop_table;
            //drop_table << " DROP TABLE IF EXISTS DnameCounter";
			
            //sql::PreparedStatement *prep_stmt = m_con->prepareStatement(drop_table.str());
			
			//prep_stmt->execute();

            //drop_table << "DROP TABLE IF EXISTS DnameAggregation";

			//prep_stmt = m_con->prepareStatement(drop_table.str());
			
			//prep_stmt->execute();

            std::stringstream create_table;
            create_table << "CREATE TABLE DnameCounter"
						 << "(Id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY," 
						 	" Timestamp INT, Timebin TIMESTAMP, DnameCounterVal INT)";
            sql::PreparedStatement * prepare_stat;
            prepare_stat = m_con->prepareStatement(create_table.str());
            prepare_stat->execute();
	    	std::cout << "#\t DnameCounter table created\n";
            
			std::stringstream create_table2;
            create_table2 << "CREATE TABLE DnameAggregation"
						 << "(Id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY," 
						 	" Timestamp INT, Timebin TIMESTAMP, Dname VARCHAR(200), Counter INT)";
            prepare_stat = m_con->prepareStatement(create_table2.str());
            prepare_stat->execute();
	    	std::cout << "#\t DnameAggregation table created\n";

			if (m_output_destination == "file") {
		        pugi::xml_node file_name = n.child("file_name");
        		if(!file_name) 
                	throw std::runtime_error("missing file_name");
            	m_file_name = file_name.attribute("val").value();
				return;
			}

			if (m_output_destination == "socket") {
				/* Read IP address of the server hosting the database */
        		pugi::xml_node server_ip = n.child("server_ip");
        		if(!server_ip) 
        		    throw std::runtime_error("server_ip");
        		std::string ser_ip = server_ip.attribute("val").value();
				/* Check if the address is correctly inserted */
				if ((inet_pton(AF_INET, ser_ip.c_str(), 
					&m_serv_add.sin_addr)) <= 0)
					throw std::runtime_error("address creation error");
        		/* Read the port to be used */
				pugi::xml_node server_port = n.child("server_port");
        		if(!server_port) 
        		    throw std::runtime_error("server_port");
				m_serv_add.sin_port =
					htons(server_port.attribute("val").as_uint());
				/* Address type is INET */
				m_serv_add.sin_family = AF_INET;
				return;
			}
			throw std::runtime_error("output_type must be 'file' or 'socket'"); 
		}

		/**
		  * Helper function to print the output on a file
		  */
		void _output_to_file()
		{
			char *p;
			dns_hash_table::iterator ht_it;
		    for (ht_it = m_dns_ht.begin(); ht_it != m_dns_ht.end(); ht_it++) {
				if (ht_it->second.cnt > m_query_threshold) {
					/* Before to output the string, this are encoded with the
					 * punycode format. */
					idna_to_unicode_lzlz(ht_it->first.c_str(), &p, 0);
					m_output_file << p << "\t" << ht_it->second.cnt << "\t";
					delete p;
					std::set<uint32_t> *vec = &ht_it->second.a_rec_ip_addr;  
					std::set<uint32_t>::iterator it;  
					for(it = vec->begin(); it != vec->end(); it++)
						m_output_file << *it << "\t";
	  	    		m_output_file << "\n";
				}
			}
		}
		
		/*
		** packi16() -- store a 16-bit int into a char buffer (like htons())
		*/ 
		void packi16(unsigned char *buf, unsigned int i)
		{
		    *buf++ = i>>8; *buf++ = i;
		}
		
		/*
		** packi32() -- store a 32-bit int into a char buffer (like htonl())
		*/ 
		void packi32(unsigned char *buf, unsigned long i)
		{
		    *buf++ = i>>24; *buf++ = i>>16;
		    *buf++ = i>>8;  *buf++ = i;
		}

		void _serialize_control_to_socket(bool start, int sock_fd)
		{
			dns_statistics message_to_send;
			dns_statistics::ControlMessage *control_to_send =
				message_to_send.mutable_control();

			control_to_send->set_timestamp(m_timestamp);
			control_to_send->set_start(start);

			std::string string_to_send;
			message_to_send.SerializeToString(&string_to_send);

			unsigned char header[4]; // Length of the message
			packi32(header, string_to_send.length());
			
			/* Send message via the socket: */
			/* First we have to send the header telling how long the protobuf
			 * message will be to the other end on the communication */
			if ( (write(sock_fd, header, 4)) < 0 )
				throw std::runtime_error("header not sent");
			/* Then we can finally send the protobuf message */
			if ( (write(sock_fd, string_to_send.c_str(), 
				string_to_send.length())) < 0 )
				throw std::runtime_error("message not sent");
		}

		void _serialize_data_to_socket(const std::string *dname, dns_info *data,
			int sock_fd)
		{
			#if PUNYCODE_SUPPORT
				char *puny_decoded;
			#endif		
			/* Prepare the dns_statistics message */
			dns_statistics message_to_send;
			dns_statistics::DataMessage *data_to_send =
				message_to_send.mutable_data();
			#if PUNYCODE_SUPPORT
				/* Before to output the string, this are encoded with the
				 * punycode format. */
				idna_to_unicode_lzlz(dname->c_str(), &puny_decoded, 0);
				/* Set the dname */
				data_to_send->set_name(puny_decoded);
			#else
				data_to_send->set_name(*dname);
			#endif

			/* Set the counter */
			data_to_send->set_dname_queries_counter(data->cnt);
			/* Set the ip address set */
			std::set<uint32_t> *ip_set = &data->a_rec_ip_addr;  
			std::set<uint32_t>::iterator it;
			for (it = ip_set->begin(); it != ip_set->end(); it++) {
				data_to_send->add_ip_address(ip_to_string(*it));
				data_to_send->add_a_records_counter(0);
			}

			/* Set the other fields */
			data_to_send->set_ip_distance_moving_avg(0.0);	
			data_to_send->set_unique_ttls_counter(0.0);
			data_to_send->set_ttl_moving_avg(0.0);
			data_to_send->set_ttl_standard_dev(0.0);

			data_to_send->set_a_queries_counter(0);
			data_to_send->set_as_counter(0);
			
			if (!message_to_send.IsInitialized())
				throw std::runtime_error
					("protocol buffer object not initialized");

			std::string string_to_send;
			message_to_send.SerializeToString(&string_to_send);
			
			unsigned char header[4]; // Length of the message
			packi32(header, string_to_send.length());
			
			/* Send message via the socket: */
			/* First we have to send the header telling how long the protobuf
			 * message will be to the other end on the communication */
			if ( (write(sock_fd, header, 4)) < 0 )
				throw std::runtime_error("header not sent");
			/* Then we can finally send the protobuf message */
			if ( (write(sock_fd, string_to_send.c_str(), 
				string_to_send.length())) < 0 )
				throw std::runtime_error("message not sent");
			/* Deallocate the string */
			#if PUNYCODE_SUPPORT
				delete puny_decoded;
			#endif
		}

		void _output_to_socket()
		{
			int sock_fd;
			/* create socket */
			if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
				throw std::runtime_error("Socket creatin error");

			/* Check if is possible to connect to the server */
			if (connect(sock_fd, (struct sockaddr *)&m_serv_add,
				sizeof(m_serv_add)) < 0)
				throw std::runtime_error("Connection error");
			
			/* Send a first control message to notify the other end that the
			 * data transmission is going to start */
			_serialize_control_to_socket(true, sock_fd);
			
			dns_hash_table::iterator ht_it;
		    for (ht_it = m_dns_ht.begin(); ht_it != m_dns_ht.end(); ht_it++) {
				if (ht_it->second.cnt > m_query_threshold) 			
					_serialize_data_to_socket(&ht_it->first, &ht_it->second, sock_fd);
			}

			/* Send a first control message to notify the other end that the
			 * data transmission is finished */
			_serialize_control_to_socket(false, sock_fd);
			/* Close the socket used to transfer data to the broker */
			close(sock_fd);
		}

		void dump_dname_counter()
		{
        	uint64_t timestamp = (uint64_t)m_timestamp_2;
            
            std::stringstream insert_into;
            insert_into << "INSERT INTO DnameCounter" 
						<< "(Timestamp, Timebin, DnameCounterVal)"
            " VALUES (?, ?, ?);";
           	
            /* -----------------   POPULATING THE DATABASE TABLE ------------- */
            std::shared_ptr<sql::PreparedStatement> prep_stmt(m_con->prepareStatement(insert_into.str()));
            prep_stmt->setInt(1, timestamp);
            /* convert timestamp in string "YYYY-MM-DD hh:mm:ss" */
            time_t curr_time;
            curr_time = timestamp;
            struct tm *c_time = localtime(&curr_time);            
            std::stringstream unix_timestamp;
            unix_timestamp << c_time->tm_year+1900 << "-" 
                           << c_time->tm_mon+1 << "-" 
                           << c_time->tm_mday << " "
                           << c_time->tm_hour << ":"
                           << c_time->tm_min << ":"
                           << c_time->tm_sec; 
            
            prep_stmt->setDateTime(2,unix_timestamp.str());
            prep_stmt->setInt(3, m_dname_cnt);
            
            prep_stmt->executeUpdate();
        }

		void dump_aggregation()
		{
			uint64_t timestamp = (uint64_t)m_timestamp_2;
            
            std::stringstream insert_into;
            insert_into << "INSERT INTO DnameAggregation" 
						<< "(Timestamp, Timebin, Dname, Counter)"
            " VALUES (?, ?, ?, ?);";
           	
            /* -----------------   POPULATING THE DATABASE TABLE ------------- */
            std::shared_ptr<sql::PreparedStatement> prep_stmt(m_con->prepareStatement(insert_into.str()));
            prep_stmt->setInt(1, timestamp);
            /* convert timestamp in string "YYYY-MM-DD hh:mm:ss" */
            time_t curr_time;
            curr_time = timestamp;
            struct tm *c_time = localtime(&curr_time);            
            std::stringstream unix_timestamp;
            unix_timestamp << c_time->tm_year+1900 << "-" 
                           << c_time->tm_mon+1 << "-" 
                           << c_time->tm_mday << " "
                           << c_time->tm_hour << ":"
                           << c_time->tm_min << ":"
                           << c_time->tm_sec; 
            
            prep_stmt->setDateTime(2,unix_timestamp.str());
			
			dns_hash_table::iterator it;
			for (it = m_dns_ht.begin(); it != m_dns_ht.end(); it++) {
				std::string name = it->first;
				prep_stmt->setString(3, name);
				int cnt = it->second.cnt;
				prep_stmt->setInt(4, cnt);
            	prep_stmt->executeUpdate();
			}
		}

		/**
		  * The function to check if the received messag has to be forwarded to
		  * the output.
		  * @param m	The message to be aggregated.
		  */
        void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */) 
        {
			dns_info new_entry;
            auto dns_packet = static_cast<const DNSMessage *>(m.get());
			
			uint32_t c_time = (dns_packet->timestamp >> 32);
			
			/* Intialize the timestamp, with the first received packet's timestamp */
		    if (m_timestamp == 0) {
				std::stringstream file;
				file << m_file_name << m_period_cnt;
				m_output_file.open(file.str());
				m_timestamp = c_time;
				m_timestamp_2 = c_time;
			}
		    
			/* Print the current timestamp every ten minutes of trace */
			if (c_time >= m_timestamp_2 + m_printout_period) {
				m_timestamp_2 = c_time;
				dump_dname_counter();
				m_dname_cnt = 0;
				std::cout << m_timestamp_2 << "\n";
			}
			
			/* After one hour print the table and flush its content */
		    if (c_time >= m_timestamp + m_aggregation_period) {
				m_timestamp = c_time;
				m_period_cnt++;
				dump_aggregation();
				#if 0
				if (m_output_destination == "file") {
					_output_to_file();
					m_output_file.close();
					std::stringstream file;
					file << m_file_name << m_period_cnt;
					m_output_file.open(file.str());
				} else
					_output_to_socket();
				#endif
				m_dns_ht.clear();
			}
			
			/* Only DNS answers with at least one a-record or one c-record */
			if (dns_packet->a_recs.size() == 0 && dns_packet->c_names.size() == 0)
				return;
			
			m_dname_cnt++;

			/* Decide the identifier to track */
			std::string *identifier;

			if (m_qname_analysis) {
				if (dns_packet->c_names.size())
	    			identifier = dns_packet->c_names.front().qname;
				else
	    			identifier = dns_packet->a_recs.front().qname;
			} else {
				if (dns_packet->c_names.size())
	    			identifier = dns_packet->c_names.back().cname;
				else
	    			identifier = dns_packet->a_recs.front().qname;
			}
			
			/* Check if the identifier has been properly set */
			if (identifier == NULL) {
				std::cout << "no identifier\n";
				return;
			} 
			
			/* Transform the identifier into a lower-case string */
	    	std::transform(identifier->begin(), identifier->end(), 
				identifier->begin(), ::tolower);
			
			/* Check if the packet is already present in the hashtable */
			dns_hash_table::iterator ht_it = m_dns_ht.find(*identifier);
            if(ht_it == m_dns_ht.end()) {
				new_entry.cnt = 1;
				for (unsigned int i = 0; i < dns_packet->a_recs.size(); i++) {
					uint32_t ip_addr = dns_packet->a_recs[i].ip_addr;
					new_entry.a_rec_ip_addr.insert(ip_addr);
	            } 
				m_dns_ht[*identifier] = new_entry; 
			} else {
				for (unsigned int i = 0; i < dns_packet->a_recs.size(); i++) {
					uint32_t ip_addr = dns_packet->a_recs[i].ip_addr;
					ht_it->second.a_rec_ip_addr.insert(ip_addr);
	            } 
				ht_it->second.cnt++;
	        }
        }
    };

#ifndef _BLOCKMON_DOXYGEN_SKIP_
    REGISTER_BLOCK(DNSPacketAggregator,"DNSPacketAggregator");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */
}

