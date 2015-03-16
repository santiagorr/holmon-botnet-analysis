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
 * <blockinfo type="DNSMappingAggregator" invocation="direct" thread_exclusive="False">
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
 *     <gate type="input" name="in_msg" msg_type="DNSMessage" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *    element params {
 *    	element time_bin_aggregation {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element time_bin_printout {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element query_threshold {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element enable_txt_output {
 *      	attribute val = {bool} 
 *      }
 *    	element output_file_prefix {
 *      	attribute val = {string} 
 *      }
 *    	element enable_socket_output {
 *      	attribute val = {bool} 
 *      }
 *    	element server_ip {
 *      	attribute val = {string} 
 *      }
 *    	element server_port {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element enable_vis_buffer_output {
 *      	attribute val = {bool} 
 *      }
 *    	element db_name {
 *      	attribute val = {string} 
 *      }
 *    	element db_ip {
 *      	attribute val = {string} 
 *      }
 *    	element db_user {
 *      	attribute val = {string} 
 *      }
 *    	element db_passwd {
 *      	attribute val = {string} 
 *      }
 *    }
 *   </paramsschema>
 *
 *   <paramsexample>
 *     <params>
 *       <time_bin_aggregation val = "3600"/>
 *       <time_bin_printout val = "3600"/>
 *       <query_threshold val = "5"/>
 *   	 <enable_txt_output val = "false"/>
 *		  <output_file_prefix val = 
 *		  		"/home/schiavone/svn/demons/Sources/blockmon/main/
 *				node/usr/app_nranalysis/dns_output/aggregation_"/>
 *   	 <enable_socket_output val = "false"/>
 *   	 <server_ip val = "192.168.1.79"/>
 *   	 <server_port val = "50007"/>
 *       <enable_vis_buffer_output val = "false"/>
 *       <db_name val = "noErrorDnsAnalysis"/>
 *       <db_ip val = "127.0.0.1"/>
 *       <db_user val = "mirko"/>
 *       <db_passwd val = "mirko"/>
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

#include <PairMsg.hpp>
#include <DNSMapping.hpp>

namespace blockmon
{
	/* Definiton of the hash table to store and aggregate information regarding
	 * DNS packets. */
	typedef struct {
		uint32_t queryCnt;
		std::set<uint32_t> ipSet;
	} DNSInfo;

	typedef std::unordered_map<std::string, DNSInfo> dns_hash_table;

   	class DNSMappingAggregator: public Block
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
            
            if(!inet_ntop(AF_INET, &flipped_ip, addr_buffer, INET_ADDRSTRLEN)) {
                //throw std::runtime_error("cannot convert ip address");
				std::cerr << "WARNING: ";
				std::cerr << "Cannot convert ip address\n";
				return "";
			}
            return std::string (addr_buffer);
        }
                
        int m_ingate_id;

		dns_hash_table m_dns_ht;
		/* We need to different time reference: one for flushing the table,
		 * another for dumping into the database. */
		
		uint32_t m_next_aggregation;
		uint32_t m_time_bin_aggregation;
		uint32_t m_next_printout;
		uint32_t m_time_bin_printout;
		uint32_t m_last_timestamp;
		int m_reset_db;
		/* Minimum amount of query to see to output a certain dname into the
		 * database. */
		uint32_t m_query_threshold;
		/* Output destination: 'file' of 'socket' */
		bool m_enable_txt_output;
		bool m_enable_socket_output;
		/* File name for output. */
		std::string m_output_file_prefix;
		/* File to output on. */
		std::ofstream m_output_file;
		/* Socket reference. */
		struct sockaddr_in m_serv_add;
		
		int m_dname_cnt;

		bool m_enable_vis_buffer_output;
        sql::Driver *m_db_driver;
        std::shared_ptr<sql::Connection> m_con;
        std::string m_db_name;
        std::string m_db_ip;
        std::string m_db_user;
        std::string m_db_passwd;

    public:
		/**
		  * @brief Constructor
		  * @param name			The name of the source block
		  * @param invocation	Invocation type of the block.
		  */
        DNSMappingAggregator(const std::string &name, invocation_type) : 
			Block(name, invocation_type::Direct),
        	m_ingate_id(register_input_gate("in_msg")),
			m_dns_ht(),
			m_next_aggregation(0),
			m_next_printout(0),
			m_reset_db(1),
			m_dname_cnt(0)
        {
		}
		/**
		  * @brief Destructor
		  */
		~DNSMappingAggregator()
		{
			output_to_file(0);
		}

		/**
		  * Configure the block
		  * @param n	The xml subtree.
		  */
		void _configure(const pugi::xml_node&  n) 
        {
            pugi::xml_node time_bin_aggregation = n.child("time_bin_aggregation");
            if(!time_bin_aggregation) 
                throw std::runtime_error("missing time_bin_aggregation");
            m_time_bin_aggregation = time_bin_aggregation.attribute("val").as_uint();
				
            pugi::xml_node time_bin_printout = n.child("time_bin_printout");
            if(!time_bin_printout) 
                throw std::runtime_error("missing time_bin_printout");
            m_time_bin_printout = time_bin_printout.attribute("val").as_uint();

            pugi::xml_node query_threshold = n.child("query_threshold");
            if(!query_threshold) 
                throw std::runtime_error("missing query threshold");
            m_query_threshold = query_threshold.attribute("val").as_uint();

            pugi::xml_node enable_txt_output = n.child("enable_txt_output");
            if(!enable_txt_output) 
                throw std::runtime_error("missing enable_txt_output");
            m_enable_txt_output = enable_txt_output.attribute("val").as_bool();
			
            pugi::xml_node enable_socket_output = n.child("enable_socket_output");
            if(!enable_socket_output) 
                throw std::runtime_error("missing enable_socket_output");
            m_enable_socket_output = enable_socket_output.attribute("val").as_bool();

			if (m_enable_socket_output) {
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
			}
			if (m_enable_txt_output) {
				pugi::xml_node output_file_prefix =
					n.child("output_file_prefix");
        	    if(!output_file_prefix) 
        	        throw std::runtime_error("missing output_file_prefix");
        	    m_output_file_prefix = output_file_prefix.attribute("val").value();
			}

            pugi::xml_node enable_vis_buffer_output = n.child("enable_vis_buffer_output");
            if(!enable_vis_buffer_output) 
                throw std::runtime_error("missing enable_vis_buffer_output");
            m_enable_vis_buffer_output = enable_vis_buffer_output.attribute("val").as_bool();

			if (m_enable_vis_buffer_output) {
				/* Read IP address of the socket hosting the database */
        		pugi::xml_node db_name = n.child("db_name");
        		if(!db_name) 
        		    throw std::runtime_error("missing db_name");
        		std::string m_db_name = db_name.attribute("val").value();

        		pugi::xml_node db_ip = n.child("db_ip");
        		if(!db_ip) 
        		    throw std::runtime_error("missing db_ip");
        		std::string m_db_ip = db_ip.attribute("val").value();

        		pugi::xml_node db_user = n.child("db_user");
        		if(!db_user) 
        		    throw std::runtime_error("missing db_user");
        		std::string m_db_user = db_user.attribute("val").value();

        		pugi::xml_node db_passwd = n.child("db_passwd");
        		if(!db_passwd) 
        		    throw std::runtime_error("missing db_passwd");
        		std::string m_db_passwd = db_passwd.attribute("val").value();

	            std::stringstream sql;
	            /* Using the Driver to create a connection */
	
	            m_db_driver = sql::mysql::get_driver_instance();
				std::shared_ptr<sql::Connection> con_tmp(m_db_driver->connect(m_db_ip, 
					m_db_user, m_db_passwd));
	            m_con = con_tmp;
	
				/* The usage of USE is not supported by the prepared statement protocol */
				std::shared_ptr<sql::Statement> stmt(m_con->createStatement());
				stmt->execute("USE " + m_db_name);
				
				stmt->execute("DROP TABLE IF EXISTS DnameCounter");
	
				std::stringstream create_table;
	            create_table << "CREATE TABLE DnameCounter";
				create_table << "(Id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, "; 
				create_table <<	"Timestamp INT, ";
				create_table << "UmanReadableTimestamp TIMESTAMP, ";
				create_table << "NumberOfFoundDomainName INT)";
	
	            sql::PreparedStatement * prepare_stat;
	            prepare_stat = m_con->prepareStatement(create_table.str());
	            prepare_stat->execute();
	    		std::cout << "#\t DnameCounter table created\n";

			}

		}

		/**
		  * Helper function to print the output on a file
		  */
		void output_to_file(uint32_t c_time)
		{
			std::string fileName = m_output_file_prefix;
			std::ofstream f;
			if (c_time) {
				std::ostringstream convert;
				convert << c_time;
				fileName += convert.str();
				fileName += ".txt";
			} else
				fileName += "final.txt"; 
		
			f.open(fileName, std::ofstream::out);
			if (!f.is_open()) {
				//throw std::runtime_error("Cannot open output file");
				std::cerr << "WARNING: ";
				std::cerr << "Cannot open output file\n";
				return;
			}
			dns_hash_table::iterator ht_it;
		    for (ht_it = m_dns_ht.begin(); ht_it != m_dns_ht.end(); ht_it++) {
				if (ht_it->second.queryCnt > m_query_threshold) {
					f << ht_it->first.c_str() << "\t";
					f << ht_it->second.queryCnt << "\t";
					std::set<uint32_t> *ipSet = &ht_it->second.ipSet;  
					std::set<uint32_t>::iterator it;  
					for(it = ipSet->begin(); it != ipSet->end(); it++)
						f << *it << "\t";
	  	    		f << "\n";
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

		void _serialize_control_to_socket(bool start, int sock_fd, uint32_t c_time)
		{
			dns_statistics message_to_send;
			dns_statistics::ControlMessage *control_to_send =
				message_to_send.mutable_control();

			control_to_send->set_timestamp(c_time);
			control_to_send->set_start(start);

			std::string string_to_send;
			message_to_send.SerializeToString(&string_to_send);

			unsigned char header[4]; // Length of the message
			packi32(header, string_to_send.length());
			
			/* Send message via the socket: */
			/* First we have to send the header telling how long the protobuf
			 * message will be to the other end on the communication */
			if ( (write(sock_fd, header, 4)) < 0 ) {
				//throw std::runtime_error("header not sent in DNSMappingAggregator");
				std::cerr << "WARNING: ";
				std::cerr << "header not sent in DNSMappingAggregator\n";
				return;
			}
			/* Then we can finally send the protobuf message */
			if ( (write(sock_fd, string_to_send.c_str(), 
				string_to_send.length())) < 0 ) {
				//throw std::runtime_error("message not sent in DNSMappingAggregator");
				std::cerr << "WARNING: ";
				std::cerr << "message not sent in DNSMappingAggregator\n";
				return;
			}
		}

		void _serialize_data_to_socket(const std::string *dname, DNSInfo *data,
			int sock_fd)
		{
			/* Prepare the dns_statistics message */
			dns_statistics message_to_send;
			dns_statistics::DataMessage *data_to_send =
				message_to_send.mutable_data();

			data_to_send->set_name(*dname);

			/* Set the counter */
			data_to_send->set_dname_queries_counter(data->queryCnt);
			/* Set the ip address set */
			std::set<uint32_t> *ip_set = &data->ipSet;  
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
			
			if (!message_to_send.IsInitialized()) {
				//throw std::runtime_error
				std::cerr << "WARNING: ";
				//	("protocol buffer object not initialized in DNSMappingAggregator");
				std::cerr << "protocol buffer object not initialized in DNSMappingAggregator\n";
				return;
			}
			std::string string_to_send;
			message_to_send.SerializeToString(&string_to_send);
			
			unsigned char header[4]; // Length of the message
			packi32(header, string_to_send.length());
			
			/* Send message via the socket: */
			/* First we have to send the header telling how long the protobuf
			 * message will be to the other end on the communication */
			if ( (write(sock_fd, header, 4)) < 0 ) {
				//throw std::runtime_error("header not sent");
				std::cerr << "WARNING: ";
				std::cerr << "header not sent in DNSMappingAggregator\n";
				return;
			}
			/* Then we can finally send the protobuf message */
			if ( (write(sock_fd, string_to_send.c_str(), 
				string_to_send.length())) < 0 ) {
				//throw std::runtime_error("message not sent");
				std::cerr << "WARNING: ";
				std::cerr << "message not sent in DNSMappingAggregator\n";
				return;
			}
			/* Deallocate the string */
		}

		void output_to_socket(uint32_t c_time)
		{
			int sock_fd;
			/* create socket */
			if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				//throw std::runtime_error("Socket creatin error in DNSMappingAggregator");
				std::cerr << "WARNING: ";
				std::cerr << "Socket creatin error in DNSMappingAggregator\n";
				return;
			}
			/* Check if is possible to connect to the server */
			if (connect(sock_fd, (struct sockaddr *)&m_serv_add,
				sizeof(m_serv_add)) < 0) {
				//throw std::runtime_error("Connection error in DNSMappingAggregator");
				std::cerr << "WARNING: ";
				std::cerr << "Connection error in DNSMappingAggregator\n";
				return;
			}
			/* Before to start sending the message we need to communicate to the broker: */
			unsigned char header[4]; 

			/* The first part is made by two fixed byte: 01 */
			unsigned char header1[2]; 
			packi16(header1, 1);
			header[0] = header1[0];
			header[1] = header1[1];
			
			/* The second part is made by two byte: the first fixed to 0 and
			 * the second with this syntax:
			 * 1 -> if the database need to be reinitialized
			 * 0 -> if the database does not need to be reinitialized */
			unsigned char header2[2]; 
			packi16(header2, m_reset_db);
			header[2] = header2[0];
			header[3] = header2[1];

			/* Send message via the socket: */
			if ( (write(sock_fd, header, 4)) < 0 ) {
				//throw std::runtime_error("header not sent in DNSMappingAggregator");
				std::cerr << "WARNING: ";
				std::cerr << "header not sent in DNSMappingAggregator\n";
				close(sock_fd);
				return;
			}
			/* Send a first control message to notify the other end that the
			 * data transmission is going to start */
			_serialize_control_to_socket(true, sock_fd, c_time);
			
			dns_hash_table::iterator ht_it;
		    for (ht_it = m_dns_ht.begin(); ht_it != m_dns_ht.end(); ht_it++) {
				if (ht_it->second.queryCnt > m_query_threshold) 			
					_serialize_data_to_socket(&ht_it->first, &ht_it->second, sock_fd);
			}

			/* Send a first control message to notify the other end that the
			 * data transmission is finished */
			_serialize_control_to_socket(false, sock_fd, c_time);
			/* Close the socket used to transfer data to the broker */
			close(sock_fd);
			std::cout << "Aggregated mappings inserted into the database ";
			std::cout << c_time;
			std::cout << "\n";
		}

		void dump_dname_counter(uint32_t timestamp)
		{
            std::stringstream insert_into;
            insert_into << "INSERT INTO DnameCounter";
			insert_into	<< "(Timestamp, UmanReadableTimestamp, NumberOfFoundDomainName)";
            insert_into << " VALUES (?, ?, ?);";
           	
            /* -----------------   POPULATING THE DATABASE TABLE ------------- */
            std::shared_ptr<sql::PreparedStatement> prep_stmt(m_con->prepareStatement(insert_into.str()));
            prep_stmt->setInt(1, timestamp);
            /* convert timestamp in string "YYYY-MM-DD hh:mm:ss" */
            time_t curr_time;
            curr_time = (uint64_t)timestamp;
            struct tm *c_time = localtime(&curr_time);            
            std::stringstream unix_timestamp;

            unix_timestamp << c_time->tm_year+1900 << "-"; 
            unix_timestamp << c_time->tm_mon+1 << "-";
            unix_timestamp << c_time->tm_mday << " ";
            unix_timestamp << c_time->tm_hour << ":";
            unix_timestamp << c_time->tm_min << ":";
            unix_timestamp << c_time->tm_sec; 
            
            prep_stmt->setDateTime(2,unix_timestamp.str());
            prep_stmt->setInt(3, m_dname_cnt);
            
            prep_stmt->executeUpdate();
        }

		/**
		  * The function to check if the received messag has to be forwarded to
		  * the output.
		  * @param m	The message to be aggregated.
		  */
        void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */) 
        {
            auto mapping = std::dynamic_pointer_cast<const DNSMapping>(m);
			
            uint32_t c_time = mapping->time_sec();

			/* Intialize the timestamp, with the first received packet's timestamp */
		    if (m_next_aggregation == 0) {
				m_next_aggregation = c_time + m_time_bin_aggregation;
				m_next_printout = c_time + m_time_bin_printout;
				m_last_timestamp = c_time;
			}
		    
			/* Print the current timestamp every ten minutes of trace */
			if (c_time > m_next_printout) {
				std::cout << "Aggregator, timestamp: "<< c_time << "\n";
				m_next_printout += m_time_bin_printout;
			}
			
			/* After one hour print the table and flush its content */

			if (c_time > m_next_aggregation) {
				if (m_enable_txt_output)
					output_to_file(m_last_timestamp);
				if (m_enable_socket_output)
					output_to_socket(m_last_timestamp);
				if (m_enable_vis_buffer_output)
					dump_dname_counter(c_time);
				m_reset_db = 0;
				m_dns_ht.clear();
				m_dname_cnt = 0;
				m_last_timestamp = c_time;
				m_next_aggregation += m_time_bin_aggregation;
			}
			
			/* Decide the identifier to track */
			std::string identifier = mapping->name();
			//identifier = identifier.substr(0, identifier.length() - 1);
			uint32_t ip = mapping->address();
			
			DNSInfo new_entry;
			/* Check if the packet is already present in the hashtable */
			dns_hash_table::iterator ht_it = m_dns_ht.find(identifier);
            if(ht_it == m_dns_ht.end()) {
				new_entry.queryCnt = 1;
				new_entry.ipSet.insert(ip);
				m_dns_ht[identifier] = new_entry; 
				m_dname_cnt++;
			} else {
				ht_it->second.ipSet.insert(ip);
				ht_it->second.queryCnt++;
	        }
        }
    };

#ifndef _BLOCKMON_DOXYGEN_SKIP_
    REGISTER_BLOCK(DNSMappingAggregator,"DNSMappingAggregator");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */
}

