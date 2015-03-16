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
 * <blockinfo type="DNSAlertsCorrelator" invocation="direct" thread_exclusive="False">
 *   <humandesc>
 *		This block correlates the alerts coming from both the NR and
 *		the NX dns analysis </humandesc>
 *
 *   <shortdesc>
 *		Reads the mapping contained in the Suspicious file and assign a score to them.
 *   </shortdesc>
 *
 *   <gates>
 *     <gate type="input" name="in_msg" msg_type="Alert" m_start="0" m_end="0" />
 *     <gate type="output" name="out_msg" msg_type="Alert" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *    element params {
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
 *   	 <db_name val = "noErrorDnsAnalysis"/>
 *   	 <db_ip val = "localhost"/>
 *   	 <db_user val = "demons"/>
 *   	 <db_passwd val = "demons"/>
 *     </params>
 *   </paramsexample>
 *
 *   <variables>
 *   </variables>
 *
 * </blockinfo>
 */
#include <Block.hpp>
#include <BlockFactory.hpp>
#include <Packet.hpp>
#include <ClassId.hpp>
#include <boost/algorithm/string.hpp>
#include <Alert.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>     
#include <unordered_map>
#include <fstream>
#include <set>
#include <list>
#include <cmath>
#include <locale>

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

namespace blockmon
{
	class DNSAlertsCorrelator: public Block
	{
		int m_ingate_id;
		int m_outgate_id;
		std::ofstream m_malicious_file;

		/* Tables*/

		bool m_enable_txt_output;
		uint64_t m_detected;
		/* Driver Manager */
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
		DNSAlertsCorrelator(const std::string &name, invocation_type) : 
			Block(name, invocation_type::Direct),
			m_ingate_id(register_input_gate("in_msg")),
			m_outgate_id(register_output_gate("out_msg")),
			m_detected(0)
		{
		}

		/**
		 * @brief Destructor
		 */
		~DNSAlertsCorrelator()
		{
		}

		/**
		 * Configure the block
		 * @param n	The xml subtree.
		 */
		void _configure(const pugi::xml_node&  n) 
		{
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
			
			stmt->execute("DROP TABLE IF EXISTS nr_dns_analysis");

			std::stringstream create_table1;
			create_table1 << "CREATE TABLE nr_dns_analysis";
			create_table1 << "(Id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, "; 
			create_table1 << "Timestamp INT, ";
			create_table1 << "UmanReadableTimestamp TIMESTAMP, ";
			create_table1 << "FQDN VARCHAR(200), ";
			create_table1 << "MPF FLOAT) ";


			sql::PreparedStatement * prepare_stat;
			prepare_stat = m_con->prepareStatement(create_table1.str());
			prepare_stat->execute();
			std::cout << "#\t NR DNS Analysis table created\n";

			stmt->execute("DROP TABLE IF EXISTS nx_dns_analysis");

			std::stringstream create_table2;
			create_table2 << "CREATE TABLE nx_dns_analysis";
			create_table2 << "(Id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, "; 
			create_table2 << "Timestamp INT, ";
			create_table2 << "UmanReadableTimestamp TIMESTAMP, ";
			create_table2 << "FQDN VARCHAR(200), ";
			create_table2 << "MPF FLOAT) ";


			prepare_stat = m_con->prepareStatement(create_table2.str());
			prepare_stat->execute();
			std::cout << "#\t NX DNS Analysis table created\n";
		}

		void update_correlation_tables(const Alert *alert)	
		{
			std::vector<Alert::Node> alert_vec = *(alert->get_targets());
			std::stringstream insert_into;
			//std::cout << "Alert name: [" << alert->get_alert_name() << "]\n";
			if (alert->get_alert_name() == "MALICIOUS_DOMAIN")
				insert_into << "INSERT INTO nr_dns_analysis"; 
			else
				insert_into << "INSERT INTO nx_dns_analysis"; 
			
			insert_into << "(Timestamp, UmanReadableTimestamp, FQDN, MPF)";
			insert_into << " VALUES (?, ?, ?, ?);";

			std::shared_ptr<sql::PreparedStatement> prep_stmt(m_con->prepareStatement(insert_into.str()));

			prep_stmt->setInt(1, alert->get_create_time());
			/* convert timestamp in string "YYYY-MM-DD hh:mm:ss" */
			time_t curr_time;
			curr_time = alert->get_create_time();
			struct tm *c_time = localtime(&curr_time);            
			std::stringstream unix_timestamp;
			unix_timestamp << c_time->tm_year+1900 << "-"; 
			unix_timestamp << c_time->tm_mon+1 << "-";
			unix_timestamp << c_time->tm_mday << " ";
			unix_timestamp << c_time->tm_hour << ":";
			unix_timestamp << c_time->tm_min << ":";
			unix_timestamp << c_time->tm_sec; 

			prep_stmt->setDateTime(2,unix_timestamp.str());
			prep_stmt->setString(3, alert_vec[0].get_domain_name());
			prep_stmt->setDouble(4, alert->get_numeric_confidence());

			prep_stmt->executeUpdate();
		}

		bool correlate_mpf(const Alert *alert, float *avgScore)	
		{
			std::auto_ptr< sql::PreparedStatement > pstmt;
			std::auto_ptr< sql::ResultSet > res;

			std::vector<Alert::Node> alert_vec = *(alert->get_targets());

			std::stringstream select_query;

			if (alert->get_alert_name() == "MALICIOUS_DOMAIN")
				select_query << "SELECT * FROM nx_dns_analysis ";
			else
				select_query << "SELECT * FROM nr_dns_analysis ";

			select_query << "WHERE FQDN=";
			select_query << "'" << alert_vec[0].get_domain_name() << "'";
			select_query << " ORDER BY timestamp DESC LIMIT 1";
			
			pstmt.reset(m_con->prepareStatement(select_query.str()));
			res.reset(pstmt->executeQuery());
		
			while (res->next()) {
				*avgScore = (1.0 + (res->getDouble("MPF") + alert->get_numeric_confidence()))/3;
				return true;
			}
			return false;
		}
		
		
		void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */) 
		{
			const Alert* alert = static_cast<const Alert*>(m.get());

			update_correlation_tables(alert);
			float avgScore = 0.0;
			if (correlate_mpf(alert, &avgScore)) {
				std::cout << "Found! avg_score = " << avgScore + alert->get_numeric_confidence() << "\n";
				std::vector<Alert::Node> alert_vec = *(alert->get_targets());
				m_detected++;	
				std::shared_ptr<Alert> alert_domain =
				std::make_shared<Alert>("dns_alert_correlator", m_detected, "CORRELATED_DOMAIN");
				alert_domain.get()->add_target(Alert::Node(alert_vec[0].get_domain_name()));
				Alert::severity_level_t severity = Alert::sev_high;
				Alert::confidence_level_t confidence = Alert::conf_numeric;
				alert_domain.get()->set_assessment(severity, confidence);
				alert_domain.get()->set_confidence(avgScore);
				send_out_through(alert_domain, m_outgate_id);
			} else
				//std::cout << "not found\n";
               	send_out_through(std::move(m), m_outgate_id);
		}
	};

#ifndef _BLOCKMON_DOXYGEN_SKIP_
	REGISTER_BLOCK(DNSAlertsCorrelator,"DNSAlertsCorrelator");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */
}
