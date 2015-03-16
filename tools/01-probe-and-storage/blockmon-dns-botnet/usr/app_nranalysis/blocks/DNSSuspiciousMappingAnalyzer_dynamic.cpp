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
 * <blockinfo type="DNSSuspiciousMappingAnalyzerD" invocation="direct" thread_exclusive="False">
 *   <humandesc>
 *		This block receives a Pair [timestamp, fileName] from the
 *		DNSMappingAnalyzer block. This pair contains the name of the file and
 *		the timestamp of the Suspicious file to be analyzed. This block builds
 *		a graph from the suspicious file and takes the final decision about the
 *		domains, assigning a score to them.
 *	</humandesc>
 *
 *   <shortdesc>
 *		Reads the mapping contained in the Suspicious file and assign a score to them.
 *   </shortdesc>
 *
 *   <gates>
 *     <gate type="input" name="in_msg" msg_type="DNSMessage" m_start="0" m_end="0" />
 *     <gate type="output" name="out_msg" msg_type="Alert" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *    element params {
 *    	element geoip_file {
 *      	attribute val = {string} 
 *      }
 *    	element enable_txt_output {
 *      	attribute val = {bool} 
 *      }
 *    	element malicious_file_prefix {
 *      	attribute val = {string} 
 *      }
 *    	element enable_socket_output {
 *      	attribute val = {bool} 
 *      }
 *    	element socket_ip {
 *      	attribute val = {string} 
 *      }
 *    	element socket_port {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element enable_vis_buffer_output {
 *      	attribute val = {bool} 
 *      }
 *    	element geo_city_file {
 *      	attribute val = {string} 
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
 *    	element min_num_domains {
 *      	attribute val = {int} 
 *      }
 *    	element min_num_ips {
 *      	attribute val = {int} 
 *      }
 *    	element min_num_ases {
 *      	attribute val = {int} 
 *      }
 *    }
 *   </paramsschema>
 *
 *   <paramsexample>
 *     <params>
 *   	 <geoip_file val = "/home/schiavone/svn/demons/Sources/blockmon/main/node/usr/app_nranalysis/dns_trace/data/GeoIPASNum.dat"/>
 *   	 <enable_txt_output val = "false"/>
 *       <malicious_file_prefix val = "/home/schiavone/svn/demons/Sources/blockmon/main/node/usr/app_nranalysis/dns_output/malicious_"/>
 *		  <update_cnt_thr val = "1000"/>
 *		  <input_table_memory val = "86400"/>
 *		  <output_table_memory val = "86400"/>
 *   	 <enable_socket_output val = "false"/>
 *   	 <socket_ip val = "192.168.1.79"/>
 *   	 <socket_port val = "60007"/>
 *   	 <enable_vis_buffer_output val = "false"/>
 *   	 <geo_city_file val = "/home/schiavone/svn/demons/Sources/blockmon/main/node/usr/app_nranalysis/dns_trace/data/GeoLiteCity.dat"/>
 *   	 <db_name val = "noErrorDnsAnalysis"/>
 *   	 <db_ip val = "localhost"/>
 *   	 <db_user val = "mirko"/>
 *   	 <db_passwd val = "mirko"/>
 *   	 <ip_dist_score_threshold val = "0.5"/>
 *   	 <regex_list_file val = "/home/schiavone/svn/demons/Sources/blockmon/main/node/usr/app_nranalysis/dns_trace/data/regex_list.txt"/>
 *   	 <min_num_domains val = "10"/>
 *   	 <min_num_ips val = "5"/>
 *   	 <min_num_ases val = "3"/>
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
#include <arpa/inet.h>  
#include <sys/socket.h>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/graph/connected_components.hpp>
#include <boost/graph/subgraph.hpp>
#include <boost/regex.hpp>
#include <GeoIP.h>
#include <GeoIPCity.h>

#include "dns_analysis_results.pb.h"
#include "dns_statistics.pb.h"
#include <PairMsg.hpp>

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

#include <DNSSuspiciousMapping.hpp>

#define DOMAIN_COLOR 0
#define IP_ADDRESS_COLOR 1

using namespace boost;

namespace blockmon
{
	typedef property<edge_weight_t, float> EdgeWeightProperty;
	typedef property<vertex_name_t, std::string> VertexNameProperty;
	typedef property<vertex_color_t, uint32_t,
		VertexNameProperty> VertexProperties;
	
	// create a typedef for the Graph type
	typedef adjacency_list<vecS, vecS, undirectedS, VertexProperties, EdgeWeightProperty> Graph;
	
	// writing out the edges in the graph
	typedef graph_traits<Graph>::edge_descriptor Edge;
	// Create the vertices
	typedef graph_traits<Graph>::vertex_descriptor Vertex;
	
	struct suspiciousEntry {
		std::string timestamp;
		std::string domain;
		std::string ipAddress;
		std::string clientId;
		float weight;
		int numDomain;
	};

	typedef std::vector<suspiciousEntry> suspiciousData;

   	class DNSSuspiciousMappingAnalyzerD: public Block
   	{
                
        int m_ingate_id;
        int m_outgate_id;
		GeoIP *m_geodb;
		GeoIP *m_geo_city_db;
		int m_min_num_domains;
		int m_min_num_ips;
		int m_min_num_ases;
		float m_ip_dist_score_threshold;
		std::ofstream m_malicious_file;
		struct sockaddr_in m_serv_add;
		

		/* Tables*/

		std::list<DNSSuspiciousMapping> m_input_table;
		std::unordered_map<std::string, uint32_t> m_output_table;

		uint32_t m_input_table_memory;
		uint32_t m_output_table_memory;
		int m_update_cnt_thr;

		bool m_enable_txt_output;
		bool m_enable_socket_output;
		bool m_mapping_analyzer_permission;
		bool m_mapping_aggregator_permission;

		int m_update_cnt;

		int m_reset_db;

		uint64_t m_detected;
		uint32_t m_timestamp;

        /* Driver Manager */
		bool m_enable_vis_buffer_output;
        sql::Driver *m_db_driver;
        std::shared_ptr<sql::Connection> m_con;
        std::string m_db_name;
        std::string m_db_ip;
        std::string m_db_user;
        std::string m_db_passwd;

		/* Whitlisting */
		std::string m_regex_list_file;
		std::vector<boost::regex> m_regex_dict;

		std::hash<std::string> m_hash_fn;

    public:
		/**
		  * @brief Constructor
		  * @param name			The name of the source block
		  * @param invocation	Invocation type of the block.
		  */
        DNSSuspiciousMappingAnalyzerD(const std::string &name, invocation_type) : 
			Block(name, invocation_type::Direct),
        	m_ingate_id(register_input_gate("in_msg")),
        	m_outgate_id(register_output_gate("out_msg")),
			m_mapping_analyzer_permission(false),
			m_mapping_aggregator_permission(false),
			m_update_cnt(0),
			m_reset_db(1),
			m_detected(0),
			m_timestamp(0)
        {
		}

		/**
		  * @brief Destructor
		  */
		~DNSSuspiciousMappingAnalyzerD()
		{
			m_malicious_file.close();
		}

		/**
		  * Configure the block
		  * @param n	The xml subtree.
		  */
		void _configure(const pugi::xml_node&  n) 
        {
		    pugi::xml_node geoip_file = n.child("geoip_file");
        	if(!geoip_file) 
               	throw std::runtime_error("missing geoip_file");
           	std::string geoip_file_name = geoip_file.attribute("val").value();

			m_geodb = GeoIP_open(geoip_file_name.c_str(), GEOIP_CHECK_CACHE);

            pugi::xml_node update_cnt_thr = n.child("update_cnt_thr");
            if(!update_cnt_thr) 
                throw std::runtime_error("update_cnt_thr");
            m_update_cnt_thr = update_cnt_thr.attribute("val").as_uint();

            pugi::xml_node input_table_memory = n.child("input_table_memory");
            if(!input_table_memory) 
                throw std::runtime_error("missing input_table_memory");
            m_input_table_memory = input_table_memory.attribute("val").as_uint();

            pugi::xml_node output_table_memory = n.child("output_table_memory");
            if(!output_table_memory) 
                throw std::runtime_error("missing output_table_memory");
            m_output_table_memory = output_table_memory.attribute("val").as_uint();

            pugi::xml_node min_num_domains = n.child("min_num_domains");
            if(!min_num_domains) 
                throw std::runtime_error("min_num_domains");
            m_min_num_domains = min_num_domains.attribute("val").as_uint();

            pugi::xml_node min_num_ips = n.child("min_num_ips");
            if(!min_num_ips) 
                throw std::runtime_error("min_num_ips");
            m_min_num_ips = min_num_ips.attribute("val").as_uint();

            pugi::xml_node min_num_ases = n.child("min_num_ases");
            if(!min_num_ases) 
                throw std::runtime_error("min_num_ases");
            m_min_num_ases = min_num_ases.attribute("val").as_uint();

            pugi::xml_node ip_dist_score_threshold = n.child("ip_dist_score_threshold");
            if(!ip_dist_score_threshold) 
                throw std::runtime_error("missing ip_dist_score_threshold");
            m_ip_dist_score_threshold = ip_dist_score_threshold.attribute("val").as_float();

            pugi::xml_node enable_socket_output = n.child("enable_socket_output");
            if(!enable_socket_output) 
                throw std::runtime_error("missing enable_socket_output");
            m_enable_socket_output = enable_socket_output.attribute("val").as_bool();

			if (m_enable_socket_output) {
				/* Read IP address of the socket hosting the database */
        		pugi::xml_node socket_ip = n.child("socket_ip");
        		if(!socket_ip) 
        		    throw std::runtime_error("socket_ip");
        		std::string ser_ip = socket_ip.attribute("val").value();
				/* Check if the address is correctly inserted */
				if ((inet_pton(AF_INET, ser_ip.c_str(), 
					&m_serv_add.sin_addr)) <= 0)
					throw std::runtime_error("address creation error");
        		/* Read the port to be used */
				pugi::xml_node socket_port = n.child("socket_port");
        		if(!socket_port) 
        		    throw std::runtime_error("socket_port");
				m_serv_add.sin_port =
					htons(socket_port.attribute("val").as_uint());
				/* Address type is INET */
				m_serv_add.sin_family = AF_INET;
			}

            pugi::xml_node enable_txt_output = n.child("enable_txt_output");
            if(!enable_txt_output) 
                throw std::runtime_error("missing enable_txt_output");
            m_enable_txt_output = enable_txt_output.attribute("val").as_bool();

			if (m_enable_txt_output) {
            	pugi::xml_node malicious_file_prefix =
					n.child("malicious_file_prefix");
            	if(!malicious_file_prefix) 
            	    throw std::runtime_error("missing malicious_file_prefix");
				m_malicious_file.open(malicious_file_prefix.attribute("val").value());
			}

            pugi::xml_node enable_vis_buffer_output = n.child("enable_vis_buffer_output");
            if(!enable_vis_buffer_output) 
                throw std::runtime_error("missing enable_vis_buffer_output");
            m_enable_vis_buffer_output = enable_vis_buffer_output.attribute("val").as_bool();

			if (m_enable_vis_buffer_output) {
		    	pugi::xml_node geo_city_file = n.child("geo_city_file");
        		if(!geo_city_file) 
            	   	throw std::runtime_error("missing geo_city_file");
           		std::string geo_city_file_name = geo_city_file.attribute("val").value();

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

				m_geo_city_db =
					GeoIP_open(geo_city_file_name.c_str(), GEOIP_CHECK_CACHE);

	            std::stringstream sql;
	            /* Using the Driver to create a connection */
	
	            m_db_driver = sql::mysql::get_driver_instance();
				std::shared_ptr<sql::Connection> con_tmp(m_db_driver->connect(m_db_ip, 
					m_db_user, m_db_passwd));
	            m_con = con_tmp;
	
				/* The usage of USE is not supported by the prepared statement protocol */
				std::shared_ptr<sql::Statement> stmt(m_con->createStatement());
				stmt->execute("USE " + m_db_name);
				
				stmt->execute("DROP TABLE IF EXISTS DNSAnalysis");
	
				std::stringstream create_table;
	            create_table << "CREATE TABLE DNSAnalysis";
				create_table << "(Id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, "; 
				create_table <<	"Timestamp INT, ";
				create_table << "UmanReadableTimestamp TIMESTAMP, ";
				create_table << "DomainName VARCHAR(200), ";
				create_table << "NumberOfIPs INT, ";
				create_table << "IP VARCHAR(30), ";
				create_table << "IPLocationLon FLOAT, ";
				create_table << "IPLocationLat FLOAT, ";
				create_table << "Score FLOAT, ";
				create_table << "NumberOfQueries INT, ";
				create_table << "AppName VARCHAR(30))";
	
	            sql::PreparedStatement * prepare_stat;
	            prepare_stat = m_con->prepareStatement(create_table.str());
	            prepare_stat->execute();
		    	std::cout << "#\t DNS Analysis table created\n";
			}

	    	pugi::xml_node regex_list_file = n.child("regex_list_file");
    		if(!regex_list_file) 
        	   	throw std::runtime_error("missing regex_list_file");
       		m_regex_list_file = regex_list_file.attribute("val").value();

		}

		std::string ip_to_string(uint32_t ip)
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
		
		void getAsnAndOrganization(uint32_t ip, std::string *retAsn, std::string *retOrg)
		{
			char *as = GeoIP_name_by_addr(m_geodb, ip_to_string(ip).c_str());
			if (as) {
				std::string asn(as);
				delete as;
				if (asn[0] == 'A' && asn[1] == 'S') {
					unsigned int first_space = asn.find(" ");
					if (first_space != asn.npos) {
						*retAsn = asn.substr(0, first_space);
						*retOrg = asn.substr(first_space + 1, asn.length());
						return;
					}
				}
			}
			*retAsn = "";
			*retOrg = "";
		}

		std::pair<float, float> getLongitudeAndLatitude(uint32_t ip)
		{
			std::pair<float, float> result(0.0, 0.0);
			GeoIPRecord *rec = NULL;
			rec = GeoIP_record_by_addr(m_geo_city_db, ip_to_string(ip).c_str());
			if (rec) {
				result.first = rec->longitude;
				result.second = rec->latitude;
			}
			return result;
		}

		void loadRegEx()
		{
			std::ifstream fin; 
			std::string line;

			fin.open(m_regex_list_file);
			if (!fin)
				throw std::runtime_error("Cannot open the file regexes file");
			m_regex_dict.clear();

			while (1) {
				getline(fin, line);
				if (!(line == "" || (line[0] == '/' && line[1] == '/'))) {
					boost::regex e(line);  
					m_regex_dict.push_back(e);
				}
				if (fin.eof())
					break;
			}
			fin.close();
		}

		void whiteListInputTable()
		{
			std::list<DNSSuspiciousMapping>::iterator inputIt;
			
			int whitelisted_cnt = 0;

			for (inputIt = m_input_table.begin(); inputIt != m_input_table.end(); inputIt++) {
				inputIt->unset_whitelisted();
				for (unsigned int i = 0; i < m_regex_dict.size(); i++) {
					if (boost::regex_match(inputIt->domain_name(), m_regex_dict.at(i))) {
						inputIt->set_whitelisted();
						whitelisted_cnt++;
						break;
					}
				}
			}
			std::cout << "InputTable size: " << m_input_table.size();
			std::cout << " whitelisted: " << whitelisted_cnt << "\n";
		}

		Graph* buildMappingGraph()
		{
			// declare a graph object
			Graph *g = new Graph;
		
			property_map<Graph, vertex_name_t>::type nameId = get(vertex_name, *g);
			property_map<Graph, vertex_color_t>::type color = get(vertex_color, *g);
			property_map<Graph, edge_weight_t>::type edgeWeight = get(edge_weight, *g);
			
			/* We need these containers to be sure that the nodes that we are adding to
			 * the graph were not already there*/
			std::unordered_map<std::string, Vertex> domainSet;
			std::unordered_map<std::string, Vertex> ipSet;
			std::unordered_map<std::string, Vertex>::iterator it;
			
			bool newDomain = true;
			bool newIP = true;
			
			std::list<DNSSuspiciousMapping>::iterator inputIt;

			for (inputIt = m_input_table.begin(); inputIt != m_input_table.end(); inputIt++) {
				if (inputIt->whitelisted())
					continue;
				/* Check if this domain is already in the graph */
				it = domainSet.find(inputIt->domain_name());
				Vertex u1;
				if (it == domainSet.end()) {
					u1 = add_vertex(*g);
					nameId[u1] = inputIt->domain_name();
					color[u1] = DOMAIN_COLOR;
					domainSet.insert(std::pair<std::string, Vertex>(inputIt->domain_name(), u1));
				} else {
					u1 = it->second;
					newDomain = false;
				}
				/* Check if this ip is already in the graph */
				it = ipSet.find(boost::lexical_cast<std::string>(inputIt->address()));
				Vertex u2;
				if (it == ipSet.end()) {
					u2 = add_vertex(*g);
					nameId[u2] = boost::lexical_cast<std::string>(inputIt->address());
					color[u2] = IP_ADDRESS_COLOR;
					ipSet.insert(std::pair<std::string, Vertex>
						(boost::lexical_cast<std::string>(inputIt->address()), u2));
				} else {
					u2 = it->second;
					newIP = false;
				}
				
				/* Add a new edge */
				if (newDomain || newIP) {
					/* The Domain or the IP is new, add a new edge to the graph*/
					Edge e1;
					e1 = (add_edge(u1, u2, *g)).first;
					edgeWeight[e1] = inputIt->score();
				} else {
					/* The Domain and the IP are not new, check if this edge already exists*/
					Edge e1;
					bool exist;
					tie(e1, exist) = edge(u1, u2, *g);
					if (exist) {
						/* The edge already exist, just update the weight */
						if (edgeWeight[e1] < inputIt->score())
							edgeWeight[e1] = inputIt->score();
					} else {
						/* The edge do not exist, create it! */
						e1 = (add_edge(u1, u2, *g)).first;
						edgeWeight[e1] = inputIt->score();
					}
				}
			}
			return g;
		}
		
		std::vector<std::set<int>> filterMappingGraph(Graph *g)
		{
			property_map<Graph, vertex_color_t>::type color = get(vertex_color, *g);
			
		    std::vector<int> component(num_vertices(*g));
		    int num = connected_components(*g, &component[0]);
		    
			/* Put component into a more suitable data staructure */
			std::vector<std::set<int> > subGraph(num);
			//std::unordered_map<int, std::set<int>> subGraph(num);
			
			for (unsigned int i = 0; i < component.size(); i++) {
				int comp = component.at(i);
				subGraph[comp].insert(i);
			}
			
			std::vector<std::set<int> > subGraphFiltered;
		
			for (unsigned int i = 0; i < subGraph.size(); i++) {
				std::set<int>::iterator it;
				int domCnt = 0;
				int ipCnt = 0;
				std::set<int> *setVer = &subGraph[i];
				for (it = setVer->begin(); it != setVer->end(); it++) {
					Vertex v = vertex( *it, *g);	
					if (color[v] == DOMAIN_COLOR)
						domCnt++;
					else if (color[v] == IP_ADDRESS_COLOR)
						ipCnt++;
					else
						throw std::runtime_error("Error in the graph color");
				}	
				/* If the filter condition is not met we skip this component */
				#if 0
				if (domCnt < m_min_num_domains || ipCnt < m_min_num_ips)
					continue;
				subGraphFiltered.push_back(*setVer);
				#endif
				if (domCnt >= m_min_num_domains && ipCnt >= m_min_num_ips)
					subGraphFiltered.push_back(*setVer);
			}

			return subGraphFiltered;
		}
		
		void filterFromLegitimate(Graph *g, std::vector<std::set<int> > *comp)
		{
			std::unordered_map<std::string, int> totDomOcc;
			std::unordered_map<std::string, int>::iterator it;
		
			property_map<Graph, vertex_name_t>::type nameId = get(vertex_name, *g);
		
			for (unsigned int i = 0; i < comp->size(); i++) {
				std::set<int>::iterator it;
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
					Vertex v = vertex( *it, *g);
					totDomOcc[nameId[v]] = 1;
				}
			}
		
			std::list<DNSSuspiciousMapping>::iterator inputIt;

			for (inputIt = m_input_table.begin(); inputIt != m_input_table.end(); inputIt++) {
				it = totDomOcc.find(inputIt->domain_name());
				if (it != totDomOcc.end()) {
					int val = inputIt->num_blocks() + 1;
					if (it->second < val)
						it->second = val;
				}		
			}
		
			for (unsigned int i = 0; i < comp->size(); i++) {
				std::set<int>::iterator it;
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
					Vertex v = vertex( *it, *g);
					int degree = out_degree(v, *g);
					int numDom = totDomOcc[nameId[v]];
					if ( numDom - degree > degree)
						clear_vertex(v, *g);
				}
			}
		}
		
		std::vector< std::set<int> > filterByAsn(Graph *g,
			std::vector<std::set<int> > *comp)
		{
			property_map<Graph, vertex_name_t>::type nameId = get(vertex_name, *g);
			property_map<Graph, vertex_color_t>::type color = get(vertex_color, *g);
			
			int minUniqueASCount = m_min_num_ases;

			std::vector< std::set<int> > filtered;

			for (unsigned int i = 0; i < comp->size(); i++) {
				std::set<int>::iterator it;
				std::set<std::string> ASesPerComponent;
				std::set<int> *setVer = &comp->at(i);
				for (it = setVer->begin(); it != setVer->end(); it++) {
					Vertex v = vertex( *it, *g);
					int cnt = 0;
					if (color[v] == IP_ADDRESS_COLOR) {
						cnt++;
						std::string asn, org;
						uint32_t ip = atoi(nameId[v].c_str());
						getAsnAndOrganization(ip, &asn, &org);
						ASesPerComponent.insert(org);
					}
				}
				if (ASesPerComponent.size() >= (unsigned int)minUniqueASCount)
					filtered.push_back(comp->at(i));
			}

			return filtered;
		}
		
		float IPDistScore(std::vector<uint32_t> *ipVec)
		{
			std::unordered_map<uint32_t, std::vector<int>> slash24s;
			for (unsigned int i = 0; i < ipVec->size(); i++)
				slash24s[ipVec->at(i) >> 8].push_back((ipVec->at(i) << 24)>>24);
			std::unordered_map<uint32_t, std::vector<int>>::iterator slash24;
			
			float totalScore = 0;
			float LOG2_255 = log2(255);
		
			for (slash24 = slash24s.begin(); slash24 != slash24s.end(); slash24++) {
				int numIPs = slash24->second.size();
				if (numIPs == 1)
					totalScore += 1;
				else {
					int maxIP = 0, minIP = 255;
					for (int j = 0; j < numIPs; j++) {
						if (slash24->second.at(j) < minIP)
							minIP = slash24->second.at(j);
						if (slash24->second.at(j) > maxIP)
							maxIP = slash24->second.at(j);
					}
					float IPDistMean = (maxIP - minIP)/float(numIPs - 1);
					float alpha = -log2(IPDistMean/255.0)/LOG2_255;
					float beta = -log2(numIPs/255.0)/LOG2_255;
					//float score = ((1 - alpha + beta)/2)*numIPs;
					float score = (1 - alpha + alpha * beta);
					totalScore += score;
				}
			}
			return (totalScore/slash24s.size());
		}

		std::vector< std::set<int> > filterByIPDistScore(Graph *g,
			std::vector<std::set<int> > *comp)
		{
			property_map<Graph, vertex_name_t>::type nameId = get(vertex_name, *g);
			property_map<Graph, vertex_color_t>::type color = get(vertex_color, *g);
			
			std::vector< std::set<int> > filtered;

			for (unsigned int i = 0; i < comp->size(); i++) {
				std::set<int>::iterator it;
				std::vector<uint32_t> ipVec;
				std::set<int> *setVer = &comp->at(i);
				for (it = setVer->begin(); it != setVer->end(); it++) {
					Vertex v = vertex( *it, *g);
					if (color[v] == IP_ADDRESS_COLOR) {
						uint32_t ip = atoi(nameId[v].c_str());
						ipVec.push_back(ip);
					}
				}
				if (IPDistScore(&ipVec) >= m_ip_dist_score_threshold)
					filtered.push_back(comp->at(i));
			}

			return filtered;
		}

		void printComponents(Graph *g, std::vector< std::set<int> > *comp)
		{
			property_map<Graph, vertex_name_t>::type nameId = get(vertex_name, *g);
			
			for (unsigned int i = 0; i < comp->size(); i++) {
				std::set<int>::iterator it;
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
					Vertex v = vertex( *it, *g);	
					std::cout << nameId[v] << " ";
				}	
				std::cout << "\n";
			}
		}

		int64_t compute_avg_ip_distance(std::vector<uint32_t> ipVec)
		{
			if (ipVec.size() < 2)
				return 0;
			sort(ipVec.begin(), ipVec.end());
			std::vector<int64_t> distances;
			for (unsigned int i = 0; i < ipVec.size() - 1; i++) {
				uint32_t a = ipVec.at(i);
				uint32_t b = ipVec.at(i + 1);
				int64_t res = (int64_t)(b - a);
				distances.push_back(res);
			}
			
			sort(distances.begin(), distances.end());
			int idx = int(distances.size()/2);
			
			return distances.at(idx);
		}

		void output_to_txt(Graph *g, std::vector< std::set<int> > *comp)
		{
			property_map<Graph, vertex_name_t>::type nameId = get(vertex_name, *g);
			property_map<Graph, vertex_color_t>::type color = get(vertex_color, *g);
			property_map<Graph, edge_weight_t>::type edgeWeight = get(edge_weight, *g);
		
			typedef graph_traits<Graph>::out_edge_iterator edge_iter;
			
			for (unsigned int i = 0; i < comp->size(); i++) {
				std::set<int>::iterator it;
				std::vector<uint32_t> addrs;
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
					Vertex v = vertex( *it, *g);	
					if (color[v] == IP_ADDRESS_COLOR)
						addrs.push_back(atoi(nameId[v].c_str()));
				}
				float ipDistanceScore = IPDistScore(&addrs);
					
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
					Vertex v = vertex( *it, *g);	
					if (color[v] == DOMAIN_COLOR) {
						if (m_output_table.count(nameId[v]) == 0) {
							m_output_table.insert(std::pair<std::string, uint32_t>
								(nameId[v], m_timestamp));
							edge_iter ei, ei_end;
							float finalScore = 0.0;
							int cnt = 0;
							for (tie(ei, ei_end) = out_edges(v, *g); ei != ei_end; ++ei) {
								finalScore += edgeWeight[*ei];
								//Vertex u = target(*ei, *g);
								cnt++;
							}
							if (cnt)
								finalScore = finalScore/cnt;

							m_malicious_file << m_timestamp << " "
											 << nameId[v]   << " " 
											 << finalScore 		<< " " 
											 << ipDistanceScore  << "\n";
						}
					}
				}	
			}
			m_malicious_file.flush();
		}

		void output_to_vis_buffer(Graph *g, std::vector< std::set<int> > *comp)
		{
			property_map<Graph, vertex_name_t>::type nameId = get(vertex_name, *g);
			property_map<Graph, vertex_color_t>::type color = get(vertex_color, *g);
			property_map<Graph, edge_weight_t>::type edgeWeight = get(edge_weight, *g);
		
			typedef graph_traits<Graph>::out_edge_iterator edge_iter;

            std::stringstream insert_into;
            insert_into << "INSERT INTO DNSAnalysis"; 
			insert_into	<< "(Timestamp, UmanReadableTimestamp, DomainName, NumberOfIPs, ";
			insert_into	<< "IP, IPLocationLon, IPLocationLat, Score, NumberOfQueries, AppName)";
            insert_into << " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

            std::shared_ptr<sql::PreparedStatement> prep_stmt(m_con->prepareStatement(insert_into.str()));
            prep_stmt->setInt(1, (uint64_t)m_timestamp);

            /* convert timestamp in string "YYYY-MM-DD hh:mm:ss" */
            time_t curr_time;
            curr_time = (uint64_t)m_timestamp;
            struct tm *c_time = localtime(&curr_time);            
            std::stringstream unix_timestamp;
            unix_timestamp << c_time->tm_year+1900 << "-"; 
            unix_timestamp << c_time->tm_mon+1 << "-";
            unix_timestamp << c_time->tm_mday << " ";
            unix_timestamp << c_time->tm_hour << ":";
            unix_timestamp << c_time->tm_min << ":";
            unix_timestamp << c_time->tm_sec; 
            
            prep_stmt->setDateTime(2,unix_timestamp.str());

			for (unsigned int i = 0; i < comp->size(); i++) {
				std::set<int>::iterator it;
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
					Vertex v = vertex( *it, *g);	
					if (color[v] == DOMAIN_COLOR) {
						if (m_output_table.count(nameId[v]) == 0) {
							m_output_table.insert(std::pair<std::string, uint32_t>
								(nameId[v], m_timestamp));
							edge_iter ei, ei_end;
							float score = 0.0;
							int cnt = 0;
							std::set<std::string> addrs;
							for (tie(ei, ei_end) = out_edges(v, *g); ei != ei_end; ++ei) {
								score += edgeWeight[*ei];
								cnt++;
								Vertex u = target(*ei, *g);
								addrs.insert(nameId[u]);
							}
							if (cnt)
								score = score/cnt;
							
							prep_stmt->setString(3, nameId[v]);
							prep_stmt->setInt(4, addrs.size());

							prep_stmt->setDouble(8, score);
							
							prep_stmt->setInt(9, 1);
							prep_stmt->setString(10, "NR Analysis");
							
							std::set<std::string>::iterator it;
							for (it = addrs.begin(); it != addrs.end(); it++) {
								std::pair<float, float> loc =
									getLongitudeAndLatitude(atoi(it->c_str()));
								prep_stmt->setString(5, ip_to_string(atoi(it->c_str())));
								prep_stmt->setDouble(6, loc.first);
								prep_stmt->setDouble(7, loc.second);
            					prep_stmt->executeUpdate();
							}
						}
					}
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
			dns_analysis_results message_to_send;
			dns_analysis_results::ControlMessage *control_to_send =
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
			if ( (write(sock_fd, header, 4)) < 0 ) {
				//throw std::runtime_error("header not sent in DNSSuspiciousMappingAnalyzerD");
				std::cerr << "WARNING: ";
				std::cerr << "header not sent in DNSSuspiciousMappingAnalyzerD\n";
				return;
			}
			/* Then we can finally send the protobuf message */
			if ( (write(sock_fd, string_to_send.c_str(), 
				string_to_send.length())) < 0 ) {
				//throw std::runtime_error("message not sent in DNSSuspiciousMappingAnalyzerD");
				std::cerr << "WARNING: ";
				std::cerr << "message not sent in DNSSuspiciousMappingAnalyzerD\n";
				return;
			}
		}

		void _serialize_data_to_socket(const std::string *dname, float score,
			int sock_fd)
		{
			/* Prepare the dns_statistics message */
			dns_analysis_results message_to_send;
			dns_analysis_results::DataMessage *data_to_send =
				message_to_send.mutable_data();

			data_to_send->set_dname(*dname);
			data_to_send->set_timestamp(m_timestamp);
			data_to_send->set_whitelisted(false);
			data_to_send->set_score(score);

			if (!message_to_send.IsInitialized()) {
				//throw std::runtime_error
				std::cerr << "WARNING: ";
				//	("protocol buffer object not initialized in DNSSuspiciousMappingAnalyzerD");
				std::cerr << "protocol buffer object not initialized in DNSSuspiciousMappingAnalyzerD\n";
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
				//throw std::runtime_error("header not sent in DNSSuspiciousMappingAnalyzerD");
				std::cerr << "WARNING: ";
				std::cerr << "header not sent in DNSSuspiciousMappingAnalyzerD\n";
				return;
			}
			/* Then we can finally send the protobuf message */
			if ( (write(sock_fd, string_to_send.c_str(), 
				string_to_send.length())) < 0 ) {
				//throw std::runtime_error("message not sent in DNSSuspiciousMappingAnalyzerD");
				std::cerr << "WARNING: ";
				std::cerr << "message not sent in DNSSuspiciousMappingAnalyzerD\n";
				return;
			}
			/* Deallocate the string */
		}

		void output_to_socket(Graph *g, std::vector<std::set<int> > *comp)
		{
			int sock_fd;
			/* create socket */
			if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				//throw std::runtime_error("Socket creatin error in DNSSuspiciousMappingAnalyzerD");
				std::cerr << "WARNING: ";
				std::cerr << "socket creatin error in DNSSuspiciousMappingAnalyzerD\n";
				return;
			}
			/* Check if is possible to connect to the server */
			if (connect(sock_fd, (struct sockaddr *)&m_serv_add,
				sizeof(m_serv_add)) < 0) {
				//throw std::runtime_error("Connection error in DNSSuspiciousMappingAnalyzerD");
				std::cerr << "WARNING: ";
				std::cerr << "connection error in DNSSuspiciousMappingAnalyzerD\n";
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
				//throw std::runtime_error("header not sent in DNSSuspiciousMappingAnalyzerD");
				std::cerr << "WARNING: ";
				std::cerr << "header not sent in DNSSuspiciousMappingAnalyzerD\n";
				close(sock_fd);
				return;
			}

			/* Send a first control message to notify the other end that the
			 * data transmission is going to start */

			_serialize_control_to_socket(true, sock_fd);
			
			property_map<Graph, vertex_name_t>::type nameId = get(vertex_name, *g);
			property_map<Graph, vertex_color_t>::type color = get(vertex_color, *g);
			property_map<Graph, edge_weight_t>::type edgeWeight = get(edge_weight, *g);
		
			typedef graph_traits<Graph>::out_edge_iterator edge_iter;
			for (unsigned int i = 0; i < comp->size(); i++) {
				std::set<int>::iterator it;
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
					Vertex v = vertex( *it, *g);	
					if (color[v] == DOMAIN_COLOR) {
						if (m_output_table.count(nameId[v]) == 0) {
							m_output_table.insert(std::pair<std::string, uint32_t>
								(nameId[v], m_timestamp));
							edge_iter ei, ei_end;
							float avg = 0.0;
							int cnt = 0;
							std::set<std::string> addrs;
							for (tie(ei, ei_end) = out_edges(v, *g); ei != ei_end; ++ei) {
								avg += edgeWeight[*ei];
								cnt++;
								Vertex u = target(*ei, *g);
								addrs.insert(nameId[u]);
							}
							if (cnt)
								avg = avg/cnt;
							_serialize_data_to_socket(&nameId[v], avg, sock_fd);
						}
					}
				}	
			}

			/* Send a first control message to notify the other end that the
			 * data transmission is finished */
			
			_serialize_control_to_socket(false, sock_fd);

			/* Close the socket used to transfer data to the broker */
			close(sock_fd);
			std::cout << "Suspicious mappings updated on the database ";
			std::cout << m_timestamp;
			std::cout << "\n";
		}

		void refreshTables()
		{
			std::unordered_map<std::string, uint32_t>::iterator it;
			
			std::cout << "size input before: " << m_input_table.size() << "\n";

			while(1) {
				if (m_timestamp - m_input_table.front().message_time() > m_input_table_memory)
					m_input_table.pop_front();
				else
					break;
			}

			std::cout << "size input after: " << m_input_table.size() << "\n";
			
			std::vector<std::unordered_map<std::string, uint32_t>::iterator> toDelete;

			for (it = m_output_table.begin(); it != m_output_table.end(); it++) {
				if (m_timestamp - it->second > m_output_table_memory)
					toDelete.push_back(it);
			}

			for (unsigned int i = 0; i < toDelete.size(); i++)
				m_output_table.erase(toDelete[i]);
		}

		void outputAlerts(Graph *g, std::vector< std::set<int> > *comp)
		{
			property_map<Graph, vertex_name_t>::type nameId = get(vertex_name, *g);
			property_map<Graph, vertex_color_t>::type color = get(vertex_color, *g);
			property_map<Graph, edge_weight_t>::type edgeWeight = get(edge_weight, *g);
		
			typedef graph_traits<Graph>::out_edge_iterator edge_iter;
			
			for (unsigned int i = 0; i < comp->size(); i++) {
				std::set<int>::iterator it;
					
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
					Vertex v = vertex( *it, *g);	
					if (color[v] == DOMAIN_COLOR) {
						edge_iter ei, ei_end;
						float finalScore = 0.0;
						int cnt = 0;
						std::vector<uint32_t> malicious_ip_addresses;
						for (tie(ei, ei_end) = out_edges(v, *g); ei != ei_end; ++ei) {
							finalScore += edgeWeight[*ei];
							Vertex u = target(*ei, *g);
							uint32_t ip = atoi(nameId[u].c_str());
							malicious_ip_addresses.push_back(ip);
							cnt++;
						}
						if (cnt)
							finalScore = finalScore/cnt;
						std::vector<Alert::Node> malicious_domain_name;
						
						assert(malicious_ip_addresses.size());

						for(unsigned int i = 0; i < malicious_ip_addresses.size(); i++)
							malicious_domain_name.push_back(
								Alert::Node(malicious_ip_addresses.at(i), nameId[v]));
						
						m_detected++;	
						std::shared_ptr<Alert> alert_domain =
							std::make_shared<Alert>(get_name(), m_detected, "MALICIOUS_DOMAIN");
						alert_domain.get()->set_targets(malicious_domain_name);
						Alert::severity_level_t severity = Alert::sev_high;
						Alert::confidence_level_t confidence = Alert::conf_numeric;
						alert_domain.get()->set_assessment(severity, confidence);
						alert_domain.get()->set_confidence(finalScore);
						send_out_through(alert_domain,m_outgate_id);
					}
				}	
			}
		}

        void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */) 
        {
            auto mapping = std::dynamic_pointer_cast<const DNSSuspiciousMapping>(m);
	
			if (!m_timestamp)
				m_timestamp = mapping->message_time();
			
			if (m_timestamp < mapping->message_time())
				m_timestamp = mapping->message_time();

			m_input_table.push_back(*mapping);

			m_update_cnt++;

			if (m_update_cnt < m_update_cnt_thr)
				return;
			
			m_update_cnt = 0;

			refreshTables();
			
			loadRegEx();
			whiteListInputTable();

			// declare a graph object
			Graph *g = buildMappingGraph();
		
			std::vector< std::set<int> > components;
			components = filterMappingGraph(g);
			
			filterFromLegitimate(g, &components);

			components = filterMappingGraph(g);

			std::vector< std::set<int> > final;
			
			final = filterByAsn(g, &components);
			
			std::vector< std::set<int> > ipDistFiltered;

			ipDistFiltered = filterByIPDistScore(g, &final);

			outputAlerts(g, &ipDistFiltered);

			if (ipDistFiltered.size() == 0)
				return;

			if (m_enable_socket_output)
				output_to_socket(g, &ipDistFiltered);
			
			if (m_enable_txt_output)
				output_to_txt(g, &ipDistFiltered);

			if (m_enable_vis_buffer_output)
				output_to_vis_buffer(g, &ipDistFiltered);

			m_reset_db = 0;
			

			delete g;
        }
    };

#ifndef _BLOCKMON_DOXYGEN_SKIP_
    REGISTER_BLOCK(DNSSuspiciousMappingAnalyzerD,"DNSSuspiciousMappingAnalyzerD");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */
}
