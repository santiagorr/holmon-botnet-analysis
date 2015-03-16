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
 * <blockinfo type="DNSSuspiciousMappingAnalyzer" invocation="direct" thread_exclusive="False">
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
 *   	 <geoip_file val = "/home/mirko/dns_trace/data/GeoIPASNum.dat"/>
 *   	 <enable_txt_output val = "false"/>
 *       <malicious_file_prefix val = "/home/mirko/dns_output/malicious_"/>
 *   	 <enable_socket_output val = "false"/>
 *   	 <socket_ip val = "192.168.1.79"/>
 *   	 <socket_port val = "60007"/>
 *   	 <enable_vis_buffer_output val = "false"/>
 *   	 <geo_city_file val = "/home/mirko/dns_trace/data/GeoLiteCity.dat"/>
 *   	 <db_name val = "dnsAnalysis"/>
 *   	 <db_ip val = "192.168.0.55"/>
 *   	 <db_user val = "mirko"/>
 *   	 <db_passwd val = "mirko"/>
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
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>     
#include <unordered_map>
#include <fstream>
#include <set>
#include <locale>
#include <arpa/inet.h>  
#include <sys/socket.h>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/graph/connected_components.hpp>
#include <boost/graph/subgraph.hpp>
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

   	class DNSSuspiciousMappingAnalyzer: public Block
   	{
                
        int m_ingate_id;
		GeoIP *m_geodb;
		GeoIP *m_geo_city_db;
		int m_min_num_domains;
		int m_min_num_ips;
		int m_min_num_ases;
		std::string m_malicious_file_prefix;
		struct sockaddr_in m_serv_add;

		/* Output destination: 'file' of 'socket' */
		bool m_enable_txt_output;
		bool m_enable_socket_output;
		bool m_mapping_analyzer_permission;
		bool m_mapping_aggregator_permission;
		std::string m_suspicious_file;
		int m_reset_db;
		uint32_t m_timestamp;

        /* Driver Manager */
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
        DNSSuspiciousMappingAnalyzer(const std::string &name, invocation_type) : 
			Block(name, invocation_type::Direct),
        	m_ingate_id(register_input_gate("in_msg")),
			m_mapping_analyzer_permission(false),
			m_mapping_aggregator_permission(false),
			m_suspicious_file(""),
			m_reset_db(1),
			m_timestamp(0)
        {
		}

		/**
		  * @brief Destructor
		  */
		~DNSSuspiciousMappingAnalyzer()
		{
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
            	m_malicious_file_prefix =
					malicious_file_prefix.attribute("val").value();
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

		Graph* buildMappingGraph(suspiciousData *data)
		{
			if (data == NULL) {
				std::cerr << "data is NULL\n";
				return NULL;
			}
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
		
			for (unsigned int i = 0; i < data->size(); i++) {
				/* Check if this domain is already in the graph */
				it = domainSet.find(data->at(i).domain);
				Vertex u1;
				if (it == domainSet.end()) {
					u1 = add_vertex(*g);
					nameId[u1] = data->at(i).domain;
					color[u1] = DOMAIN_COLOR;
					domainSet.insert(std::pair<std::string, Vertex>(data->at(i).domain, u1));
				} else {
					u1 = it->second;
					newDomain = false;
				}
				/* Check if this ip is already in the graph */
				it = ipSet.find(data->at(i).ipAddress);
				Vertex u2;
				if (it == ipSet.end()) {
					u2 = add_vertex(*g);
					nameId[u2] = data->at(i).ipAddress;
					color[u2] = IP_ADDRESS_COLOR;
					ipSet.insert(std::pair<std::string, Vertex>(data->at(i).ipAddress, u2));
				} else {
					u2 = it->second;
					newIP = false;
				}
				
				/* Add a new edge */
				if (newDomain || newIP) {
					/* The Domain or the IP is new, add a new edge to the graph*/
					Edge e1;
					e1 = (add_edge(u1, u2, *g)).first;
					edgeWeight[e1] = data->at(i).weight;
				} else {
					/* The Domain and the IP are not new, check if this edge already exists*/
					Edge e1;
					bool exist;
					tie(e1, exist) = edge(u1, u2, *g);
					if (exist) {
						/* The edge already exist, just update the weight */
						if (edgeWeight[e1] < data->at(i).weight)
							edgeWeight[e1] = data->at(i).weight;
					} else {
						/* The edge do not exist, create it! */
						e1 = (add_edge(u1, u2, *g)).first;
						edgeWeight[e1] = data->at(i).weight;
					}
				}
			}
			return g;
		}
		
		suspiciousData* readSuspiciousFile()
		{
		
			std::ifstream inputFile;
			inputFile.open(m_suspicious_file.c_str(), std::ifstream::in);
			if (!inputFile.is_open()) {
				std::cout << "DNSSuspiciousMappingAnalyzer: Cannot open suspicious file " << m_suspicious_file.c_str() << "\n";
				return NULL;
			}
		
			suspiciousData *data = new suspiciousData; 
		
			while(1) {
				std::string line;
				getline(inputFile, line);
				std::vector<std::string> line_vec;
				boost::split(line_vec, line, boost::is_any_of(" "));
				if (line_vec.size() < 5) {
					if (inputFile.eof())
						break;
					continue;
				}
				struct suspiciousEntry entry;
				entry.timestamp = line_vec[0];
				entry.domain = line_vec[1];
				entry.ipAddress = line_vec[2];
				if (line_vec[3] != "None")
					entry.clientId = line_vec[3];
				entry.weight = atof(line_vec[4].c_str());
				entry.numDomain = atoi(line_vec[5].c_str());
				data->push_back(entry);
				if (inputFile.eof())
					break;
			}
			return data;
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
		
		void filterFromLegitimate(suspiciousData *data, 
			Graph *g, std::vector<std::set<int> > *comp)
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
		
			for (unsigned int i = 0; i < data->size(); i++) {
				it = totDomOcc.find(data->at(i).domain);
				if (it != totDomOcc.end()) {
					int val = data->at(i).numDomain + 1;
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
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
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
			
			std::ostringstream convert;
			convert << m_timestamp;
			std::string fileName;
			fileName = m_malicious_file_prefix;
			fileName += convert.str();
			fileName += ".txt";

			std::ofstream malFile;
			malFile.open(fileName);

			for (unsigned int i = 0; i < comp->size(); i++) {
				std::set<int>::iterator it;
				std::vector<uint32_t> addrs;
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
					Vertex v = vertex( *it, *g);	
					if (color[v] == IP_ADDRESS_COLOR)
						addrs.push_back(atoi(nameId[v].c_str()));
				}
				int64_t ipDistance = compute_avg_ip_distance(addrs);
					
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
					Vertex v = vertex( *it, *g);	
					if (color[v] == DOMAIN_COLOR) {
						edge_iter ei, ei_end;
						float avg = 0.0;
						int cnt = 0;
						std::vector<uint32_t> addrs;
						for (tie(ei, ei_end) = out_edges(v, *g); ei != ei_end; ++ei) {
							avg += edgeWeight[*ei];
							cnt++;
							Vertex u = target(*ei, *g);
							addrs.push_back(atoi(nameId[u].c_str()));
						}
						if (cnt)
							avg = avg/cnt;

						malFile << m_timestamp << " "
							    << nameId[v]   << " " 
								<< avg 		<< " " 
								<< ipDistance  << "\n";
					}
				}	
			}
			#if 0
			for (unsigned int i = 0; i < comp->size(); i++) {
				std::set<int>::iterator it;
				for (it = comp->at(i).begin(); it != comp->at(i).end(); it++) {
					Vertex v = vertex( *it, *g);	
					if (color[v] == DOMAIN_COLOR) {
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
						malFile << nameId[v] << " " << avg << "\n";
					}
				}	
			}
			#endif
			malFile.flush();
			malFile.close();
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
				//throw std::runtime_error("header not sent in DNSSuspiciousMappingAnalyzer");
				std::cerr << "WARNING: ";
				std::cerr << "header not sent in DNSSuspiciousMappingAnalyzer\n";
				return;
			}
			/* Then we can finally send the protobuf message */
			if ( (write(sock_fd, string_to_send.c_str(), 
				string_to_send.length())) < 0 ) {
				//throw std::runtime_error("message not sent in DNSSuspiciousMappingAnalyzer");
				std::cerr << "WARNING: ";
				std::cerr << "message not sent in DNSSuspiciousMappingAnalyzer\n";
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
				//	("protocol buffer object not initialized in DNSSuspiciousMappingAnalyzer");
				std::cerr << "protocol buffer object not initialized in DNSSuspiciousMappingAnalyzer\n";
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
				//throw std::runtime_error("header not sent in DNSSuspiciousMappingAnalyzer");
				std::cerr << "WARNING: ";
				std::cerr << "header not sent in DNSSuspiciousMappingAnalyzer\n";
				return;
			}
			/* Then we can finally send the protobuf message */
			if ( (write(sock_fd, string_to_send.c_str(), 
				string_to_send.length())) < 0 ) {
				//throw std::runtime_error("message not sent in DNSSuspiciousMappingAnalyzer");
				std::cerr << "WARNING: ";
				std::cerr << "message not sent in DNSSuspiciousMappingAnalyzer\n";
				return;
			}
			/* Deallocate the string */
		}

		void output_to_socket(Graph *g, std::vector<std::set<int> > *comp)
		{
			int sock_fd;
			/* create socket */
			if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				//throw std::runtime_error("Socket creatin error in DNSSuspiciousMappingAnalyzer");
				std::cerr << "WARNING: ";
				std::cerr << "socket creatin error in DNSSuspiciousMappingAnalyzer\n";
				return;
			}
			/* Check if is possible to connect to the server */
			if (connect(sock_fd, (struct sockaddr *)&m_serv_add,
				sizeof(m_serv_add)) < 0) {
				//throw std::runtime_error("Connection error in DNSSuspiciousMappingAnalyzer");
				std::cerr << "WARNING: ";
				std::cerr << "connection error in DNSSuspiciousMappingAnalyzer\n";
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
				//throw std::runtime_error("header not sent in DNSSuspiciousMappingAnalyzer");
				std::cerr << "WARNING: ";
				std::cerr << "header not sent in DNSSuspiciousMappingAnalyzer\n";
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

			/* Send a first control message to notify the other end that the
			 * data transmission is finished */
			
			_serialize_control_to_socket(false, sock_fd);

			/* Close the socket used to transfer data to the broker */
			close(sock_fd);
			std::cout << "Suspicious mappings updated on the database ";
			std::cout << m_timestamp;
			std::cout << "\n";
		}

        void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */) 
        {
            auto *message = static_cast<const PairMsg<uint32_t, std::string> *>(m.get());
	
			m_suspicious_file = message->val();

            std::cout<<m_suspicious_file<<std::endl;

			m_timestamp = message->key();
			
			suspiciousData *data = readSuspiciousFile();
					
			// declare a graph object
			Graph *g = buildMappingGraph(data);
		
			std::vector< std::set<int> > components;
			components = filterMappingGraph(g);
			
			filterFromLegitimate(data, g, &components);
		
			components = filterMappingGraph(g);

			std::vector< std::set<int> > final;
			
			final = filterByAsn(g, &components);
			
			if (final.size() == 0)
				return;

			if (m_enable_socket_output)
				output_to_socket(g, &final);
			
			if (m_enable_txt_output)
				output_to_txt(g, &final);

			if (m_enable_vis_buffer_output)
				output_to_vis_buffer(g, &final);

			m_reset_db = 0;
			
			delete data;
			delete g;
        }
    };

#ifndef _BLOCKMON_DOXYGEN_SKIP_
    REGISTER_BLOCK(DNSSuspiciousMappingAnalyzer,"DNSSuspiciousMappingAnalyzer");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */
}
