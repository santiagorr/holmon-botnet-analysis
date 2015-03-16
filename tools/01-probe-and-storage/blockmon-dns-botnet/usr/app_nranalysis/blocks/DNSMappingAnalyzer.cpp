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
 * <blockinfo type="DNSMappingAnalyzer" invocation="direct" thread_exclusive="False">
 *   <humandesc>
 *   	This block receives as input NOERROR DNSPAcket messages and creates a 
 *		mapping IPaddress Dname. The goal is to update this mapping in order to
 *		learn where are localed the most common application on the internet.
 *		Suspicious mapping will be output on a file.
 *	</humandesc>
 *
 *   <shortdesc>
 *      Stores and aggregates information regarding DNSMessage, and dumps to a
 *      database. 
 *   </shortdesc>
 *
 *   <gates>
 *     <gate type="input" name="in_msg" msg_type="DNSMessage" m_start="0" m_end="0" />
 *     <gate type="output" name="out_msg1" msg_type="PairMsg" m_start="0" m_end="0" />
 *     <gate type="output" name="out_msg2" msg_type="DNSSuspiciousMapping" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *    element params {
 *    	element time_bin_merge {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element time_bin_split_cleanup {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element time_bin_printout {
 *      	attribute val = {unsigned int} 
 *      }
 *    	element suspicious_file_prefix {
 *      	attribute val = {string} 
 *      }
 *    	element dump_file {
 *      	attribute val = {string} 
 *      }
 *    	element load_file {
 *      	attribute val = {string} 
 *      }
 *    	element load_config {
 *      	attribute val = {bool} 
 *      }
 *    	element tld_names_file {
 *      	attribute val = {string} 
 *      }
 *    	element geoip_file {
 *      	attribute val = {string} 
 *      }
 *    	element max_cluster_size {
 *      	attribute val = {int} 
 *      }
 *    	element max_num_clusters {
 *      	attribute val = {int} 
 *      }
 *    	element clustering_threshold {
 *      	attribute val = {float} 
 *      }
 *    	element domain_count_threshold {
 *      	attribute val = {float} 
 *      }
 *    }
 *   </paramsschema>
 *
 *   <paramsexample>
 *     <params>
 *        <time_bin_merge val = "21600"/>
 *        <time_bin_split_cleanup val = "86400"/>
 *        <time_bin_printout val = "86400"/>
 *        <suspicious_file_prefix val = "/home/schiavone/svn/demons/Sources/blockmon/main/node/usr/app_nranalysis/dns_output/suspicious.txt"/>
 *        <dump_file_prefix val = "/home/schiavone/svn/demons/Sources/blockmon/main/node/usr/app_nranalysis/dns_output/dump_"/>
 *        <load_file val = "/home//schiavone/svn/demons/Sources/blockmon/main/node/usr/app_nranalysis//dns_output/load.txt"/>
 *        <load_config val = "false"/>
 *   	  <tld_names_file val = "/home/schiavone/svn/demons/Sources/blockmon/main/node/usr/app_nranalysis/dns_trace/data/effective_tld_names.dat"/>
 *   	  <geoip_file val = "/home/schiavone/svn/demons/Sources/blockmon/main/node/usr/app_nranalysis/dns_trace/data/GeoIPASNum.dat"/>
 *        <max_cluster_size val = "30"/>
 *        <max_num_clusters val = "100"/>
 *        <clustering_threshold val = "0.7"/>
 *        <domain_count_threshold val = "0.5"/>
 *      </params>
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
#include <fstream>
#include <set>
#include <unordered_map>
#include <locale>

#include <PairMsg.hpp>
#include <DNSMapping.hpp>
#include <DNSSuspiciousMapping.hpp>

#include "IPBlocks.hpp"

namespace blockmon
{
   	class DNSMappingAnalyzer: public Block
   	{
        int m_ingate_id;
		int m_outgate_id1;
		int m_outgate_id2;
		DNSMap *m_IP_tree;
		/* We need to different time reference: one for flushing the table,
		 * another for dumping into the database. */
		uint32_t m_next_merge;
		uint32_t m_next_split_cleanup;
		uint32_t m_next_printout;
		uint32_t m_time_bin_merge;
		uint32_t m_time_bin_split_cleanup;
		uint32_t m_time_bin_printout;
		
		bool m_load_config;

		/* File name for output. */
		std::string m_load_file;
		std::string m_dump_file_prefix;
		std::string m_suspicious_file_prefix;
		std::string m_last_suspicious_file;
		uint32_t m_last_timestamp;
		std::string m_tld_names_file;
		std::string m_geoip_file;

		/*Blocks Parameter*/
		int m_maxClusterSize;
		unsigned int m_maxNumClusters;
		float m_clusteringThreshold;
		float m_domainCountThreshold;

    public:
		/**
		  * @brief Constructor
		  * @param name			The name of the source block
		  * @param invocation	Invocation type of the block.
		  */
        DNSMappingAnalyzer(const std::string &name, invocation_type) : 
			Block(name, invocation_type::Direct),
        	m_ingate_id(register_input_gate("in_msg")),
        	m_outgate_id1(register_output_gate("out_msg1")),
        	m_outgate_id2(register_output_gate("out_msg2")),
			m_IP_tree(NULL),
			m_next_merge(0),
		 	m_next_split_cleanup(0),
		 	m_next_printout(0),
			m_dump_file_prefix("")
        {
		}

		/**
		  * @brief Destructor
		  */
		~DNSMappingAnalyzer()
		{
			if (m_dump_file_prefix != "")
				m_IP_tree->dumpt(m_dump_file_prefix, 0);
		}

		/**
		  * Configure the block
		  * @param n	The xml subtree.
		  */
		void _configure(const pugi::xml_node&  n) 
        {
            pugi::xml_node time_bin_merge = n.child("time_bin_merge");
            if(!time_bin_merge) 
                throw std::runtime_error("missing time_bin_merge");
            m_time_bin_merge = time_bin_merge.attribute("val").as_uint();
				
            pugi::xml_node time_bin_split_cleanup = n.child("time_bin_split_cleanup");
            if(!time_bin_split_cleanup) 
                throw std::runtime_error("missing time_bin_split_cleanup");
            m_time_bin_split_cleanup = time_bin_split_cleanup.attribute("val").as_uint();
				
            pugi::xml_node time_bin_printout = n.child("time_bin_printout");
            if(!time_bin_printout) 
                throw std::runtime_error("missing time_bin_printout");
            m_time_bin_printout = time_bin_printout.attribute("val").as_uint();

		    pugi::xml_node suspicious_file_prefix = n.child("suspicious_file_prefix");
        	if(!suspicious_file_prefix) 
               	throw std::runtime_error("missing suspicious_file_prefix");
           	m_suspicious_file_prefix = suspicious_file_prefix.attribute("val").value();

		    pugi::xml_node dump_file = n.child("dump_file_prefix");
        	if(!dump_file) 
               	throw std::runtime_error("missing dump_file_prefix");
           	m_dump_file_prefix = dump_file.attribute("val").value();

		    pugi::xml_node load_config = n.child("load_config");
        	if(!load_config) 
               	throw std::runtime_error("missing load_config");
           	m_load_config = load_config.attribute("val").as_bool();

			if (m_load_config) {
		    	pugi::xml_node load_file = n.child("load_file");
        		if(!load_file) 
            	   	throw std::runtime_error("missing load_file");
           		m_load_file = load_file.attribute("val").value();
			}
		    pugi::xml_node tld_names_file = n.child("tld_names_file");
        	if(!tld_names_file) 
               	throw std::runtime_error("missing tld_names_file");
           	m_tld_names_file = tld_names_file.attribute("val").value();

		    pugi::xml_node geoip_file = n.child("geoip_file");
        	if(!geoip_file) 
               	throw std::runtime_error("missing geoip_file");
           	m_geoip_file = geoip_file.attribute("val").value();
			geodb_ = GeoIP_open(m_geoip_file.c_str(), GEOIP_CHECK_CACHE);

            pugi::xml_node max_cluster_size = n.child("max_cluster_size");
            if(!max_cluster_size) 
                throw std::runtime_error("missing max_cluster_size");
            m_maxClusterSize = max_cluster_size.attribute("val").as_int();

            pugi::xml_node max_num_clusters = n.child("max_num_clusters");
            if(!max_num_clusters) 
                throw std::runtime_error("missing max_num_clusters");
            m_maxNumClusters = max_num_clusters.attribute("val").as_int();

            pugi::xml_node clustering_threshold = n.child("clustering_threshold");
            if(!clustering_threshold) 
                throw std::runtime_error("missing clustering_threshold");
            m_clusteringThreshold = clustering_threshold.attribute("val").as_float();

            pugi::xml_node domain_count_threshold = n.child("domain_count_threshold");
            if(!domain_count_threshold) 
                throw std::runtime_error("missing domain_count_threshold");
            m_domainCountThreshold = domain_count_threshold.attribute("val").as_float();
		}

		void sendMessageToOutputGate()
		{
			std::shared_ptr<PairMsg<uint32_t, std::string> > msg =
			std::make_shared<PairMsg<uint32_t, std::string> >
			(m_last_timestamp, m_last_suspicious_file);
			/* Send message to the output gate */
			send_out_through(msg, m_outgate_id1);
		}

		void sendSuspiciousMessage(uint32_t ip, std::string dom, uint32_t c_time)
		{
			std::shared_ptr<DNSSuspiciousMapping> msg =
			std::make_shared<DNSSuspiciousMapping>
			(c_time, dom, ip, "Null", m_IP_tree->m_lastWeight,
				m_IP_tree->m_lastNumBlocks);
			/* Send message to the output gate */
			send_out_through(msg, m_outgate_id2);
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

		    if (m_next_split_cleanup == 0) {
				m_IP_tree = new DNSMap(&m_tld_names_file, 8, m_maxClusterSize,
					m_maxNumClusters, m_clusteringThreshold, m_domainCountThreshold);

				if (m_load_config) {
					m_IP_tree->loadt(m_load_file);
					m_IP_tree->setDoOutputSuspicious();
					m_last_suspicious_file = 
						m_IP_tree->setSuspiciousFile(m_suspicious_file_prefix, c_time);
					std::cout << "IP Mapping configuration loaded\n";
				}
				//m_IP_tree->dumpt("load_test", 10);
				//m_IP_tree->extractStatistics();
				m_next_merge = c_time + m_time_bin_merge;
				m_next_split_cleanup = c_time + m_time_bin_split_cleanup;
				m_next_printout = c_time + m_time_bin_printout;
			}
			

			#if 0
			if (c_time > m_next_printout) {
				std::cout << "END OF PRINTOUT PERIOD\n";
				std::cout << "timestamp: " << c_time << "\n";
				m_IP_tree->extractStatistics();
				std::cout << "\n";
				m_next_printout += m_time_bin_printout;
			}
			#endif

			if (c_time > m_next_merge) {
				int mergedCnt = m_IP_tree->mergeAllBlocks();
				std::cerr << "END OF MERGE PERIOD\n";
				std::cerr << "timestamp: " << c_time << "\n";
				std::cerr << "merged IPBlocks: " << mergedCnt << "\n";
				
				m_IP_tree->reclusterAllBlocks();
				m_next_merge += m_time_bin_merge;
			}

			if (c_time > m_next_split_cleanup) {
				if (m_IP_tree->getDoOutputSuspicious())
					sendMessageToOutputGate();
				else
					m_IP_tree->setDoOutputSuspicious();

				m_last_timestamp = c_time;
				m_last_suspicious_file = 
					m_IP_tree->setSuspiciousFile(m_suspicious_file_prefix, c_time);

				int splitCnt = m_IP_tree->splitAllBlocks();

				int removedIPBlocks = m_IP_tree->removeEmptyIPBlocks();
				int removedDomains = m_IP_tree->removeDomainsFromAllIPBlocks();

				m_IP_tree->dumpt(m_dump_file_prefix, c_time);

				//int splitCnt = m_IP_tree->splitAllBlocks();
				std::cerr << "END OF SPLIT-CLEAN PERIOD\n";
				std::cerr << "timestamp: " << c_time << "\n";
				std::cerr << "split IPBlocks: " << splitCnt << "\n";
				std::cerr << "removed IPBlocks: " << removedIPBlocks << "\n";
				std::cerr << "removed Domains: " << removedDomains << "\n";
				m_next_split_cleanup += m_time_bin_split_cleanup;
			}

			if (c_time > m_next_printout) {
				std::cout << "END OF PRINTOUT PERIOD\n";
				std::cout << "timestamp: " << c_time << "\n";
				m_IP_tree->extractStatistics();
				m_next_printout += m_time_bin_printout;
			}

			uint32_t ip = mapping->address();
			std::string name = mapping->name();
			std::string last_cname = mapping->last_cname();
			//name = name.substr(0, name.length() - 1);
			//last_cname = name.substr(0, name.length() - 1);

			if(m_IP_tree->add(ip, &name, &last_cname, c_time))
				sendSuspiciousMessage(ip, name, c_time);
        }
    };

#ifndef _BLOCKMON_DOXYGEN_SKIP_
    REGISTER_BLOCK(DNSMappingAnalyzer,"DNSMappingAnalyzer");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */
}
