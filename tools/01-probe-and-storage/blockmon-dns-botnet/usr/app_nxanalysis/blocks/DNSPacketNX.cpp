/*--------------------------------------------------------
 * FTR&D/MAPS/STT
 *--------------------------------------------------------
 *
 * Copyright France Telecom  2012,  All Rights Reserved.
 *
 * This software is the confidential and proprietary
 * information of France Telecom.
 * You shall not disclose such Confidential Information
 * and shall use it only in accordance with the terms
 * of the license agreement you entered into with
 * France Telecom.
 *
 *--------------------------------------------------------
 * Author      : Hachem GUERID
 *--------------------------------------------------------
 */
/*
 * <blockinfo type="DNSPacketNX" invocation="direct" scheduling_type="passive" thread_exclusive="False">
 *   <humandesc>
 *     Identify suspicious hosts
 *     The block takes as input the DNS errors messages (NXDOMAIN answers)
 *     The block sends to the DNSCorrelate the identifiers of the suspicious hosts
 *   </humandesc>
 *
 *   <shortdesc>Identify suspicious hosts  </shortdesc>
 *
 *   <gates>
 *     <gate type="input" name="in_msg_nx" msg_type="DnsEntry" m_start="0" m_end="0" />
 *     <gate type="output" name="out_infectedlist" msg_type="InfectedList" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *    element params {
 *    	element correlation_timeout {
 *      	attribute val = {float} 
 *      }
 *    	element buffer_size {
 *      	attribute val = {int} 
 *      }
 *    	element proxy_fillrate {
 *      	attribute val = {float} 
 *      }
 *    	element merge_threshold {
 *      	attribute val = {float} 
 *      }
 *    	element number_hash {
 *      	attribute val = {int} 
 *      }
 *    	element reset_time {
 *      	attribute val = {int} 
 *      }
 *    	element communities_threshold {
 *      	attribute val = {int} 
 *      }
 *    	element flush_time {
 *      	attribute val = {int} 
 *      }
 *    	element results_directory {
 *      	attribute val = {string} 
 *      }
 *    }
 *   </paramsschema>
 *
 *   <paramsexample>
 *     <params>
 *			<correlation_timeout value="300"/>
 *			<proxy_fillrate value="0.2"/>
 *			<merge_threshold value="0.60"/>
 *			<buffer_size value="1000"/>
 *			<number_hash value="1"/>
 *			<reset_time value="72000"/>
 *			<communities_threshold value="6"/>
 *			<results_directory value="/tmp/"/>
 *			<flush_time value="3600"/>
 *     </params>
 *   </paramsexample>
 *
 *   <variables>
 *     <variable name="pktcnt" human_desc="integer" access="read"/>
 *     <variable name="valid_dns_cnt" human_desc="integer" access="read"/>
 *   </variables>
 *
 * </blockinfo>
 */

#include<Block.hpp>
#include<BlockFactory.hpp>
#include<cstdio>
#include<Packet.hpp>
#include<netinet/in.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <vector>
#include <Alert.hpp>
#include "NetTypes.hpp"
#include "ClientList.hpp"
#include "dnsh.h"
#include "../messages/InfectedList.hpp"
#include <fstream>
#include "boost/shared_ptr.hpp"
#include "DnsEntry.hpp"

using namespace std;

#if !defined(USE_SIMPLE_PACKET) && !defined(USE_SLICED_PACKET)

// FIXME this class is no more compliant with NewPacket class
//       TO BE REWRITTEN!


using namespace NXAnalyzer;
namespace blockmon
{

    /**
     * process the NXDomain answers in order to identify the suspicious ones
     * the suspicious ones are sent to the DNSCorrelator 
     */
    class DNSPacketNX: public Block
    {
       unsigned long long  m_count; // number of packets
		unsigned long long  m_count_validdns; // number of packets
        unsigned long long  m_corelation_timer_threeshold; // count the number nxdomain answers 
		unsigned long long  m_count_communities; // number of detected communities
		unsigned long long  m_count_correlation_periods; // number of performed correlation
		unsigned long long  m_current_time;
		unsigned long long 	m_flush_time;
		unsigned int 		m_interval_correlation;
		unsigned long long 	m_no_tld;
		unsigned long long 	tld_non_existent;
		unsigned long long 	m_count_proxy;
		int m_thres_communities; // minimum number of member to form a community
		int m_min_req_thres; 
		float f_proxy_fillrate;
		float f_merge_thres;
		int bufferSize;
		int numHash;
		int m_one_or_to;
		int m_client_counter;
		int m_ingate_id_nxmsg;
		int m_out_gate_id_infected;
		ClientList* clientsInTheSystem;	
		ClientList* listToSend;
		ClientList* proxyClients;
		typedef boost::unordered_map<string , string> unordered_map;
		unordered_map mapp;
		string m_results_directory;

    public:
        /**
         * @brief Constructor
         * @param name         The name of the packet counter block
         * @param invocation   Invocation type of the block (Indirect, Direct, Async)
         */
        DNSPacketNX(const std::string &name, invocation_type invocation) 
        : Block(name, invocation), 
        m_count(0), 
		m_count_validdns(0),
		m_corelation_timer_threeshold(0),
		m_count_communities(0),
		m_count_correlation_periods(0),
		m_current_time(0),
		m_flush_time(3600),
		m_interval_correlation(60),
		m_no_tld(0),
		tld_non_existent(0),
		m_count_proxy(0),
		m_thres_communities(8),
		m_min_req_thres(7),
		f_proxy_fillrate(0.6),
		f_merge_thres(0.7),
		bufferSize(600),
		numHash(2),
		m_ingate_id_nxmsg(register_input_gate("in_msg_nx")),
		m_out_gate_id_infected(register_output_gate("out_infectedlist"))
        {
            register_variable("pktcnt",make_rd_var(no_mutex_t(), m_count));
			register_variable("valid_dns_cnt",make_rd_var(no_mutex_t(), m_count_validdns));
			clientsInTheSystem =  new ClientList();
			listToSend = new ClientList();
			proxyClients = new ClientList();
			initTld();
        }
		DNSPacketNX(const DNSPacketNX &)=delete;
        DNSPacketNX& operator=(const DNSPacketNX &) = delete;
        DNSPacketNX(DNSPacketNX &&)=delete;
        DNSPacketNX& operator=(DNSPacketNX &&) = delete;

        /**
         * @brief Destructor
         */
        virtual ~DNSPacketNX() {
			delete clientsInTheSystem;
			delete listToSend;
			delete proxyClients;
		}

		
		/**
         * @brief initialis the list of valid tld
         */
		void initTld(){
			for (unsigned int i=0; i< validTLD.size() ; i++)
			{
				mapp.insert(unordered_map::value_type(validTLD[i], validTLD[i]));
			}
			return;
		}
		

        /**
         * @brief Configures the block, 
         * @param n The configuration parameters 
         */
        void _configure(const pugi::xml_node&  n )
        {
			pugi::xml_node correlation_timeout = n.child("correlation_timeout");
            if(correlation_timeout)
            {
                if(correlation_timeout.attribute("value"))
                    m_interval_correlation = correlation_timeout.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed correlation timer");
            }
            pugi::xml_node communities_threshold = n.child("communities_threshold");
            if(communities_threshold)
            {
                if(communities_threshold.attribute("value"))
                    m_thres_communities = communities_threshold.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed minimum community threshold");
            }

			pugi::xml_node minimum_requests = n.child("minimum_requests");
            if(minimum_requests)
            {
                if(minimum_requests.attribute("value"))
                    m_min_req_thres = minimum_requests.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed minimum number of requests");
            }
			
			pugi::xml_node proxy_fillrate = n.child("proxy_fillrate");
            if(proxy_fillrate)
            {
                if(proxy_fillrate.attribute("value"))
                    f_proxy_fillrate = proxy_fillrate.attribute("value").as_float();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed proxy bloom filter fillrate threshold");
            }
			pugi::xml_node merge_threshold = n.child("merge_threshold");
            if(merge_threshold)
            {
                if(merge_threshold.attribute("value"))
                    f_merge_thres = merge_threshold.attribute("value").as_float();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed merge threshold");
            }
            pugi::xml_node buffer_size = n.child("buffer_size");
			if(buffer_size)
            {
                if(buffer_size.attribute("value"))
                    bufferSize = buffer_size.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed buffer size");
            }
			pugi::xml_node number_hash = n.child("number_hash");
			if(number_hash)
            {
                if(number_hash.attribute("value"))
                    numHash = number_hash.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed number of hash function");
            }

			
			pugi::xml_node flush_time = n.child("flush_time");
			if(flush_time)
            {
                if(flush_time.attribute("value"))
                    m_flush_time = flush_time.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed time before Reset");
            }
			
			pugi::xml_node results_directory = n.child("results_directory");
            if(results_directory)
            {
                if(results_directory.attribute("value"))
                    m_results_directory = results_directory.attribute("value").value();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed proxy bloom filter fillrate threshold");
            }
			
			ofstream myfile;
			myfile.open (m_results_directory + "detected", ios::out | ios::app ); 
			if (myfile.is_open()){
				myfile << "# correlation period = " << m_interval_correlation << "  min requests = " <<  m_min_req_thres << "proxy fill rate = " << f_proxy_fillrate << endl;
				myfile << "# merge threshold = " << f_merge_thres << " min community = " << m_thres_communities << endl;
				myfile <<  "# buffer_size  = " << bufferSize << "  number of hashs  = " << numHash << endl;
				myfile << "# flush time  =  " << m_flush_time << endl;
				myfile.close();
			} else{
					cerr << "we did not write*****************************" << endl;
			}
				
        }

        /**
         * @brief Receive and process NX domain DNS packets
         * @param m     The message
         * @param index The index of the gate the message came on
         */
        virtual void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */)
        {
			if(m->type() == MSG_ID(DnsEntry)){
				m_count++;
				const DnsEntry* nxmsg = static_cast<const DnsEntry*>(m.get());

				string m_domain_name = (nxmsg->get_name());
				m_current_time = (nxmsg->get_timestamp());
				uint32_t m_identifier = (nxmsg->get_identifier());
				
				
				if(m_domain_name.empty())
					return;
				m_domain_name.erase(m_domain_name.end()-1); // erase the last dot of the fqdn
				size_t tld_pos = m_domain_name.find_last_of(".");
				if(tld_pos == std::string::npos){ // if there is no dot, drop the msg
					m_no_tld++;
					return; 
				}
				std::transform(m_domain_name.begin(), m_domain_name.end(), m_domain_name.begin(), ::tolower);
				if(mapp.find(m_domain_name.substr(tld_pos+1)) == mapp.end()){
					tld_non_existent++;
					return;			
				}
			
				m_count_validdns++;
				Client* client;
				client = clientsInTheSystem->retrive(m_identifier, m_current_time);
				if (client == NULL){
					client =  new Client(m_identifier, m_current_time, bufferSize, numHash);
					m_client_counter++;
					clientsInTheSystem->putClient(client);
					client->hit((unsigned char*)m_domain_name.c_str(), m_domain_name.size()+1);		
				}  else {
					client->hit((unsigned char*)m_domain_name.c_str(), m_domain_name.size()+1);
					if (m_current_time - client->getTimestamp()  > m_flush_time){
						client->flushClient(m_current_time);
						if(listToSend->contains(client)){
							listToSend->removeClient(client);
						}
					}
					
					if(proxyClients->contains(client)){
						m_count_proxy++;
						return;
					}
					
					if(client->bloomfilter->fillrate() > f_proxy_fillrate){
						proxyClients->putClient(client);
						m_count_proxy++;
						if(listToSend->contains(client)){
							listToSend->removeClient(client);
						}
						return;
					}
					if(client->getSmartCounter() >= m_min_req_thres){
						if(!listToSend->contains(client))
							listToSend->putClient(client);
					}
				}
				
				if(m_corelation_timer_threeshold == 0)
					m_corelation_timer_threeshold = m_current_time;
				if(m_current_time - m_corelation_timer_threeshold > m_interval_correlation){
					m_count_correlation_periods++;
					std::vector<Client*> infected_list;
					Client* client2;
					for (int i=0; i < listToSend->size(); i++) {
						client2 = listToSend->getclient(i);
						if(client2 == NULL)
							continue;
						infected_list.push_back(client2);
					}
					listToSend->clear();
					
					//infected list msg to send
					std::shared_ptr<InfectedList> infected = std::make_shared<InfectedList>(m_count_correlation_periods, infected_list.size());
					infected.get()->set_infected(infected_list);
					m_corelation_timer_threeshold = 0;
					send_out_through(infected,m_out_gate_id_infected); 
					
					ofstream myfile;
					myfile.open (m_results_directory + "nx_stats", ios::out | ios::app ); 
					if (myfile.is_open()){
						myfile << m_count << " ; " << m_count_validdns << " ; " <<  m_no_tld << " ; " << tld_non_existent << " ; " << m_count_proxy << endl;
						myfile.close();
					} else{
						cerr << "we did not write*****************************" << endl;
					}

				}
		
			}  else 	{
				throw std::runtime_error("wrong message type in pkt counter");
			
			}
		}
		
    };


#ifndef _BLOCKMON_DOXYGEN_SKIP_
    REGISTER_BLOCK(DNSPacketNX,"DNSPacketNX");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */

}//blockmon

#endif
