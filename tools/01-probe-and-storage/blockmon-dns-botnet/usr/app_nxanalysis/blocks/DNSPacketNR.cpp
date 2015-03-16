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
/**
 * <blockinfo type="DNSPacketNR" invocation="direct" scheduling_type="passive" thread_exclusive="False">
 *   <humandesc>
 *     Identify Malicious domain names 
 *     The block takes as input DNS NORREROR answers messages and the identifiers of the communities of the infected hosts
 *     The block sends the malicious domain name to the export module
 *   </humandesc>
 *
 *   <shortdesc>Identify Malicious domain names  </shortdesc>
 *
 *   <gates>
 *     <gate type="input" name="in_msg_nr" msg_type="DnsEntry" m_start="0" m_end="0" />
 *     <gate type="input" name="in_alert" msg_type="Alert" m_start="0" m_end="0" />
 *     <gate type="output" name="out_alert" msg_type="Alert" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *    element params {
 *    	element infection_threshold {
 *      	attribute val = {float} 
 *      }
 *    	element buffer_size {
 *      	attribute val = {int} 
 *      }
 *    	element proxy_fillrate {
 *      	attribute val = {float} 
 *      }
 *    	element inter_filter {
 *      	attribute val = {float} 
 *      }
 *    	element number_hash {
 *      	attribute val = {int} 
 *      }
 *    	element overal_bf_size {
 *      	attribute val = {int} 
 *      }
 *    	element overal_bf_threshold {
 *      	attribute val = {float} 
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
			<infection_threshold value="0.70"/>
			<buffer_size value="10000"/>
			<proxy_fillrate value="0.1"/>
			<inter_filter value="0.1"/>
			<number_hash value="2"/>
			<overal_bf_size value="1000000"/>
			<overal_bf_threshold value="0.5"/>
			<flush_time value="3600"/>
			<results_directory value="/tmp/"/>
 *     </params>
 *   </paramsexample>
 *
 *   <variables>
 *     <variable name="pktcnt" human_desc="integer" access="read"/>
 *     <variable name="detected" human_desc="integer" access="read"/>
 *     <variable name="recv_alerts" human_desc="integer" access="read"/>
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
#include <string>
#include <cstring>
#include <iomanip>
#include <vector>
#include <Alert.hpp>
#include <fstream>

#include "NetTypes.hpp"
#include "ClientList.hpp"
#include "dnsh.h"
#include "DnsEntry.hpp"


using namespace std;

#if !defined(USE_SIMPLE_PACKET) && !defined(USE_SLICED_PACKET)

// FIXME this class is no more compliant with NewPacket class
//       Reason: the packet is no more linear in memory.
//       TO BE REWRITTEN!


using namespace NXAnalyzer;
namespace blockmon
{

    /**
     * Implements a block that receives noerror dns answers and the ipdresses of communities of infected users
	 * to detect the domain name of a milicious domain name
     */
    class DNSPacketNR: public Block
    {
        unsigned long long  m_count;
		unsigned long long  m_init_timer;
		unsigned long long  m_current_timer;
		unsigned long long 	m_detected;
		unsigned long long 	m_sum_detection_time;
		unsigned long long 	m_sum_detection_time2;
		unsigned long long	m_current_time;
		unsigned long long 	m_flush_time;
		float f_infected_thres;
		float f_proxy_fillrate;
		unsigned long long m_listcount;
		int bufferSize;
		int numHash;
		float f_inter_filter;
		unsigned int m_overal_bf_size;
		float f_overal_bf_threshold;
        int m_ingate_nrmsg;
		int m_ingate_alerts;
		int m_outgate_malicious;
		ClientList* infectedList;
		typedef boost::unordered_map<uint32_t , int> unordered_map;
		unordered_map map_infected_hosts;
		typedef boost::unordered_map<unsigned long long , ClientList*> unordered_mapp;
		unordered_mapp map_identified_communities;
		typedef boost::unordered_map<string , string> unordered_map3;
		unordered_map3 map_detected_domain;
		typedef boost::unordered_map<unsigned long long, BloomFilter*> unordered_map_bloom;
		unordered_map_bloom map_bloom;
		string m_results_directory;

    public:

        /**
         * @brief Constructor
         * @param name         The name of the source block
         * @param invocation   Invocation type of the block (Indirect, Direct, Async)
         */
        DNSPacketNR(const std::string &name, invocation_type invocation) 
        : Block(name, invocation), 
		m_count(0), 
		m_init_timer(0),
		m_detected(0),
		m_sum_detection_time(0),
		m_sum_detection_time2(0),
		m_current_time(0),
		m_flush_time(3600),
		f_infected_thres(0.7),
		f_proxy_fillrate(0.3),
		m_listcount(0),
		bufferSize(1600),
		numHash(2),
		f_inter_filter(2.0),
		m_overal_bf_size(100000),
		f_overal_bf_threshold(0.5),
        m_ingate_nrmsg(register_input_gate("in_msg_nr")),
        m_ingate_alerts(register_input_gate("in_alert")),
		m_outgate_malicious(register_output_gate("out_alert"))
        {
            register_variable("pktcnt",make_rd_var(no_mutex_t(), m_count));
            register_variable("detected",make_rd_var(no_mutex_t(), m_detected));
			register_variable("recv_alerts",make_rd_var(no_mutex_t(), m_listcount));
			infectedList = new ClientList();
        }
		DNSPacketNR(const DNSPacketNR &)=delete;
        DNSPacketNR& operator=(const DNSPacketNR &) = delete;
        DNSPacketNR(DNSPacketNR &&)=delete;
        DNSPacketNR& operator=(DNSPacketNR &&) = delete;

        /**
         * @brief Destructor
         */
        ~DNSPacketNR()  {
			delete infectedList;
		}
	
        /**
         * @brief Configures the block
         * @param n The configuration parameters 
         */
        void _configure(const pugi::xml_node&  n )
        {
        	pugi::xml_node infection_threshold = n.child("infection_threshold");
            if(infection_threshold)
            {
                if(infection_threshold.attribute("value"))
                    f_infected_thres = infection_threshold.attribute("value").as_float();
                else
                    throw std::runtime_error("DNSPacketNR: Malformed infection threshold");
            }
            pugi::xml_node Buffer_Size = n.child("Buffer_Size");
            if(Buffer_Size)
            {
                if(Buffer_Size.attribute("value"))
                    bufferSize = Buffer_Size.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNR: Malformed buffer size");
            }

			pugi::xml_node number_Hash = n.child("number_Hash");
            if(number_Hash)
            {
                if(number_Hash.attribute("value"))
                    numHash = number_Hash.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNR: number of hash functions");
            }
			
			pugi::xml_node proxy_fillrate = n.child("proxy_fillrate");
            if(proxy_fillrate)
            {
                if(proxy_fillrate.attribute("value"))
                    f_proxy_fillrate = proxy_fillrate.attribute("value").as_float();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed proxy bloom filter fillrate threshold");
            }	
			
			pugi::xml_node results_directory = n.child("results_directory");
            if(results_directory)
            {
                if(results_directory.attribute("value"))
                    m_results_directory = results_directory.attribute("value").value();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed proxy bloom filter fillrate threshold");
            }
			
			pugi::xml_node inter_filter = n.child("inter_filter");
            if(inter_filter)
            {
                if(inter_filter.attribute("value"))
                    f_inter_filter = inter_filter.attribute("value").as_float();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed proxy bloom filter fillrate threshold");
            }
			
			pugi::xml_node overal_bf_size = n.child("overal_bf_size");
            if(overal_bf_size)
            {
                if(overal_bf_size.attribute("value"))
                    m_overal_bf_size = overal_bf_size.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNR: Malformed buffer size");
            }

			pugi::xml_node overal_bf_threshold = n.child("overal_bf_threshold");
            if(overal_bf_threshold)
            {
                if(overal_bf_threshold.attribute("value"))
                    f_overal_bf_threshold = overal_bf_threshold.attribute("value").as_float();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed proxy bloom filter fillrate threshold");
            }
			
			pugi::xml_node flush_time = n.child("flush_time");
			if(flush_time)
            {
                if(flush_time.attribute("value"))
                    m_flush_time = flush_time.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNR: Malformed buffer size");
            }
        }
		
        /**
         * If the message received is of type RawPacket and from an identified infected IP adress treat it
         * If the message received is of type Alert collect the ip addresses of the community 
         * @param m     The message
         * @param index The index of the gate the message came on
         */
        void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */)
        {
	
			if(m->type() == MSG_ID(DnsEntry)){
				int community_number, counter;
				const DnsEntry* nxmsg = static_cast<const DnsEntry*>(m.get());
				m_count++;
				string m_domain_name = (nxmsg->get_name());
				m_current_time = (nxmsg->get_timestamp());
				uint32_t m_identifier = (nxmsg->get_identifier());			
				
				// init the time of the block
				if(m_init_timer==0){
					m_init_timer = m_current_time;
					ofstream myfile;
					myfile.open (m_results_directory + "detected", ios::out | ios::app ); 
					if (myfile.is_open()){
						myfile << "# THE DNS PACKET NR BLOCK VARIABLES " << endl;
						myfile << "# Infected threeshold = " << f_infected_thres << " # Buffer Size = " << bufferSize << " # number of hashes = "<< numHash << endl;
						myfile << "# Proxy fillrate = " << f_proxy_fillrate << " Interdomain threeshold = " << f_inter_filter << " interdomain filter = " << m_overal_bf_size << endl;
						myfile << "# Flush time = " << m_flush_time << endl;
						myfile.close();
					} else{
							cerr << "we did not write*****************************" << endl;
					}
				}
					
	
	

				if(map_infected_hosts.find(m_identifier) == map_infected_hosts.end()){
					return;
				}
				
				community_number = map_infected_hosts.find(m_identifier)->second;
				Client* client;
				ClientList* listActual;
				BloomFilter* list_bloom; //
				client = infectedList->retrive(m_identifier, m_current_time);

				if (client == NULL){
					return;
				} 
				
				if(map_detected_domain.find(m_domain_name) != map_detected_domain.end()){ // already detected;
					return;
				}
			
				if(map_identified_communities.find(community_number) == map_identified_communities.end()){
					return;
				}
			
				listActual = map_identified_communities.find(community_number)->second;
				if(map_bloom.find(community_number) == map_bloom.end()){ //
					return;
				}
				
				list_bloom = map_bloom.find(community_number)->second; //
				if((listActual == NULL) || (list_bloom == NULL)){ /////
					return;
				}
				
				// check if we flush the host
				if(m_current_time - client->getTimestamp()  > m_flush_time){
					for(int i=0; i < listActual->size(); i++){
						Client* client2 = listActual->getclient(i);
						if( client2 == NULL)
							continue;
						infectedList->removeClient(client2);
						map_infected_hosts.erase(client2->getName());
					}
					
					map_identified_communities.erase(community_number);
					delete listActual;
					map_bloom.erase(community_number); //
					delete list_bloom;
					return;
				}

				client->hit((unsigned char*)m_domain_name.c_str(), m_domain_name.size()+1);
			
				list_bloom->addDomain((unsigned char*)m_domain_name.c_str(), m_domain_name.size()+1); //
				
				float avg_fillrate=0.0;
				counter=0;
				for(int i=0; i<listActual->size(); i++){
					Client* client2 = listActual->getclient(i);
					if( client2 == NULL)
						continue;
					if(client2->bloomfilter == NULL){
						continue;
					}
					if(client2->bloomfilter->contains((unsigned char*)m_domain_name.c_str(), m_domain_name.size()+1)){
						counter++;
						avg_fillrate += client2->bloomfilter->fillrate();
					}
				}
				
				
				
				if(counter > f_infected_thres*listActual->size()){
				
				
					if(map_detected_domain.find(m_domain_name) != map_detected_domain.end()){ // already detected;
						return;
					}
					avg_fillrate = avg_fillrate / (counter*1.0) ;
					if(avg_fillrate > f_proxy_fillrate){
						return;
					}
					
					int count_down = 0;
					int its_there=0;
					BloomFilter *temp_list_bloom;
					float avg_inter_fillrate=0.0;
					
					unordered_map_bloom::iterator map_it;
					for(map_it=map_bloom.begin(); map_it != map_bloom.end(); map_it++){
						temp_list_bloom = map_it->second;
						if(map_it->second != NULL){
							if((temp_list_bloom->getNumberOnes() != 0) && (temp_list_bloom->fillrate() < f_overal_bf_threshold)){
								count_down++;
								if(temp_list_bloom->contains((unsigned char*)m_domain_name.c_str(), m_domain_name.size()+1)){
									its_there++;
									avg_inter_fillrate+=temp_list_bloom->fillrate();
								}
							}
						}
						
					}
					
					// if the filters are full, drop the process
					if ( (float)(its_there/(count_down *1.0)) > f_inter_filter){
						return;
					}
					
					m_detected++;
					m_sum_detection_time += m_current_timer - client->getTimestamp();
					m_sum_detection_time2 += m_current_timer - m_init_timer;
					
					map_detected_domain.insert(unordered_map3::value_type(m_domain_name, m_domain_name));
					ofstream myfile;
					myfile.open (m_results_directory + "detected", ios::out | ios::app ); 
					if (myfile.is_open()){
						myfile << m_domain_name << " ; " << listActual->size() << " ; " << listActual->getID() << " ; " << avg_fillrate << " ; " << m_current_timer - m_init_timer <<  " ; "  << m_current_timer - client->getTimestamp() << " ; " << m_sum_detection_time2/m_detected << " ; " << m_sum_detection_time/m_detected << " ; ";
						myfile << (float)(its_there/(count_down *1.0))  << " ; " << avg_inter_fillrate/its_there << " ; " << its_there << " ; " << count_down  << endl;
						//myfile << "Yime =  " << packet->timestamp_s() - client->getTimestamp() << " Wakeup time = " << packet->timestamp_s() - m_init_timer << "   detection time =  " << client->getTimestamp() <<  "  actual time =  " << packet->timestamp_s() << endl;
						myfile.close();
					} else{
						printf("we did not write*****************************\n");
					}
					
					

					std::vector<uint32_t> malicious_ip_addresses = (nxmsg->get_ip_address());
					std::vector<Alert::Node> malicious_domain_name;

					if(malicious_ip_addresses.begin() == malicious_ip_addresses.end()){
						malicious_domain_name.push_back(Alert::Node(m_domain_name));
					} else {
						for(auto it = malicious_ip_addresses.begin(); it != malicious_ip_addresses.end(); ++it){
							malicious_domain_name.push_back(Alert::Node(*it, m_domain_name));
						}
					}
					
					
				
					std::shared_ptr<Alert> alert_domain = std::make_shared<Alert>(get_name(), m_detected, "NX_APPLICATION");
					alert_domain.get()->set_targets(malicious_domain_name);
					Alert::severity_level_t severity = Alert::sev_high;
					Alert::confidence_level_t confidence = Alert::conf_numeric;
					alert_domain.get()->set_assessment(severity, confidence);
					alert_domain.get()->set_confidence((float)(counter/(listActual->size()*1.0)));
					send_out_through(alert_domain,m_outgate_malicious);
					
					
				}
				return;
				
			} else if(m->type()==MSG_ID(Alert)){
				const Alert* alert = static_cast<const Alert*>(m.get());
				ClientList* listActual = new ClientList();
				listActual->putID(m_listcount);
				Client* client;

				vector<Alert::Node> community_members = *(alert->get_targets());
	
				if(community_members.size() > 0){
					BloomFilter *bloom = new BloomFilter(m_overal_bf_size,3);
					map_bloom.insert(std::make_pair(m_listcount, bloom));
				}
				unordered_map3 map_string;
				
				
				for (unsigned int i=0; i< community_members.size() ; i++)
				{
					client = infectedList->retrive(community_members[i].get_ipv4(), 0);
					if (client == NULL){
						client =  new Client(community_members[i].get_ipv4(), m_current_time, bufferSize, numHash);
						infectedList->putClient(client);
						map_infected_hosts.insert(std::make_pair(community_members[i].get_ipv4(), m_listcount));
					} else {
						client->flushClient(m_current_time);
						map_infected_hosts.find(community_members[i].get_ipv4())->second = m_listcount;
					}
					listActual->putClient(client);
					map_identified_communities.insert(std::make_pair(m_listcount, listActual));
				}
				m_listcount++;
				
			} else {
				throw std::runtime_error("wrong message type in pkt counter");
			}
		}

    };

#ifndef _BLOCKMON_DOXYGEN_SKIP_
    REGISTER_BLOCK(DNSPacketNR,"DNSPacketNR");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */

}//blockmon

#endif
