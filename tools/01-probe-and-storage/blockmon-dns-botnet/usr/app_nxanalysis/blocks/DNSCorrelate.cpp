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
 * <blockinfo type="DNSCorrelate" invocation="direct" scheduling_type="passive" thread_exclusive="False">
 *   <humandesc>
 *     Identify the communities of infected hosts
 *     The block receives lists of suspicious hosts from the DNSPacketNX block
 *     The block sends the communities of infected hosts to the DNSPacketNR block
 *   </humandesc>
 *
 *   <shortdesc>Identify the communities of infected hosts </shortdesc>
 *
 *   <gates>
 *     <gate type="input" name="in_infectedlist" msg_type="InfectedList" m_start="0" m_end="0" />
 *     <gate type="output" name="out_alert" msg_type="Alert" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *    element params {
 *    	element merge_threshold {
 *      	attribute val = {float} 
 *      }
 *    	element buffer_size {
 *      	attribute val = {int} 
 *      }
 *    	element communities_threshold {
 *      	attribute val = {int} 
 *      }
 *    	element correlate_time {
 *      	attribute val = {int} 
 *      }
 *    	element flush_time {
 *      	attribute val = {int} 
 *      }
 *    }
 *   </paramsschema>
 *
 *   <paramsexample>
 *     <params>
 *  	  	<merge_threshold value="0.60"/>
 *  		<buffer_size value="1000"/>
 *  		<communities_threshold value="3"/>
 *  		<correlate_time value="300"/>
 *  		<flush_time value="3600"/>
 *     </params>
 *   </paramsexample>
 *
 *   <variables>
 *     <variable name="count" human_desc="integer" access="read"/>
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
#include "../messages/InfectedList.hpp"



#include "NetTypes.hpp"
#include "ClientList.hpp"
#include "dnsh.h"

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
    class DNSCorrelate: public Block
    {
		long long m_count;
		float f_merge_thres;
		int bufferSize;
		int numHash;
		int m_correlate_time;
		int m_flush_time;
		unsigned int m_thres_communities;
		int m_count_communities;
        int m_ingate_id;
		int m_out_gate_id;
		int m_out_gate_id2;
		typedef boost::unordered_map<uint32_t , int> unordered_map;
		unordered_map map_already_there;
		string m_results_directory;

		
    public:

        /**
         * @brief Constructor
         * @param name         The name of the source block
         * @param invocation   Invocation type of the block (Indirect, Direct, Async)
         */
        DNSCorrelate(const std::string &name, invocation_type invocation) 
        : Block(name, invocation), 
		m_count(0),
		f_merge_thres(0.8),
		bufferSize(800),
		numHash(2),
		m_correlate_time(60),
		m_flush_time(3600),
		m_thres_communities(8),
		m_count_communities(0),
        m_ingate_id(register_input_gate("in_infectedlist")),
		m_out_gate_id(register_output_gate("out_alert")){
			register_variable("count",make_rd_var(no_mutex_t(), m_count));
        }
		DNSCorrelate(const DNSCorrelate &)=delete;
        DNSCorrelate& operator=(const DNSCorrelate &) = delete;
        DNSCorrelate(DNSCorrelate &&)=delete;
        DNSCorrelate& operator=(DNSCorrelate &&) = delete;

        /**
         * @brief Destructor
         */
        ~DNSCorrelate() {
			///delete infectedList;
		}
		
        void _configure(const pugi::xml_node&  n )
        {
			pugi::xml_node communities_threshold = n.child("communities_threshold");
            if(communities_threshold)
            {
                if(communities_threshold.attribute("value"))
                    m_thres_communities = communities_threshold.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed minimum community threshold");
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
			pugi::xml_node correlate_time = n.child("correlate_time");
			if(correlate_time)
            {
                if(correlate_time.attribute("value"))
                    m_correlate_time = correlate_time.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed buffer size");
            }
			
			pugi::xml_node flush_time = n.child("flush_time");
			if(flush_time)
            {
                if(flush_time.attribute("value"))
                    m_flush_time = flush_time.attribute("value").as_uint();
                else
                    throw std::runtime_error("DNSPacketNX: Malformed buffer size");
            }
			
        }
		
        /**
         * If the message received is of type RawPacket and from an identified infected IP adress treat it
         * If the message received is of type Alert collect the ip addresses
         * @param m     The message
         * @param index The index of the gate the message came on
         */
        void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */)
        {
			
			if(m->type()==MSG_ID(InfectedList))
			{
				m_count++;
				const InfectedList* infect = static_cast<const InfectedList*>(m.get());
				std::vector<Client*> detected_list = *(infect->get_infected());
				int detected_list_size = (infect->get_list_Size());
				std::vector<bool> present_list (detected_list_size,false);
				std::vector<unsigned int> community_members;
				Client* client, *client2;
				BloomFilter* bloom;
				
				for (int i=0; i < detected_list_size; i++) {
					client = detected_list[i];
					if(map_already_there.find(client->getName()) != map_already_there.end()){
						int time_add = map_already_there.find(client->getName())->second;
						if((m_count - time_add)*m_correlate_time > m_flush_time){
							map_already_there.erase(client->getName());
						} else {
							present_list[i] = true;
							continue;
						}
					}

					present_list[i] = true;
					community_members.push_back(client->getName());
					
					bloom = client->bloomfilter;
					for(int j=i+1; j < detected_list_size; j++){
						if(present_list[j])
							continue;
						client2 = detected_list[j];
						if(map_already_there.find(client2->getName()) != map_already_there.end()){
							int time_add = map_already_there.find(client2->getName())->second;
							if((m_count - time_add)*m_correlate_time > m_flush_time){
								map_already_there.erase(client2->getName());
							} else {
								continue;
							}
						}

						if(client2->bloomfilter->compare(bloom) > f_merge_thres){ //merge
							community_members.push_back(client2->getName());
							present_list[j] = true;
							if(client2->bloomfilter->fillrate() < bloom->fillrate())
								bloom = client2->bloomfilter;
						}

					}
					if(community_members.size() > m_thres_communities){
						m_count_communities++;
						for(unsigned int i=0; i < community_members.size(); i++){
							if(map_already_there.find(community_members[i]) == map_already_there.end()){
								map_already_there.insert(std::make_pair(community_members[i], m_count));
							}
						}

						std::vector<Alert::Node> community_members2;
						for (unsigned int k = 0; k < community_members.size(); k++) {
							community_members2.push_back(Alert::Node(community_members[k]));
						}
						
						std::shared_ptr<Alert> alert = std::make_shared<Alert>(get_name(), m_count_communities, "COMMUNITY DETECTED");
						alert.get()->set_targets(community_members2);
						send_out_through(alert,m_out_gate_id);
						
					}
					community_members.clear();

				}
	
				return;
			}
		}
    };

#ifndef _BLOCKMON_DOXYGEN_SKIP_

    REGISTER_BLOCK(DNSCorrelate,"DNSCorrelate");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */

}//blockmon

#endif
