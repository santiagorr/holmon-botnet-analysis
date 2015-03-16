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
 * <blockinfo type="DNSDemux" invocation="direct" scheduling_type="passive" thread_exclusive="False">
 *   <humandesc>
 *     Demux DNS answers (NOERROR, NXDOMAIN)
 *     The block takes as input packets or DnsEntry messages
 *     The block sends DNS NXDOMAIN messages to the "DNSPacketNX" Block and the NOERROR messages to "DNSPacketNR" blocks
 *   </humandesc>
 *
 *   <shortdesc>Demux DNS answers </shortdesc>
 *
 *   <gates>
 *     <gate type="input" name="in_pkt" msg_type="Packet" m_start="0" m_end="0" />
 *     <gate type="input" name="in_msg" msg_type="DnsEntry" m_start="0" m_end="0" />
 *     <gate type="output" name="out_msg_nx" msg_type="DnsEntry" m_start="0" m_end="0" />
 *     <gate type="output" name="out_msg_nr" msg_type="DnsEntry" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *   </paramsschema>
 *
 *   <paramsexample>
 *     <params>
 *  	  	This block does not require configuration.
 *     </params>
 *   </paramsexample>
 *
 *   <variables>
 *     <variable name="pktcnt"  human_desc="integer" access="read" />
 *     <variable name="nxcount" human_desc="integer" access="read" />
 *     <variable name="nrcount" human_desc="integer" access="read" />
 *   </variables>
 * </blockinfo>
 */

#include<Block.hpp>
#include<Packet.hpp>
#include<DNSPacket.hpp>
#include<BlockFactory.hpp>
#include<cstdio>
#include<netinet/in.h>
#include <iostream>
#include <ctime>
#include <chrono>
#include <iomanip>
#include "NetTypes.hpp"
#include "dnsh.h"
#include <fstream>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <DNSQRParser.hpp>
#include <DNSMapping.hpp>
#include "DnsEntry.hpp"

using namespace NXAnalyzer;
using namespace std;

#if !defined(USE_SIMPLE_PACKET) && !defined(USE_SLICED_PACKET)

// FIXME this class is no more compliant with NewPacket class
//       Reason: the packet is no more linear in memory.
//       TO BE REWRITTEN!

namespace blockmon
{

    /**
     * Implements a block that reads DNS packets and sends the NOERROR and NXDOMAIN answers to other blocks
     */
    class DNSDemux: public Block
    {
        unsigned long long m_count; // the number of packets
		unsigned long long m_dns_nx_count; // number of nxdomain answers
		unsigned long long m_dns_nr_count; // number of noerror answers
		unsigned long long m_current_timer;
		unsigned long long m_pps;
        int m_ingate_id_pkt;
		int m_ingate_id_msg;
		int m_outgate_id_nxmsg;
		int m_outgate_id_nrmsg;
		string m_name;
		int m_rcode;
        std::vector<uint32_t>   m_addrs;
		uint32_t   m_identifier;


    public:
        /**
         * @brief Constructor
         * @param name         The name of the packet counter block
         * @param invocation   Invocation type of the block (Indirect, Direct, Async)
         */
        DNSDemux(const std::string &name, invocation_type invocation) 
        : Block(name, invocation), 
        m_count(0), 
		m_dns_nx_count(0),
		m_dns_nr_count(0),
		m_current_timer(0),
		m_pps(0),
        m_ingate_id_pkt(register_input_gate("in_pkt")),
        m_ingate_id_msg(register_input_gate("in_msg")),
		m_outgate_id_nxmsg(register_output_gate("out_msg_nx")),
		m_outgate_id_nrmsg(register_output_gate("out_msg_nr"))
        {
            register_variable("pktcnt",make_rd_var(no_mutex_t(), m_count));
            register_variable("nxcount",make_rd_var(no_mutex_t(), m_dns_nx_count));
			register_variable("nrcount",make_rd_var(no_mutex_t(), m_dns_nr_count));
        }

		DNSDemux(const DNSDemux &)=delete;
        DNSDemux& operator=(const DNSDemux &) = delete;
        DNSDemux(DNSDemux &&)=delete;
        DNSDemux& operator=(DNSDemux &&) = delete;
       
	   /**
        * @brief Destructor
        */
        ~DNSDemux() {}

        /**
         * @brief Configures the block
         * @param n The configuration parameters 
         */
        void _configure(const pugi::xml_node&  n )
        {	

        }

        /**
         * @brief reads the DNS header and send the packet to the appropriate gate
         * @param m     The message
         * @param index The index of the gate the message came on
         */
        void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */)
        {
            if(m->type()==MSG_ID(Packet))
            {
				const Packet* packet = static_cast<const Packet*>(m.get());
				m_count++;
				
				m_current_timer = packet->timestamp_s();
				m_identifier = packet->ip_dst();
				
				auto parser = dnsqr::Parser<DNSDemux>(*this);
				m_name.clear();
				m_addrs.clear();
				
				if(parser.parse_dns_payload(packet->payload(), packet->payload_len())){
					if(m_rcode == 3){
						if(m_name.empty())
							return;
						m_dns_nx_count++;
						send_out_through(std::move(std::make_shared<DnsEntry>(m_name, m_identifier, m_rcode,   m_current_timer)), m_outgate_id_nxmsg);
					} else if(m_rcode == 0){
						m_dns_nr_count++;
						std::shared_ptr<DnsEntry> nxmsg = std::make_shared<DnsEntry>(m_name, m_identifier, m_rcode, m_current_timer);
						nxmsg.get()->set_ip_address(m_addrs);
						send_out_through(std::move(nxmsg), m_outgate_id_nrmsg);
					}
							
				}
			} else if(m->type() == MSG_ID(DnsEntry)){
				const DnsEntry* nxmsg = static_cast<const DnsEntry*>(m.get());
				m_rcode = (nxmsg->get_rcode());
				if(m_rcode == 3){
					m_dns_nx_count++;
					send_out_through(std::move(m), m_outgate_id_nxmsg);
				}else if(m_rcode == 0){
					m_dns_nr_count++;
					send_out_through(std::move(m), m_outgate_id_nrmsg);					
				}
			}
			
        }
		
		
		bool dns_header(uint16_t id, uint16_t codes,
				uint16_t qdcount, uint16_t ancount,
				uint16_t nscount, uint16_t arcount) {
			// mappings only care about positive results
				m_rcode = dnsqr::Decode::rcode(codes);
			return (dnsqr::Decode::rcode(codes) == dnsqr::kRCodeNoError)||(dnsqr::Decode::rcode(codes) == dnsqr::kRCodeNXDomain);
			}
		void dns_qd(const std::string& name, dnsqr::RRType qtype) {
			m_name = name;
		}
	    void dns_end(bool complete) {
        // we don't actually care about the end of the message
		}
	
		void dns_rr_a(dnsqr::Section sec, const std::string& name,  unsigned ttl, uint32_t a) 
		{
			// same as the ftw nr analysis
			if (sec == dnsqr::kSectionAnswer) {
				m_addrs.push_back(a);
			} 
		}
	
	    void dns_rr_cname(dnsqr::Section sec, const std::string& name,
                      unsigned ttl, std::string& cname) {
			//do nothing, and don't know how to get rid of it
		}
	

    };

#ifndef _BLOCKMON_DOXYGEN_SKIP_
    REGISTER_BLOCK(DNSDemux,"DNSDemux");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */

}//blockmon

#endif
