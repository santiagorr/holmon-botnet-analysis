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

/**
 * <blockinfo type="DNSTraceReader" invocation="async" thread_exclusive="True">
 *   <humandesc>
 *      Reads the input from a text file (timestamp, DNS protobuf packet) and
 *      creates blockmon DNSMessage messages. Only the NOERROR DNSMessages are
 *      forwarded to output.  The input file has the following format (the
 *      number refer to the column):
 *		input[0] -> timestamp;
 *		input[1 - 6] -> unrelated information;
 *		input[7] -> DNS protobuf packet.
 *		The format of the DNS protobuf packet is specified in "ticket_dns.pb.h".
 *   </humandesc>
 *   <shortdesc>
 *      Reads (timestamp, DNS protobuf packet), creates blockmon DNSMessage
 *      messages and forward NOERROR messages to the output.
 *   </shortdesc>
 *
 *   <gates>
 *     <gate type="output" name="out_msg" msg_type="DNSMapping" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *    element params {
 *      element skip_until_timestamp {
 *        attribute val = {unsigned int}
 *      }
 *      element file_name {
 *        attribute val = {string}
 *      }
 *      element time_align {
 *        attribute val = {bool}
 *      }
 *    }
 *   </paramsschema>
 *
 *   <paramsexample>
 *     <params>
 *		  <skip_until_timestamp val = "0"/>
 *		  <trace_speed_mul val = "1"/>
 *		  <file_name val = 
 *		  	"/home/schiavone/svn/demons/Sources/blockmon/main/node/usr/app_nranalysis/dns_trace/input"/>
 *        <time_align val = "false"/>
 *     </params>
 *   </paramsexample>
 *
 *   <variables>
 *     <variable name="inputPktCnt" human_desc="integer" access="read"/>
 *   </variables>
 *
 * </blockinfo>
 */
#include <netinet/in.h> 
#include <Block.hpp>
#include <Packet.hpp>
#include <pugixml.hpp>
#include <BlockFactory.hpp>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <NetTypes.hpp>
#include <boost/algorithm/string.hpp>
#include <ctype.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <iostream>
#include <ctime>
#include <PairMsg.hpp>

#include "DNSMessage.hpp"
#include "DNSParser.hpp"
#include "ticket_dns.pb.h"
#include <DNSMapping.hpp>

using namespace pugi;

namespace blockmon
{
	static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

    class DNSTraceReader: public Block
    {
        int m_gate_id;
		DNSParser m_dns_parser;
		/* Start the analysis aligning to the start of the next hour. */
		bool m_time_align;
		float m_trace_speed_mul;
		uint64_t m_skip_until_timestamp;
		uint32_t m_ref_realtime;
		uint32_t m_cur_realtime;
		uint32_t m_ref_virtualtime;
		uint32_t m_cur_virtualtime;
        double m_input_pkt_cnt;

		/* Name of the input file */
		std::ifstream m_input_file;
    public:
		/**
		  * @brief Constructor
		  * @param name			The name of the source block
		  * @param invocation	Invocation type of the block.
		  */
        DNSTraceReader(const std::string &name, invocation_type invocation) :
			Block(name, invocation_type::Async), //ignore options, must be indirect
        	m_gate_id(register_output_gate("out_msg")),
			m_ref_realtime(0),
			m_cur_realtime(0),
			m_ref_virtualtime(0),
			m_cur_virtualtime(0),
			m_input_pkt_cnt(0)
        {
            register_variable("inputPktCnt",make_rd_var(no_mutex_t(), m_input_pkt_cnt));
		}
		
		/**
		  * Configure the block
		  * @param n	The xml subtree.
		  */
        void _configure(const pugi::xml_node& n) 
        {
            pugi::xml_node file_name = n.child("file_name");
            if(!file_name) 
                throw std::runtime_error("missing file_name");

            pugi::xml_node time_align = n.child("time_align");
            if(!time_align) 
                throw std::runtime_error("missing time align");
            m_time_align = time_align.attribute("val").as_bool();

            pugi::xml_node skip_until_timestamp = n.child("skip_until_timestamp");
            if(!skip_until_timestamp) 
                throw std::runtime_error("missing skip_until_timestamp");
            m_skip_until_timestamp = (skip_until_timestamp.attribute("val").as_uint());

            pugi::xml_node trace_speed_mul = n.child("trace_speed_mul");
            if(!trace_speed_mul) 
                throw std::runtime_error("missing trace_speed_mul");
            m_trace_speed_mul = (trace_speed_mul.attribute("val").as_float());

			if ((m_skip_until_timestamp >> 32) == 0)
				m_skip_until_timestamp = m_skip_until_timestamp << 32;

			m_ref_realtime = (uint32_t)std::time(0);
			
			m_input_file.open(file_name.attribute("val").value());
        }
       	
		/**
		  * The function to read the DNS packet from a text file.
		  */
        void _do_async()
        {
			/* If the file is closed the trace is over */	
			if (!m_input_file.is_open())
				return;

			/* If the end of the input file is reached, close file */
			if (m_input_file.eof()) {
				std::cout << "The trace is over\n";
				m_input_file.close();
				return;
			}

			/* Read line from the input file */
			std::string line;
			getline(m_input_file, line);

			/* Put the line content into a vector */
			std::vector<std::string> line_vec;
			/* Split the line into columns */
			boost::split(line_vec, line, boost::is_any_of("\t"));

			/* Decode line information: timestamp */
			uint64_t timestamp = strtoul(line_vec[0].c_str(), NULL, 10);

			if ((timestamp >> 32) == 0)
				timestamp = timestamp << 32;

			if (m_skip_until_timestamp && (timestamp < m_skip_until_timestamp ))
				return;
			
			m_input_pkt_cnt++;

			/* Check if the analysis is time aligned, otherwise wait for the
			 * next hour */
			if (m_time_align) {
				if (timestamp % 3600)
					return;
				else
					m_time_align = false;
			}

			/* The string is coded in base64 */
			int size = line_vec.size() - 2;
			if (size < 0)
				return;

			std::string b64_dns_packet = line_vec.at(size);
			
			std::string protob_dns_packet = base64_decode(b64_dns_packet);

			/* Parse the string containing a protocol buffer packet into a c++ class */
			ticket_dns ticket;	
			ticket.ParseFromString(protob_dns_packet);	
		
			/* Perform a prefiltering: if the packet is not NOERROR, or the answer field
			 * is empty, do not forward the packet on */

			/* Accept only answer message, the rcode has to be present */
			if (!ticket.has_rcode())
			 	return;
			/* Accept only NOERROR answer */
			if (ticket.rcode() != 0)
				return;
			/* Accept only packet carrying at least one answer */
			if (ticket.answers_size() == 0)
				return;
		
			std::shared_ptr<DNSMessage> msg = std::make_shared<DNSMessage>();
			
			m_dns_parser.Parse_from_protobuf(ticket, *msg, timestamp);

			/* Only DNS answers with at least one a-record or one c-record */
			if (msg->a_recs.size() == 0)
				return;

			std::string *name, *last_cname;
			
			ustime_t c_time = (msg->timestamp >> 32) * 1000000;
			
			#if 0
			if (m_current_timestamp == 0)
				m_current_timestamp = msg->timestamp >> 32;
			
			if ((msg->timestamp >> 32) >= m_current_timestamp) {
				m_current_timestamp = msg->timestamp >> 32;
			} else {
				std::cout << "WARNING: Old Timestamp: ";
				std::cout << m_current_timestamp << " " << (msg->timestamp >> 32) << "\n";
			}
			#endif

			if (msg->c_names.size()) {
    			name = msg->c_names.front().qname;
    			last_cname = msg->c_names.back().cname;
			} else {
    			name = msg->a_recs.front().qname;
    			last_cname = msg->a_recs.front().qname;
			}
			
			/* This transormation is not anymore needed since it is done in the DNSMapper*/
			#if 1
			/* Transform the identifier into a lower-case string */
	    	std::transform(name->begin(), name->end(), 
				name->begin(), ::tolower);
			
			/* Transform the identifier into a lower-case string */
	    	std::transform(last_cname->begin(), last_cname->end(), 
				last_cname->begin(), ::tolower);
			#endif

			for (unsigned int i = 0; i < msg->a_recs.size(); i++) {
				uint32_t ip_addr = msg->a_recs[i].ip_addr;
				std::shared_ptr<DNSMapping> out_msg =
					std::make_shared<DNSMapping>(c_time, *name, *last_cname, ip_addr);
				send_out_through(out_msg, m_gate_id);
			}
			
			if (m_trace_speed_mul) {
				if (m_ref_virtualtime == 0)
					m_ref_virtualtime = timestamp >> 32;

				m_cur_virtualtime = timestamp >> 32;

				m_cur_realtime = (uint32_t)std::time(0);
				
				if (m_cur_virtualtime - m_ref_virtualtime >= 60) {
					int diff = m_cur_realtime - m_ref_realtime;
					if (60/m_trace_speed_mul - diff > 0)
						usleep((60/m_trace_speed_mul - diff)*1000000);
					m_ref_realtime = (uint32_t)std::time(0);
					m_ref_virtualtime = m_cur_virtualtime;
				}
			}

			/* If the end of the input file is reached, close file */
			if (m_input_file.eof()) {
				std::cout << "The trace is over\n";
				m_input_file.close();
				return;
			}
		}

		/** Helper function to check if a char is a base64 number 
		  * @param c 	It is the char to be checked.
		  */	
		static inline bool is_base64(unsigned char c) {
	  		return (isalnum(c) || (c == '+') || (c == '/'));
		}

		/** Helper function to decode a base64 number 
		  * @param encoded_string 	It is the string to be decoded.
		  */	
		std::string base64_decode(std::string const& encoded_string) {
	  		size_t in_len = encoded_string.size();
	  		size_t i = 0;
	  		size_t j = 0;
	  		int in_ = 0;
	  		unsigned char char_array_4[4], char_array_3[3];
	  		std::string ret;
	
	  		while (in_len-- && ( encoded_string[in_] != '=') && 
				is_base64(encoded_string[in_])) {
	   			char_array_4[i++] = encoded_string[in_]; in_++;
	    			if (i ==4) {
	      				for (i = 0; i <4; i++)
	        				char_array_4[i] = 
								static_cast<unsigned char>
								(base64_chars.find(char_array_4[i]));
	
	      				char_array_3[0] = 
							(char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
	      				char_array_3[1] = 
							((char_array_4[1] & 0xf) << 4) +
							((char_array_4[2] & 0x3c) >> 2);
	      				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) +
							char_array_4[3];
	
	      				for (i = 0; (i < 3); i++)
	        				ret += char_array_3[i];
	      				i = 0;
	    			}
	  		}
	
	  		if (i) {
	    			for (j = i; j <4; j++)
	      				char_array_4[j] = 0;
	
	    			for (j = 0; j <4; j++)
	      				char_array_4[j] = 
							static_cast<unsigned char>
							(base64_chars.find(char_array_4[j]));
	
	    			char_array_3[0] =
						(char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
	    			char_array_3[1] = 
						((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
	    			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
	
	    			for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	  		}
	  	return ret;
		}
    };

#ifndef _BLOCKMON_DOXYGEN_SKIP_
    REGISTER_BLOCK(DNSTraceReader,"DNSTraceReader");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */
}

