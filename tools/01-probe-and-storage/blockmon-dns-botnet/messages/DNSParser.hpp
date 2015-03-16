/* Copyright (c) 2011, NEC Europe Ltd, Consorzio Nazionale
 * Interuniversitario per le Telecomunicazioni, Institut
 * Telecom/Telecom Bretagne, ETH Zürich, INVEA-TECH a.s. 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Interuniversitario per le Telecomunicazioni nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
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

#ifndef _MESSAGES_DNSPARSER_HPP_
#define _MESSAGES_DNSPARSER_HPP_

//#if defined(USE_SIMPLE_PACKET) || defined(USE_SLICED_PACKET)

#include "Packet.hpp"
#include "DNSMessage.hpp"

#ifdef WITH_NR_DNS_ANALYSIS
	#include "../usr/app_nranalysis/blocks/ticket_dns.pb.h"
#endif

namespace blockmon
{

	class DNSParser
	{
		public:
			/*
			 * Constructor 
			 */
			DNSParser(){}

			/*
			 * Destructor
			 */ 
			virtual ~DNSParser(){}

			/*
			 * Method for parsing DNS packet.
			 * @param &p Packet with DNS content.
			 * @param &msg Processed DNS packet in DNSMessage format.
			 */ 
			int Parse(const Packet &p, DNSMessage &msg);
		#ifdef WITH_NR_DNS_ANALYSIS
			/*
			 * Method for parsing DNS packet from a protocol buffer packet.
			 * @param &t Protocol buffer packet with DNS content.
			 * @param &msg Processed DNS packet in DNSMessage format.
			 */ 
			int Parse_from_protobuf(const ticket_dns &t, DNSMessage &msg, uint64_t timestamp);
		#endif
		private:
			/*
			 *
			 */ 
			std::string* read_dns_name(uint16_t* consumed, const uint8_t * data, const uint8_t * dns_start); 
	};
}


//#endif //if defined(USE_SIMPLE_PACKET) || defined(USE_SLICED_PACKET)

#endif //_MESSAGES_DNSPARSER_HPP_

