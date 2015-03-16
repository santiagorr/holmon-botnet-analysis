/* Copyright (c) 2011, Consorzio Nazionale Interuniversitario
 * per le Telecomunicazioni.
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

#ifndef _MESSAGES_DNSPARSER_CPP_
#define _MESSAGES_DNSPARSER_CPP_

#include "DNSParser.hpp"
#include <NetTypes.hpp>
#include <netinet/in.h>

// FIXME no bounds checking -- trivially crafted-packet segfaultable

// loads 2B in Big endian into uint_16t
// FIXME astoundingly unportable
#define load_BE_u16(A) (((*(A)) << 8) + *((A) + 1))

// loads 4B in Big endian into uint_16t
// FIXME astoundingly unportable
#define load_BE_u32(B) (((load_BE_u16(B)) << 16) + (load_BE_u16(B + 2)))

namespace blockmon {
	#ifdef WITH_NR_DNS_ANALYSIS
	/*
	 * Method for parsing DNS packet from a protocol buffer packet.
	 * @param &t Protocol buffer packet with DNS content.
	 * @param &msg Processed DNS packet in DNSMessage format.
	 */ 
	int DNSParser::Parse_from_protobuf(const ticket_dns &t, DNSMessage &msg,
		uint64_t timestamp)
	{
		msg.timestamp = timestamp;
		/* transaction_id */
		if (t.has_session_id())
			msg.transaction_id = (uint16_t)t.session_id();
		else
			msg.transaction_id = (uint16_t)(-1);

		msg.QR_flag = 255;
		/* QR_flag not used */
	#if 0
		if (t.has_qr_flag())
			msg.QR_flag = (uint8_t)t.qr_flag();
	#endif

		/* op_code */
		if (t.has_opcode())
			msg.op_code = t.opcode();
		else		
			msg.op_code = (uint8_t)(-1);

		/* Authoritative Answer flag */
		if (t.has_auth_ans())
			msg.AA_flag = (uint8_t)t.auth_ans();
		else
			msg.AA_flag = (uint8_t)(-1);		

		/* TrunCation flag */
		if (t.has_trunc())
			msg.TC_flag = (uint8_t)t.trunc();
		else
			msg.TC_flag = (uint8_t)(-1);	
		/* Recursion Desired flag */
		if (t.has_rec_des())
			msg.RD_flag = (uint8_t)t.rec_des();
		else
			msg.RD_flag = (uint8_t)(-1);	
		/* Recursion Available flag */
		if (t.has_rec_des())
			msg.RA_flag = (uint8_t)t.rec_avail();
		else
			msg.RA_flag = (uint8_t)(-1);	

		msg.AD_flag = (uint8_t)(-1);
		msg.ND_flag = (uint8_t)(-1);

		/* re_code */
		if (t.has_rcode())
			msg.re_code = t.rcode();
		else
			msg.re_code = (uint8_t)(-1);


		msg.n_questions = t.questions_size();
		msg.n_answer = t.answers_size();
		msg.n_ns = 0;
		msg.n_additional = t.additionals_size();

		for (int i = 0; i < t.questions_size(); i++) {
			const ticket_dns::Question q = t.questions(i);
			struct q_record q_rec;
			if (q.has_type())
				q_rec.rtype = q.type();
			else
				q_rec.rtype = (uint16_t)(-1);

			if (q.has_dns_class())
				q_rec.dclass = q.dns_class();
			else
				q_rec.dclass = (uint16_t)(-1);

			if (q.has_name()) {
				std::string *str = new std::string(); 
				*str = q.name();
				q_rec.qname = str;
			} else
				q_rec.qname = NULL;
			msg.queries.push_back(q_rec);
		}

		for (int i = 0; i < t.answers_size(); i++) {
			const ticket_dns::ResourceRecord a = t.answers(i);
			/* Check if A-record */
			if (a.type()==1) {
				struct a_record a_rec;

				if (a.has_ttl())
					a_rec.ttl = a.ttl();
				else
					a_rec.ttl = (uint32_t)(-1);

				if (a.has_type())
					a_rec.rtype = a.type();
				else
					a_rec.rtype = (uint16_t)(-1);

				if (a.has_dns_class())
					a_rec.dclass = a.dns_class();
				else
					a_rec.dclass = (uint16_t)(-1);

				if (a.has_name()) {
					std::string *str = new std::string(); 
					*str = a.name();
					a_rec.qname = str;
				} else
					a_rec.qname = NULL;

				if (a.has_rdata()) {
					std::string ip_addr = a.rdata();
					uint32_t ip_out = 0;
					ip_out += (unsigned int)(uint8_t)ip_addr[0] << 24;
					ip_out += (unsigned int)(uint8_t)ip_addr[1] << 16;
					ip_out += (unsigned int)(uint8_t)ip_addr[2] << 8;
					ip_out += (unsigned int)(uint8_t)ip_addr[3];
					a_rec.ip_addr = ip_out;
				}
				msg.a_recs.push_back(a_rec);
			}
			/* Check if CNAME-record */
			if (a.type()==5) {
				struct cname_record c_rec;

				if (a.has_ttl())
					c_rec.ttl = a.ttl();
				else
					c_rec.ttl = (uint32_t)(-1);

				if (a.has_type())
					c_rec.rtype = a.type();
				else
					c_rec.rtype = (uint16_t)(-1);

				if (a.has_dns_class())
					c_rec.dclass = a.dns_class();
				else
					c_rec.dclass = (uint16_t)(-1);

				if (a.has_name()) {
					std::string *str = new std::string(); 
					*str = a.name();
					c_rec.qname = str;
				} else
					c_rec.qname = NULL;

				if (a.has_rdata()) {
					std::string *str = new std::string(); 
					*str = a.rdata();
					*str = (*str).substr(0, (*str).size() - 1);
					c_rec.cname = str;
				} else
					c_rec.cname = NULL;
				msg.c_names.push_back(c_rec);
			}
		}
		return 0;
	}
	#endif
	/*
	 * Method for DNS packet parsing. 
	 * @param &p Packet with DNS content.
	 * @param &msg Processed DNS packet in DNSMessage object.
	 */
	int DNSParser::Parse(const Packet &p, DNSMessage &msg) {
		uint8_t *dns_payload = (uint8_t *) p.payload();

		msg.timestamp = p.timestamp_s();

		msg.transaction_id = load_BE_u16(dns_payload);
		
		/*msg.QR_flag = *(m_buffer + dns_offset + 2) >> 0x7;*/
		msg.QR_flag = *(dns_payload + 2) >> 0x7;
		msg.op_code = (*(dns_payload + 2) >> 3) & 0xF;
		msg.AA_flag = (*(dns_payload + 2)  >> 2) & 0x1;
		msg.TC_flag = (*(dns_payload + 2)  >> 1) & 0x1;
		msg.RD_flag = (*(dns_payload + 2) & 0x1);
		msg.RA_flag = (*(dns_payload + 3) >> 0x7);
		msg.AD_flag = (*(dns_payload + 3) >> 0x5) & 0x1;
		msg.ND_flag = (*(dns_payload + 3) >> 0x4) & 0x1;
		msg.re_code = *(dns_payload + 3) & 0xF;

		msg.n_questions = load_BE_u16(dns_payload + 4);
		msg.n_answer = load_BE_u16(dns_payload + 6);
		msg.n_ns = load_BE_u16(dns_payload + 8);
		msg.n_additional = load_BE_u16(dns_payload + 10);

		struct q_record * q_r;
		uint16_t consumed = 0;
		uint16_t len = 0;
		uint8_t *q_offset = (dns_payload + 12); /* proc je tu 6 */

		for (int i = 0; i < msg.n_questions; i++) { // parse questions
			q_r = new struct q_record;
			consumed = 0;
			q_r->qname = read_dns_name(&consumed, q_offset, dns_payload);
			q_offset += consumed;
			q_r->rtype = load_BE_u16(q_offset);
			q_offset += 2;
			q_r->dclass = load_BE_u16(q_offset);
			q_offset += 2;
			msg.queries.push_back(*q_r);
			delete q_r;
		}

		uint8_t *a_offset = q_offset;
		uint16_t type;
		uint16_t dclass;
		uint32_t ttl;
		std::string * tmp;
		struct cname_record* cn_r;
		struct a_record* a_r;

		for (int i = 0; i < msg.n_answer; i++) { // parse answers
			consumed = 0;
			tmp = read_dns_name(&consumed, a_offset, dns_payload);
			a_offset += consumed;
			type = load_BE_u16(a_offset);
			a_offset += 2;
			dclass = load_BE_u16(a_offset);
			a_offset += 2;
			ttl = load_BE_u32(a_offset);
			/*a_offset += 4;
			  len = load_BE_u16(a_offset);
			  a_offset += 2;*/
			a_offset += 6;

			switch (type) {
				case 1: // RR type address
					a_r = new struct a_record;
					a_r->ttl = ttl;
					a_r->rtype = type;
					a_r->dclass = dclass;
					a_r->qname = tmp;
					a_r->ip_addr = load_BE_u32(a_offset);
					a_offset += 4;
					msg.a_recs.push_back(*a_r);
					delete a_r;
					break;
				case 5: // RR type canonical name
					cn_r = new struct cname_record;
					cn_r->ttl = ttl;
					cn_r->rtype = type;
					cn_r->dclass = dclass;
					cn_r->qname = tmp;
					consumed = 0;
					cn_r->cname = read_dns_name(&consumed, a_offset, dns_payload);
					a_offset += consumed;
					msg.c_names.push_back(*cn_r);
					delete cn_r;
					break;

				default:
					break;
			}
		}
		return 0;
	}

	std::string *DNSParser::read_dns_name(uint16_t* consumed, const uint8_t * data, const uint8_t * dns_start) {
		unsigned int i = 0;
		uint8_t j = 0;
		std::string *tmp;
		std::string *ret;
		uint16_t fake = 0;
		uint16_t jump;

		if (*data < 0xC0) { // check if the DNS name is stored here or linked somewhere else in packet
			ret = new std::string();
			j = *(data + i);
			while (j != 0 && j < 0xC0) {
				i++;
				if (i != 1)
					*ret += "."; // put dot before each domain except the first one
				tmp = new std::string((const char*)(data + i) , j); // parse j symbols
				*ret += *tmp;
				i += tmp->length();
				j = *(data + i); // load new start of domain
				delete tmp;
			}
			if (j != 0) {
				jump = load_BE_u16(data + i) & 0x3FFF;
				*consumed += i + 2; // increase number of consumed bytes
				// we are no longer consuming packet bytes, so &fake is used
				tmp = (read_dns_name(&fake, dns_start + jump, dns_start));
				*ret += ".";
				*ret += *tmp;
				delete tmp;
				return (ret);
			}
			else {
				*consumed += i + 1; // consume the ending zero
			}
		}
		else { // we hit the link so jump somewher else in the packet
			jump = (load_BE_u16(data + i) & 0x3FFF);
			ret = read_dns_name(&fake, dns_start + jump, dns_start);
			*consumed += 2;
		}

		return ret;
	}
}

#endif //_MESSAGES_DNSPARSER_CPP_

