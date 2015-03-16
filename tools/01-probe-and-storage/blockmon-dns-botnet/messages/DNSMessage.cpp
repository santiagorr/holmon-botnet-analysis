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

#ifndef _MESSAGES_DNSMESSAGE_CPP_
#define _MESSAGES_DNSMESSAGE_CPP_

#include "DNSMessage.hpp"
#include "DNSParser.hpp"

namespace blockmon {

	/*
 	 * Constructor.
 	 * @param &p Packet with DNS content.
 	 */ 	
	DNSMessage::DNSMessage(const Packet &p) : Msg(MSG_ID(DNSMessage)) {
		DNSParser parser;
		parser.Parse(p, *this);
	}

	/* Helper printing function for DNS question */
        void DNSMessage::print_DNS_question(struct q_record rec) {
                std::cout << "Question: Type " << rec.rtype;
                std::cout << "  Class " << rec.dclass;
                std::cout << "\tName " << rec.qname->c_str() << std::endl;
        }

        /* Helper printing function for CNAME question */
        void DNSMessage::print_DNS_cname(struct cname_record rec) {
                std::cout << "CNAME: Type " << rec.rtype;
                std::cout << "  Class " << rec.dclass;
                std::cout << "  TTL " << rec.ttl;
                std::cout << "\tName " << rec.qname->c_str();
                std::cout << "\tPrimaryName " << rec.cname->c_str() << std::endl;
        }

        /* Helper printing function for A RECORD question */
        void DNSMessage::print_DNS_arec(struct a_record rec) {
                std::cout << "ARecord: Type " << rec.rtype;
                std::cout << "  Class " << rec.dclass;
                std::cout << "  TTL " << rec.ttl;
                std::cout << "\tName " << rec.qname->c_str();
                std::cout << "\tIP " << (rec.ip_addr >> 24) << "." << ((rec.ip_addr >> 16) & 0xFF) << ".";
                std::cout << ((rec.ip_addr >> 8) & 0xFF) << "." << (rec.ip_addr & 0xFF) << std::endl;
        }

	/* Main printing function for DNS packet */
        void DNSMessage::print() {
                static int seq = 1;
                std::cout << "==== DNS Header ==== "     << seq++ << std::endl;
                std::cout << "Transaction ID \t\t0x"             << std::hex << (int) transaction_id << std::dec << "\t";
                std::cout << "Query[0]/Response[1] \t"   << (int) QR_flag << std::endl;
                std::cout << "Operation code \t\t"               << (int) op_code << "\t";
                std::cout << "Authoritative answer \t"   << (int) AA_flag << std::endl;
                std::cout << "Truncated message \t"              << (int) TC_flag << "\t";
                std::cout << "Recursion desired \t"              << (int) RD_flag << std::endl;
                std::cout << "Recursion available \t"    << (int) RA_flag << "\t";
                std::cout << "Answer authenticated \t"   << (int) AD_flag << std::endl;
                std::cout << "Non-authenticated data\t"  << (int) ND_flag << "\t";
                std::cout << "Reply code\t\t"                    << (int) re_code << std::endl;

                std::cout << "==== DNS Sections ==== "   <<  std::endl;
                std::cout << "Questions " << n_questions << "\t\t\tAnswers " << n_answer <<  std::endl;
                std::cout << "Authority " << n_ns << "\t\t\tAdditional " << n_additional <<  std::endl;

                std::cout << "==== DNS Questions ==== "  <<  std::endl;
                for (unsigned int i = 0; i < queries.size(); i++)
                        print_DNS_question(queries[i]);

                std::cout << "==== DNS Answers ==== "    <<  std::endl;
                for (unsigned int i = 0; i < c_names.size(); i++)
                        print_DNS_cname(c_names[i]);
                for (unsigned int i = 0; i < a_recs.size(); i++)
                        print_DNS_arec(a_recs[i]);

                std::cout << std::endl;
        }

}

#endif
