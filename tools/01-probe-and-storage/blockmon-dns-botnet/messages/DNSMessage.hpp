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

#ifndef _MESSAGES_DNSMESSAGE_HPP_
#define _MESSAGES_DNSMESSAGE_HPP_

//#if defined(USE_SIMPLE_PACKET) || defined(USE_SLICED_PACKET)

#include <Msg.hpp>
#include <NewPacket.hpp>
#include <Packet.hpp>

namespace blockmon
{

	struct q_record {
		uint16_t rtype;
		uint16_t dclass;
		std::string* qname;
	};


	struct cname_record {
		uint32_t ttl;
		uint16_t rtype;
		uint16_t dclass;
		std::string* qname;
		std::string* cname;
	};

	struct a_record {
		uint32_t ttl;
		uint16_t rtype;
		uint16_t dclass;
		uint32_t ip_addr;
		std::string* qname;
	};

	class DNSMessage : public Msg 
	{
                public:
						uint64_t timestamp;
                        //DNS packet content
                        uint16_t transaction_id;
                        uint8_t QR_flag;
                        uint8_t op_code;
                        uint8_t AA_flag;
                        uint8_t TC_flag;
                        uint8_t RD_flag;
                        uint8_t RA_flag;
                        uint8_t AD_flag;
                        uint8_t ND_flag;
                        uint8_t re_code;

                        uint16_t n_questions;
                        uint16_t n_answer;
                        uint16_t n_ns;
                        uint16_t n_additional;


                        std::vector<struct q_record> queries;
                        std::vector<struct a_record> a_recs;
                        std::vector<struct cname_record> c_names;
                
                        /*
                         * Constructor. Create empty DNS message.
                         */                      
                        DNSMessage():
                                Msg(MSG_ID(DNSMessage)) 
                        {}                            
                        
                        /*
                         * Constructor. Create DNS message from Packet.
                         * @param &p Reference to Packet 
                         */
                        DNSMessage(const Packet &p);

                        /*
                         * Destructor
                         */                      
                        virtual ~DNSMessage() 
                        {
                            for (std::vector<struct q_record>::iterator it = queries.begin(); it != queries.end(); it++) {
                                delete it->qname;
                            }
                            queries.clear();
                            for (std::vector<struct a_record>::iterator it = a_recs.begin(); it != a_recs.end(); it++) {
                                delete it->qname;
                            }
                            a_recs.clear();
                            for (std::vector<struct cname_record>::iterator it = c_names.begin(); it != c_names.end(); it++) {
                                delete it->qname;
                                delete it->cname;
                            }
                            c_names.clear(); 
                        }

			/*
 			 * 
 			 */ 
			std::shared_ptr<Msg> clone() const
			{
				return std::make_shared<DNSMessage>(*this);
			}
		private:
			/*
 			 * Print DNS question
 			 * @param q_record Q record
 			 */
			void print_DNS_question(struct q_record);
                        
			/*
 			 * Print CName record
 			 * @param cname_record CName record
 			 */
			void print_DNS_cname(struct cname_record);
                        
			/*
 			 * Print A record
 			 * @param a_record A record
 			 */
			void print_DNS_arec(struct a_record);
	
		public:
			/*
 			 * Print DNSMessage content
 			 */
			void print(); 		
 	
        };
}


//#endif //if defined(USE_SIMPLE_PACKET) || defined(USE_SLICED_PACKET)


#endif
