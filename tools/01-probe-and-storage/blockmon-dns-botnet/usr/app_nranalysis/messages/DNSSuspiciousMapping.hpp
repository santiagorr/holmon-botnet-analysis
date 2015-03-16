/* Copyright (c) 2012 ETH Zürich. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the names of ETH Zürich nor the names of other contributors 
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
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DNS_SUSPICIOUS_MAPPING_HPP_
#define _DNS_SUSPICIOUS_MAPPING_HPP_

#include <Msg.hpp>
#include <ClassId.hpp>
#include <NetTypes.hpp>

#include <vector>
#include <memory>
#include <iostream>
#include <stdint.h>

#include <boost/lexical_cast.hpp>

namespace blockmon {
    
    class DNSSuspiciousMapping: public Msg {

    protected:
        uint32_t                m_time;
        std::string             m_domain_name;
        uint32_t                m_a;
        std::string             m_client_id;
        float     				m_score;
		int						m_num_blocks;
		bool					m_whitelisted;
        
    public:
        
        DNSSuspiciousMapping(uint32_t time, const std::string& dname, uint32_t a,
			const std::string client_id, float score, int num_blocks):
            Msg(MSG_ID(DNSSuspiciousMapping)), 
            m_time(time), 
            m_domain_name(dname), 
            m_a(a),
			m_client_id(client_id),
			m_score(score),
			m_num_blocks(num_blocks),
			m_whitelisted(false)
		{
        }

        uint32_t time() const {
            return m_time;
        }

        const uint32_t message_time() const { return m_time; }   

        const std::string& domain_name() const { return m_domain_name; }
 
        const uint32_t address() const { return m_a; }       

        const std::string& client_id() const { return m_client_id; }

        const float score() const { return m_score; }   

        const int num_blocks() const { return m_num_blocks; }   

        const bool whitelisted() const { return m_whitelisted; }   

		void set_whitelisted() { m_whitelisted = true; } 
		
		void unset_whitelisted() { m_whitelisted = false; } 

        void print(std::ostream& os) const {
            os << time() << " ";
            os << domain_name() << " ";
            os << address() << " ";
            os << client_id() << " ";
            os << score() << " ";
            os << num_blocks() << " ";
            os << whitelisted() << " ";
            os << std::endl;
        }

        // we never use this but it's pure virtual so might as well provide it?
        std::shared_ptr<Msg> clone() const {
            return std::make_shared<DNSSuspiciousMapping>(*this);
        }

    };
}

#endif
