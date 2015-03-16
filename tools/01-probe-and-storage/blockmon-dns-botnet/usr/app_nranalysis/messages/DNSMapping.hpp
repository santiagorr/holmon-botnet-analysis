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

#ifndef _DNS_MAPPING_HPP_
#define _DNS_MAPPING_HPP_

#include <Msg.hpp>
#include <ClassId.hpp>
#include <NetTypes.hpp>

#include <vector>
#include <memory>
#include <iostream>
#include <stdint.h>

#include <boost/lexical_cast.hpp>

namespace blockmon {
    
    class DNSMapping: public Msg {

    protected:
        ustime_t                m_time;
        std::string             m_name;
        std::string             m_last_cname;
        mutable std::string     m_key;
        uint32_t                m_a;
        
    public:
        
        DNSMapping():
            Msg(MSG_ID(DNSMapping)),
            m_time(0) {}
        
        DNSMapping(ustime_t time, const std::string& name, const std::string& last_cname, uint32_t a):
            Msg(MSG_ID(DNSMapping)), 
            m_time(time), 
            m_name(name), 
            m_last_cname(last_cname), 
            m_key(),
            m_a(a) {
            }

        const std::string& last_cname() const { return m_last_cname; }

        const std::string& name() const { return m_name; }
 
        const uint32_t address() const { return m_a; }       

        uint32_t time_sec() const {
            return m_time / 1000000;
        }

        const std::string& key() const {
            // dedupe key not thread safe
            if (m_key.length() == 0) {
                m_key = m_name + m_last_cname + boost::lexical_cast<std::string>(m_a);
                std::transform(m_key.begin(), m_key.end(), m_key.begin(), ::tolower);
            }
            return m_key;
        }

        void print(std::ostream& os) const {
            os << time_sec() << ", ";
            os << last_cname() << ", ";
            os << name() << ", ";
            os << m_a;
            os << std::endl;
        }

        // we never use this but it's pure virtual so might as well provide it?
        std::shared_ptr<Msg> clone() const {
            return std::make_shared<DNSMapping>(*this);
        }

    };
}

#endif
