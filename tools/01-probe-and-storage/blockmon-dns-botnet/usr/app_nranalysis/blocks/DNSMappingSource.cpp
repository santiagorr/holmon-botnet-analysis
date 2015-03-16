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
 

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <fstream>
#include <memory>
#include <NetTypes.hpp>
#include <Block.hpp>
#include <BlockFactory.hpp>
#include <Timer.hpp>
#include <DNSMapping.hpp>
     
namespace blockmon
{

class DNSMappingSource: public Block {

private:
    
    std::string                                         m_filename;
    std::ifstream                                       m_file;
    int                                                 m_gate_id;
    int                                                 m_eosdelay;
    bool                                                m_eos;
    
    static const unsigned int kEOSTimer = 1;
    
public:

    /**
     * Configure the block given an XML element containing configuration.
     * Called before the block will begin receiving messages.
     *
     * @param params_node the <params> XML element containing block parameters
     */
    void _configure(const pugi::xml_node& params_node)  {
        // get filename
        pugi::xml_node col_node;
        if ((col_node = params_node.child("file"))) {
            m_filename = col_node.attribute("name").value();
            if (m_filename.empty()) {
                throw std::runtime_error("File requires name");
            }
        }

        // open file
        m_file.open(m_filename);
    }
    
    DNSMappingSource(const std::string& name, invocation_type invocation):
        Block(name, invocation),
        m_gate_id(register_output_gate("source_out")),
        m_eosdelay(10),
        m_eos(false) {}

    ~DNSMappingSource() {}

    void _do_async()  {

        if (!m_file.is_open() || (m_file.eof())) {
            if (!m_eos) {
                /* Close stream on EOF */
                m_file.close();
                /* Set timer to shut down after stream close */
                blocklog(std::string("Reader at end of stream, will wait ") + 
                        boost::lexical_cast<std::string>(m_eosdelay) +
                            " seconds, then shut down", log_warning);
                set_timer_at(get_BM_time() + m_eosdelay * 1000000, "end of stream", kEOSTimer);            
                m_eos = true;
            }
        } else {
            // read a line and send a message
            std::string line;
            std::vector<std::string> line_vec;
            getline(m_file, line);
            boost::split(line_vec, line, boost::is_any_of("\t"));
            
            ustime_t ustime = boost::lexical_cast<uint64_t>(line_vec[0]) * 1000000;
            uint32_t a = string_to_ipv4(line_vec[3]);
            
            send_out_through(std::make_shared<DNSMapping>(ustime, line_vec[1], line_vec[2], a), m_gate_id);
        }

    }
    
    void _handle_timer(std::shared_ptr<Timer>&& t) {
        if (t->get_id() == kEOSTimer) {
            blocklog(std::string("Reader shutdown"), log_warning);
            exit(0);
        }
    }
};

REGISTER_BLOCK(DNSMappingSource,"DNSMappingSource")
}
