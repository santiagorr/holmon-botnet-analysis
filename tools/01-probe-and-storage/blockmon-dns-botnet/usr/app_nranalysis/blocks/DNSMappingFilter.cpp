/*
 * <blockinfo type="DNSMappingFilter" invocation="direct" thread_exclusive="False">
 *   <humandesc>
 *      Receives DNSMessage message in input and forward this in output
 *      accordind to the following criteria: if the piece of information
 *      carried by this packet in term of couple dname:IP_address has already
 *      been seen in the last period (specified by the parameter
 *      "table_memory") the packet is not forwarded, otherwise it is forwarded.
 *      This block can be introduced in the composition in order to lighten the
 *      following processing from redundant information.
 *   (as returned by the methods in the Packet class)
 *   </humandesc>
 *
 *   <shortdesc>
 *      Filterout packet which couple dname:IP_address has been seen recently.
 *   </shortdesc>
 *
 *   <gates>
 *     <gate type="input" name="in_msg" msg_type="DNSMessage" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <gates>
 *     <gate type="output" name="out_msg" msg_type="DNSMessage" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *    element params {
 *    	element time_bin_complete_flush {
 *			attribute val = {unsigned integer}
 *		}
 *    	element table_memory {
 *			attribute val = {unsigned integer}
 *		}
 *	  }
 *   </paramsschema>
 *
 *   <paramsexample>
 *     <params>
 *		 <time_bin_complete_flush val = "3600"/>
 *		 <table_memory val = "600"/>
 *     </params>
 *   </paramsexample>
 *
 *   <variables>
 *   </variables>
 *
 * </blockinfo>
 */
#include <iostream>
#include <unordered_map>
#include <string>
#include <set>
#include <Block.hpp>
#include <BlockFactory.hpp>
#include <Packet.hpp>
#include <ClassId.hpp>
#include <arpa/inet.h>
#include <sstream>
#include <sstream>
#include <fstream>

#include <DNSMapping.hpp>

namespace blockmon
{


   	class DNSMappingFilter: public Block
   	{
        int m_ingate_id;
        int m_outgate_id;

		/* Definiton of the hash table to store the couple dname:IP_address
		 * mapping recently seen */
		std::unordered_map<size_t, uint32_t> m_deduplicate_table;
		/* Interval of time after which the couple dname:IP_address is flushed
		 * from the table*/
		uint32_t m_table_memory;
		/* Interval of time after which the entire table is flushed. This is
		 * according to the following processing. */
		uint32_t m_time_bin_complete_flush;
		/* Time reference for flushing the table. */
		uint32_t m_next_complete_flush;

		std::hash<std::string> m_hash_fn;

    public:
		/**
		  * @brief Constructor
		  * @param name			The name of the source block
		  */
        DNSMappingFilter(const std::string &name, invocation_type invocation) : 
			Block(name, invocation),
        	m_ingate_id(register_input_gate("in_msg")),
        	m_outgate_id(register_output_gate("out_msg")), 
			m_deduplicate_table(),
			m_next_complete_flush(0)
        {
		}
		
		/**
		  * Configure the block
		  * @param n	The xml subtree.
		  */
		void _configure(const pugi::xml_node&  n) 
        {
            pugi::xml_node complete_flush = n.child("time_bin_complete_flush");
            if(!complete_flush) 
                throw std::runtime_error("missing time_bin_complete_flush");
            m_time_bin_complete_flush = complete_flush.attribute("val").as_uint();

            pugi::xml_node table_memory = n.child("table_memory");
            if(!table_memory) 
                throw std::runtime_error("missing table memory");
            m_table_memory = table_memory.attribute("val").as_uint();
		}
		
		/**
		  * The function to check if the received messag has to be forwarded to
		  * the output.
		  * @param m	The message to be checked.
		  */
        void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */) 
        {
            auto mapping = std::dynamic_pointer_cast<const DNSMapping>(m);
            
            uint32_t c_time = mapping->time_sec();
            
			/* Set time reference to flush the deduplication table */
		    if (m_next_complete_flush == 0)
				m_next_complete_flush = c_time + m_time_bin_complete_flush;
			
			/* Check if is time to flush the deduplication table */
		    if (c_time >= m_next_complete_flush) {
				m_next_complete_flush += m_time_bin_complete_flush;
				m_deduplicate_table.clear();
			}

			bool send = false;
			size_t hash_str = m_hash_fn(mapping->key());
            auto it = m_deduplicate_table.find(hash_str);
            if (it == m_deduplicate_table.end()) {
                // new mapping found, update table and forward
                m_deduplicate_table.insert(
                    std::pair<size_t, uint32_t>(hash_str, 
                                                     mapping->time_sec()));
                send = true;
            } else if (mapping->time_sec() > it->second + m_table_memory) {
                it->second = mapping->time_sec();
                send = true;
            }
            
            if (send) {
                send_out_through(std::move(m), m_outgate_id);
            }
		}
	};
#ifndef _BLOCKMON_DOXYGEN_SKIP_
    REGISTER_BLOCK(DNSMappingFilter,"DNSMappingFilter");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */
}

