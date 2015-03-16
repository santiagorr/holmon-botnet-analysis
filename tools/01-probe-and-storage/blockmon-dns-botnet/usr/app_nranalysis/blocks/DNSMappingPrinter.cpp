/*
 * <blockinfo type="DNSMappingPrinter" invocation="direct" thread_exclusive="False">
 *   <humandesc>
 *      Prints DNSMapping information
 *   </humandesc>
 *
 *   <shortdesc>
 *      Generates DNSMappings from packets 
 *   </shortdesc>
 *
 *   <gates>
 *     <gate type="input" name="in_msg" msg_type="Packet" m_start="0" m_end="0" />
 *   </gates>
 *
 *   <paramsschema>
 *    element params {
 *	  }
 *   </paramsschema>
 *
 *   <paramsexample>
 *     <params/>
 *   </paramsexample>
 *
 *   <variables>
 *   </variables>
 *
 * </blockinfo>
 */

#include <Block.hpp>
#include <BlockFactory.hpp>
#include <Packet.hpp>
#include <ClassId.hpp>

#include <iostream>

#include <DNSMapping.hpp>

namespace blockmon
{
   	class DNSMappingPrinter: public Block
   	{
        int m_ingate_id;
        int m_outgate_id;

    public:
		/**
		  * @brief Constructor
		  * @param name			The name of the source block
		  * @param invocation	Invocation type of the block.
		  */
        DNSMappingPrinter(const std::string &name, invocation_type invocation) : 
			Block(name, invocation),
        	m_ingate_id(register_input_gate("in_msg"))
        {
		}
		
		/**
		  * Receive a packet, parse and forward if necessary.
		  *
		  * @param m	The message to be checked.
		  */
        void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */) 
        {            
            std::dynamic_pointer_cast<const DNSMapping>(m)->print(std::cout);
		}
	};
#ifndef _BLOCKMON_DOXYGEN_SKIP_
    REGISTER_BLOCK(DNSMappingPrinter,"DNSMappingPrinter");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */
}

