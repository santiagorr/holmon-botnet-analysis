/*
 * <blockinfo type="DNSMapper" invocation="direct" thread_exclusive="False">
 *   <humandesc>
 *      Derives DNSMapping messages from Packets on input, and forwards them
 *      to the output gate. A DNSMapping contains a query plus all addresses 
 *      and cnames returned therefor.
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
 *   <gates>
 *     <gate type="output" name="out_nr_msg" msg_type="DNSMapping" m_start="0" m_end="0" />
 *     <gate type="output" name="out_nx_msg" msg_type="DnsEntry" m_start="0" m_end="0" />
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

#include <DNSQRParser.hpp>
#include <DNSMapping.hpp>
#include <DnsEntry.hpp>

namespace blockmon
{
	class DNSMapper: public Block
	{
		int m_ingate_id;
		int m_nx_outgate_id;
		int m_nr_outgate_id;

		int m_rcode;
		std::vector<uint32_t>   m_addrs;
		std::string             m_name;
		std::string             m_last_cname;

		public:
		/**
		 * @brief Constructor
		 * @param name			The name of the source block
		 * @param invocation	Invocation type of the block.
		 */
		DNSMapper(const std::string &name, invocation_type invocation) : 
			Block(name, invocation),
			m_ingate_id(register_input_gate("in_msg")),
			m_nx_outgate_id(register_output_gate("out_nx_msg")), 
			m_nr_outgate_id(register_output_gate("out_nr_msg")) 
		{
		}

		/**
		 * Receive a packet, parse and forward if necessary.
		 *
		 * @param m	The message to be checked.
		 */
		void _receive_msg(std::shared_ptr<const Msg>&& m, int /* index */) 
		{
			auto p = std::dynamic_pointer_cast<const Packet>(m);
			if (parse(std::move(p))) {
				std::transform(m_name.begin(), m_name.end(), 
						m_name.begin(), ::tolower);
				std::transform(m_last_cname.begin(), m_last_cname.end(), 
						m_last_cname.begin(), ::tolower);
				
				std::shared_ptr<NXAnalyzer::DnsEntry> nxmsg =
					std::make_shared<NXAnalyzer::DnsEntry>
					(m_name, p->ip_dst(), m_rcode, p->timestamp_s());

				if(m_rcode == dnsqr::kRCodeNoError) {
					nxmsg.get()->set_ip_address(m_addrs);
					for (auto it = m_addrs.begin(); it != m_addrs.end(); it++) {
						send_out_through(std::move(std::make_shared<DNSMapping>
							(p->timestamp_us(), m_name, m_last_cname, *it)),
							m_nr_outgate_id);
					}
				}

				send_out_through(std::move(nxmsg), m_nx_outgate_id);

			}

		}

		bool parse(std::shared_ptr<const Packet>&& pkt) {

			// get a parser
			auto parser = dnsqr::Parser<DNSMapper>(*this);

			// clear members
			m_name.clear();
			m_last_cname.clear();
			m_addrs.clear();

			// stash the time in the mapping, to signify we're valid
			pkt->timestamp_us();

			// parse payload -- this calls our callbacks, filling them in
			if (!parser.parse_dns_payload(pkt->payload(), pkt->payload_len())) {
				return false;
			}

			return true;
		}
		
		/* In order to integrate with the NXDomain Analysis, we need also NX answers*/
		#if 0
		bool dns_header(uint16_t id, uint16_t codes, 
				uint16_t qdcount, uint16_t ancount,
				uint16_t nscount, uint16_t arcount) {
			// mappings only care about positive results
			return dnsqr::Decode::qr(codes) && (ancount > 0) &&
				(dnsqr::Decode::rcode(codes) == dnsqr::kRCodeNoError);
		}

		#else

		bool dns_header(uint16_t id, uint16_t codes,
				uint16_t qdcount, uint16_t ancount,
				uint16_t nscount, uint16_t arcount) {
			// mappings only care about positive results
			m_rcode = dnsqr::Decode::rcode(codes);
			return (dnsqr::Decode::rcode(codes) == dnsqr::kRCodeNoError) ||
	   			   (dnsqr::Decode::rcode(codes) == dnsqr::kRCodeNXDomain);
		}


		#endif

		void dns_end(bool complete) {
			// we don't actually care about the end of the message
		}

		void dns_qd(const std::string& name, dnsqr::RRType qtype) {
			// stash the name we asked for
			m_name = name;
			// stash this as cname (will be replaced by subsequent cnames)
			m_last_cname = name;
			m_name = m_name.substr(0, m_name.length() - 1);
			m_last_cname = m_last_cname.substr(0, m_last_cname.length() - 1);
		}

		void dns_rr_a(dnsqr::Section sec, const std::string& name, 
				unsigned ttl, uint32_t a) 
		{
			if (sec == dnsqr::kSectionAnswer) {
				m_addrs.push_back(a);
			} 
		}

		void dns_rr_cname(dnsqr::Section sec, const std::string& name,
				unsigned ttl, std::string& cname) {
			// stash the cname (this handles the _last_ one)
			if (sec == dnsqr::kSectionAnswer) {
				m_last_cname = cname;
				m_last_cname = m_last_cname.substr(0, m_last_cname.length() - 1);
			}
		}


	};
#ifndef _BLOCKMON_DOXYGEN_SKIP_
	REGISTER_BLOCK(DNSMapper,"DNSMapper");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */
}

