// BASADO EN DNSMapper


/*
 * <blockinfo type="DNSBotMapper" invocation="direct" thread_exclusive="False">
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

/*
 * TMP? Funciones para insertar en la base de datos
 * Mejor que esto esté en otro bloque
 *
 * 
 *
 */
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/warning.h>
#include <cppconn/metadata.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/resultset_metadata.h>
#include <cppconn/statement.h>
#include <mysql_driver.h>
#include <mysql_connection.h>

#include <time.h>


namespace blockmon
{
	class DNSBotMapper: public Block
	{
		int m_ingate_id;
		int m_nx_outgate_id;
		int m_nr_outgate_id;

		int m_rcode;
		std::vector<uint32_t>   m_addrs;
		std::string             m_name;
		std::string             m_last_cname;

        // TODO: ¿se necesitan o estorban?
        uint16_t    m_id;
        uint16_t    m_qr;
        uint16_t    m_qdcount;
        uint16_t    m_ancount;
        uint16_t    m_nscount;
        uint16_t    m_arcount;

        sql::Driver *m_db_driver;
        std::shared_ptr<sql::Connection> m_con;
        std::string m_db_name;
        std::string m_db_ip;
        std::string m_db_user;
        std::string m_db_passwd;
   
		public:
		/**
		 * @brief Constructor
		 * @param name			The name of the source block
		 * @param invocation	Invocation type of the block.
		 */
		DNSBotMapper(const std::string &name, invocation_type invocation) : 
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

				//if(m_rcode == dnsqr::kRCodeNoError) {
					//nxmsg.get()->set_ip_address(m_addrs);
					//for (auto it = m_addrs.begin(); it != m_addrs.end(); it++) {
						//send_out_through(std::move(std::make_shared<DNSMapping>
							//(p->timestamp_us(), m_name, m_last_cname, *it)),
							//m_nr_outgate_id);
					//}
				//}

                
                //std::cout << "src ip: " << p->ip_src() << "\n" ;
                //std::cout << "dst ip: " << p->ip_dst() << "\n" ;
                //std::cout << "timestamp: " << p->timestamp_s() << "\n" ;
                //
                //std::cout << "m_id " << m_id << "\n";
                //std::cout << "m_qr " << m_qr << "\n";
                //std::cout << "m_rcode " << m_rcode << "\n";
                //std::cout << "m_qdcount " << m_qdcount << "\n" ;
                //std::cout << "m_ancount " << m_ancount << "\n" ;
                //std::cout << "m_nscount " << m_nscount << "\n" ;
                //std::cout << "m_arcount " << m_arcount << "\n" ;
                
                dump_packet_db(std::move(m), std::move(p));

				send_out_through(std::move(nxmsg), m_nx_outgate_id);

			}

		}

		bool parse(std::shared_ptr<const Packet>&& pkt) {

			// get a parser
			auto parser = dnsqr::Parser<DNSBotMapper>(*this);

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
            m_id = id ;
            m_qr = dnsqr::Decode::qr(codes);
			m_rcode = dnsqr::Decode::rcode(codes);
            m_qdcount = qdcount;
            m_ancount = ancount;
            m_nscount = nscount;
            m_arcount = arcount;

            
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

        // TODO: pasarlo a otro bloque
        
		/**
		  * Configure the block
		  * @param n	The xml subtree.
		  */
        void _configure(const pugi::xml_node&  n){
            std::cout << "configuring \n" ;
            pugi::xml_node db_name = n.child("db_name");
            if(!db_name) 
                throw std::runtime_error("missing db_name");
            std::string m_db_name = db_name.attribute("val").value();

            pugi::xml_node db_ip = n.child("db_ip");
            if(!db_ip) 
                throw std::runtime_error("missing db_ip");
            std::string m_db_ip = db_ip.attribute("val").value();

            pugi::xml_node db_user = n.child("db_user");
            if(!db_user) 
                throw std::runtime_error("missing db_user");
            std::string m_db_user = db_user.attribute("val").value();

            pugi::xml_node db_passwd = n.child("db_passwd");
            if(!db_passwd) 
                throw std::runtime_error("missing db_passwd");
            std::string m_db_passwd = db_passwd.attribute("val").value();

            std::stringstream sql;
            /* Using the Driver to create a connection */

            m_db_driver = sql::mysql::get_driver_instance();
            // WITHOUT THIS con_tmp, BLOCKMON BADLY EXITS
            std::shared_ptr<sql::Connection> con_tmp(m_db_driver->connect(m_db_ip, 
                        m_db_user, m_db_passwd));

            m_con = con_tmp;

            /* The usage of USE is not supported by the prepared statement protocol */
            std::shared_ptr<sql::Statement> stmt(m_con->createStatement());

            stmt->execute("USE " + m_db_name);

            stmt->execute("DROP TABLE IF EXISTS test");
            stmt->execute("CREATE TABLE test(id INT, label CHAR(1))");

        }

        void dump_packet_db(std::shared_ptr<const Msg>&& m, 
                std::shared_ptr<const Packet>&& p){

            std::stringstream insert_into;

            insert_into << "INSERT INTO DNSMessageHeader ";
            insert_into << "(PacketID, Query_ID, QR_flag, R_code, QD_count, AN_count, NS_count, AR_count, time, timestamp, Source_addr, Dest_addr)";
            insert_into << "VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"; 

            std::shared_ptr<sql::PreparedStatement> prep_stmt(m_con->prepareStatement(insert_into.str()));
            
            prep_stmt->setUInt(1, m_id);
            prep_stmt->setUInt(2, m_qr);
            prep_stmt->setUInt(3, m_rcode);
            prep_stmt->setUInt(4, m_qdcount);
            prep_stmt->setUInt(5, m_ancount); 
            prep_stmt->setUInt(6, m_nscount);
            prep_stmt->setUInt(7, m_arcount);

            time_t curr_time;
            curr_time = (uint64_t)p->timestamp_s();
            struct tm *c_time = localtime(&curr_time);            
            std::stringstream unix_timestamp;

            unix_timestamp << c_time->tm_year+1900 << "-"; 
            unix_timestamp << c_time->tm_mon+1 << "-";
            unix_timestamp << c_time->tm_mday << " ";
            unix_timestamp << c_time->tm_hour << ":";
            unix_timestamp << c_time->tm_min << ":";
            unix_timestamp << c_time->tm_sec; 
            
            prep_stmt->setDateTime(8,unix_timestamp.str());
            prep_stmt->setUInt64(9, p->timestamp_s());
            prep_stmt->setUInt(10, p->ip_src());
            prep_stmt->setUInt(11, p->ip_dst());

            prep_stmt->executeUpdate();
        }

	};
#ifndef _BLOCKMON_DOXYGEN_SKIP_
	REGISTER_BLOCK(DNSBotMapper,"DNSBotMapper");
#endif /* _BLOCKMON_DOXYGEN_SKIP_ */
}

