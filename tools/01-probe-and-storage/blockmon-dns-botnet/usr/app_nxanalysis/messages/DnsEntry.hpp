/*--------------------------------------------------------
 * FTR&D/MAPS/STT
 *--------------------------------------------------------
 *
 * Copyright France Telecom  2012,  All Rights Reserved.
 *
 * This software is the confidential and proprietary
 * information of France Telecom.
 * You shall not disclose such Confidential Information
 * and shall use it only in accordance with the terms
 * of the license agreement you entered into with
 * France Telecom.
 *
 *--------------------------------------------------------
 * Author      : Hachem GUERID
 *--------------------------------------------------------
 */
 #ifndef _USR_APP_NXANALYSIS_MESSAGES_DnsEntry_HPP_
#define _USR_APP_NXANALYSIS_MESSAGES_DnsEntry_HPP_


#include "Msg.hpp"
#include "ClassId.hpp"
#include <stdint.h>
#include <string>
#include <vector>

using namespace std;
using namespace blockmon;


namespace NXAnalyzer
{

    /**
     * Message containing the DNS information necessary for NXDomain application
     */

    class DnsEntry : public Msg
    {
		/**
		 * Domain name of the reply
		 */
		std::string m_name;

		/**
		 * Identifier of the client
		 */
		uint32_t   m_identifier;

		
		/**
		 * type of DNS reply
		 */
		int m_rcode;
		
		/**
		 * Source addresses of the domain names
		 */
		vector<uint32_t> m_ip_address;
		

		
		/**
		 * Add one source
		 * @param source The source (IP) to append to the list
		 */
		void add_source(uint32_t source);
		
		/**
		 * timestamp of the application
		 */
		ustime_t m_time;
		

		
    public:

        /**
         *  Create a new NXDNS message
         */        
        DnsEntry(std::string domain_name, uint32_t identifier, int rcode, ustime_t timestamp)
        : Msg(MSG_ID(DnsEntry)), m_name(domain_name), m_identifier(identifier), m_rcode(rcode),
			m_time(timestamp)
        {
        }

		/**
		 * get the domain name 
		 */
		const std::string& get_name() const{
			return m_name;
		
		}

		/**
		 * get the identifier of the user 
		 */
		const uint32_t& get_identifier() const{
			return m_identifier;
		}		
		
		/**
		 * get the rcode of the reply
		 */
		const int& get_rcode() const{
			return m_rcode;
		}
		
		/**
		 * Get the timestamp of the received packet
		 */
		const ustime_t& get_timestamp() const{
			return m_time;
		}
		
		/**
		 * Set the IP addressses of the domain name
		 */
		void set_ip_address(const vector<uint32_t> ip_address){
			m_ip_address = vector<uint32_t>(ip_address);
		}

		/**
		 * Get the IP addressses of the domain name
		 */		
		const vector<uint32_t> get_ip_address() const {
			return m_ip_address;
		}

        /**
        * No copy constructor
        */
        DnsEntry(const DnsEntry &) = delete;
        
        /**
        * No copy assignment operator
        */
        DnsEntry& operator=(const DnsEntry &) = delete;

        /**
        * No move constructor
        */
        DnsEntry(DnsEntry &&) = delete;
        
        /**
        * No move assignment operator
        */
        DnsEntry& operator=(DnsEntry &&) = delete;

        /**
        * Destroy the msg
        */
        ~DnsEntry()
        {
        }

		std::shared_ptr<Msg> clone() const 
        {
            std::shared_ptr<DnsEntry> copy = std::make_shared<DnsEntry>(m_name, m_identifier, m_rcode, m_time);
			return  copy;
        }

	private:


	};
}


#endif /* _DnsEntry_HPP_ */
