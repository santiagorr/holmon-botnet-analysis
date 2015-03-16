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
 #ifndef _USR_APP_NXANALYSIS_MESSAGES_INFECTEDLIST_HPP_
#define _USR_APP_NXANALYSIS_MESSAGES_INFECTEDLIST_HPP_

#include "Msg.hpp"
#include "ClassId.hpp"
#include <stdint.h>
#include <string>
#include <vector>
#include "../blocks/Client.hpp"
#include "../blocks/ClientList.hpp"

using namespace std;
using namespace blockmon;

namespace NXAnalyzer
{

    /**
     * BlockMon Message representing an Alert. Alert contains information
	 * about a potential attack or event.
     */

    class InfectedList : public Msg
    {


		/**
		 * Identifier of the message
		 */
		int m_identifier;
		
		/**
		 * Identifier of the message
		 */
		int m_list_size;
		
	

		/**
		 * suspicious hosts list
		 */
		vector<Client*> m_infected;
		


		
    public:

        /**
         *  Create a new InfectedList
         */        
        InfectedList(int identifier, int listSize)
        : Msg(MSG_ID(InfectedList)), m_identifier(identifier), m_list_size(listSize)
        {
        }

		/**
		 * Set the list of suspcious hosts
		 * @param suspicious hosts
		 */
		void set_infected(const vector<Client*> infected){
			m_infected = vector<Client*>(infected);
		}
		
	
		/**
		 * Get the list of suspicious hosts
		 */
		const vector<Client*>* get_infected() const {
			return &m_infected;
		}
		

		int get_identifier() const {
			return m_identifier;
		}

		int get_list_Size() const {
			return m_list_size;
		}
		
		

        /**
        * No copy constructor
        */
        InfectedList(const InfectedList &) = delete;
        
        /**
        * No copy assignment operator
        */
        InfectedList& operator=(const InfectedList &) = delete;

        /**
        * No move constructor
        */
        InfectedList(InfectedList &&) = delete;
        
        /**
        * No move assignment operator
        */
        InfectedList& operator=(InfectedList &&) = delete;

        /**
        * Destroy the infect list
        */
        ~InfectedList()
        {
        }

		std::shared_ptr<Msg> clone() const 
        {
            std::shared_ptr<InfectedList> copy = std::make_shared<InfectedList>(m_identifier, m_list_size);
			copy.get()->set_infected(m_infected);
			return copy;
        }

	private:

	};
}


#endif /* _INFECTEDLIST_HPP_ */
