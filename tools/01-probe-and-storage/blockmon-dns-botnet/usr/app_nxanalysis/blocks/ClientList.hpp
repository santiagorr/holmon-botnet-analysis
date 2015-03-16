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

#ifndef _USR_APP_NXANALYSIS_BLOCKS_CLIENTLIST_HPP_
#define _USR_APP_NXANALYSIS_BLOCKS_CLIENTLIST_HPP_


#include "Client.hpp"
#include "BloomFilter.hpp"
#include <unordered_map>
#include <boost/unordered_map.hpp>
#include <iostream>
#include<netinet/in.h>


namespace NXAnalyzer{

class ClientList
{
	int number_clients;
	int clientlist_tid;
	typedef boost::unordered_map<uint32_t, Client*> unordered_map;
	unordered_map map;
    
	public:
		
		
        /** The constructor of the client list
         */
        ClientList();
		
		
		/**
		 * Constructor 
		 *@param the sizeof the bloom filter
		 *@param number of hash function
		 */
		ClientList(int bufferSize, int numHash);
		
		
        /** Second constructor of the clientlist
         * @param the client to construct the list with
         */
        ClientList(Client* client);
		
		
		/**
		 * Destructor
		 */
		virtual ~ClientList();

		
        /** Retrive the client object associated to an ip address
         * If the client doesn't exist, create it before
         * @param IP address of the client
         * @param timestamp of the creation of the client object
         * @return Client
         */
		Client* retrive(uint32_t sip4, uint64_t timestamp);


        /** add a new client in the list
         * @param client ot insert
         */
        void putClient(Client* client);


        /** Remove a client object from the list
         * @param client to remove
         * @return removed client, null if the object doesn't exist
         */
        Client* removeClient(Client* client);

		
        /** test if the client is contained in the list
         * @param client
         * @return true if it contains, false otherwise
         */
        bool contains(Client* client);



        /** test if the client is contained in the list
         * @param IP address
         * @return true if it contains, false otherwise
         */
        bool contains(uint32_t IP);

		
        /** retrieve a client object associated with an IP addresse
         * @param IP address of the client
         * @return the client object, null if it doesn't exist
         */
        Client* get(uint32_t IP);

        /** get the current size of the client list
         * @return the number of clients in the list
         */
        int size();

		
        /** get the client i in the client list
		 * @param the position of the client in the list
         * @return the client 
         */
		Client* getclient(int i);

        /** clear the list from clients
         *
         */
        void clear();
		
		/** get the identifier of the list
		 * @return the identifier
		 */
		int getID();

		/** put an identifier to the list
		 * @param the identifier
		 */
		void putID(int i);

		
        BloomFilter* bloomFilter;
		
};

}
#endif // _USR_APP_NXANALYSIS_BLOCKS_CLIENTLIST_HPP_
