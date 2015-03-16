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

#ifndef _USR_APP_NXANALYSIS_BLOCKS_CLIENT_HPP_
#define _USR_APP_NXANALYSIS_BLOCKS_CLIENT_HPP_
#include "BloomFilter.hpp"
#include <stdlib.h>
#include<cstdio>
#include<netinet/in.h>
#include "NetTypes.hpp"
#include <iostream>
#include <chrono>

namespace NXAnalyzer{

class Client
{
         uint32_t name;
		int smartCounter;
        int requestCounter;
        uint64_t time_stamp;
        int uid;
        static int clientCounter;

    public:
		
		/** constructor of the Client class
         *
         *@param the ip address of the client
         *@param the timestamp of the creation of the object
         */
        Client(uint32_t sip4, uint64_t timestamp);

		/** Constructor
         *
         *@param the ip address of the client
         *@param the timestamp of the creation of the object
		 *@param the size of the bloom filter buffer in bits
		 *@param the number of hash function to use
         */
		Client(uint32_t sip4,uint64_t timestamp, int bufferSize, int numHash);

		/**
		 * Destructor
		 */
        virtual ~Client();
		
		Client(const Client &)=delete;
        Client& operator=(const Client &) = delete;
        Client(Client &&)=delete;
        Client& operator=(Client &&) = delete;

        /** insert the requested domain names in the client's bloom filter
         * @param domain names
         */
        void hit(unsigned char* domain, int len);


        /** clear the different elements of the client
         */
        void clear();

        /** get the current the timestamp of the client
         * @return the client timestamp
        */
        uint64_t getTimestamp();

        /** to initialize the different fields of the client
         */
        void initClient();

        /** get the approximate value of the nuber of different domain names in the bloom filter
         * @return number of requested domain name
         */
        int getSmartCounter();

        /** get the ip address of the client
         * @return IP address of the client
         */
        uint32_t getName();


		void flushClient(uint64_t timestamp);


        BloomFilter* bloomfilter;


};
}
#endif // _USR_APP_NXANALYSIS_BLOCKS_CLIENT_HPP_
