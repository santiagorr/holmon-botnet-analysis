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

#ifndef _USR_APP_NXANALYSIS_BLOCKS_BLOOMFILTER_HPP_
#define _USR_APP_NXANALYSIS_BLOCKS_BLOOMFILTER_HPP_
#include<cstring>
#include<stdlib.h>
#include "bloom/sha1.h"

namespace NXAnalyzer{

class BloomFilter
{

        int            			bufferSize;
        int             		numberHash;
        int             		m_numberOnes;
        unsigned long long		compareCount;
		int 					m_ratecount;
		int 					arraySize;
        unsigned char *         buffer;
    	SHA1					sha;


    public:
        /**
        * The Constructor of the Bloom filter
        * More to come
        */
        BloomFilter();

        /**
         * Constructor of the bloom filter
         * We get the size and the number of hash function from the XML files
         * @param the size of the bloom filter
         * @param the number of hash functions to use
         */
        BloomFilter(int bS, int nH);

		/**
		 * Destructor
		 */
	    ~BloomFilter();

		BloomFilter(const BloomFilter &)=delete;
        BloomFilter& operator=(const BloomFilter &) = delete;
        BloomFilter(BloomFilter &&)=delete;
        BloomFilter& operator=(BloomFilter &&) = delete;
        /**
         * A function to test if a string belongs to the bloom filter
         * @param the domain name
         * @return true if the bloom filter contains the string, false otherwise
         */
         bool contains(unsigned char *name, int len);

        /**
         * Add a string to the bloom filter
         * @param the domain name
         * @return true if the domain exist, false otherwise
         */
        bool addDomain(unsigned char *name, int len);

        /**
         * The hashing function
         * it is Dumb in this stage
         * will use crypto hashing functions in the future
         * @param the domain name
         * @param the number of the hashing function
         * @return the value of the hashing function
         */
        unsigned*  hashFunction(unsigned char *name, int len);

        /**
         * Compare between two bloom filters
         * @param a pointer to the second bloom filter
         * @return the degree of resemblance between the two bloom filter
         */
        float compare(BloomFilter* bloomFilter);

        /**
         * the fill rate of the bloom filter
         * used to compare between two bloom filters
         * or to test
         * @return the fill rate of the current bloom filter
         */
        float fillrate();

        /**
         * the number of ones in the bloom filter
         * compute it from the buffer directly
         * Usefull in the comparaison and in the computing
         * @return number of ones in the bloom filter
         */
         int numberOnes();

        /**
          * Initialize the bloom filter
          * init the vector and all the integers used different counting operations
          */
        void initBloom();

        /**
         * Get the buffer
         *@return the memory space reserved for the bloom filter
         */
        unsigned char * getBuffer() const; // will probably not be used

        /**
         * Get the number of ones
         * Use onle the integer count
         * @return the value of the count numberOnes
         */
        int getNumberOnes();

        /**
         * The number of ones in the comparaison
         * The compared number of count
         * @return the value of the compute value
         */
		int getNumberComp();
		
        /** copy bloom filters
         * @param bloom filter to copy
         */
        void copyBloom(BloomFilter* bf);

		/**
		 * merge two bloom filters according to our NX detection
		 * @param the bloom filter to merge with
		*/
		void merge(BloomFilter* bf);

		/**
		 * get the compare count
		 * @retrun the compare count of the object
		*/		
		unsigned long long getCompareCount();
		
		/** The defaut size of the bloom filter */
		static const int BUFFER_SIZE = 800;

		/** The Defaut number of the hash functions */
		static const int NUMBER_HASH = 2;
		

};
   
}
#endif // _USR_APP_NXANALYSIS_BLOCKS_BLOOMFILTER_HPP_
