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
 
#include "BloomFilter.hpp"

namespace NXAnalyzer{

BloomFilter::BloomFilter():
        bufferSize(BUFFER_SIZE),
        numberHash(NUMBER_HASH),
        m_numberOnes(0),
        compareCount(0) {
			arraySize = (bufferSize/8) + 1;
            buffer = new unsigned char[arraySize];
			m_ratecount = (arraySize / 64) + 1;
            initBloom();
        }

BloomFilter::BloomFilter(int bS, int nH):
        bufferSize(bS),
        numberHash(nH),
        m_numberOnes(0),
        compareCount(0) {
			arraySize = (bufferSize/8) + 1;
            buffer = new unsigned char[bufferSize];
			m_ratecount = (arraySize / 64) + 1;
            initBloom();
        }

BloomFilter::~BloomFilter(){
		delete [] buffer;
}
		
unsigned* BloomFilter::hashFunction(unsigned char *name, int len){
    unsigned  *msgdig;
	msgdig = new unsigned[5];
	sha.Reset();
    sha.Input((const unsigned char *)name, len);
    if(!sha.Result(msgdig)){
		return NULL;
	}
	return msgdig;
}

bool BloomFilter::addDomain(unsigned char *name, int len){
	int i;
    unsigned hash;
    int count=0;
    for(i=0; i<numberHash; i++){
        hash = (unsigned) hashFunction(name, len)[i];
		hash %= bufferSize;
	
        if((buffer[hash/8] >> (hash%8)) & 1){
            count++;
		} else {
            buffer[hash/8]  |= (1 << (hash%8));
			m_numberOnes++;
			compareCount |= ( 1 << (i/(8*m_ratecount)));
			
		}
   }
   if(count == numberHash) return true;
   return false;
}

bool BloomFilter::contains(unsigned char *name, int len){
    int i=0;
    unsigned hash;
    for(i=0; i<numberHash; i++){
		hash = (unsigned)hashFunction(name, len)[i];
		hash %= bufferSize;

        if(!((buffer[hash/8] >> (hash%8)) & 1)){
            return false;
		}
    }
    return true;

}

float BloomFilter::fillrate(){
    return ((float)(m_numberOnes)/bufferSize);
}

int BloomFilter::numberOnes(){
    int i=0;
    int count=0;
    for(i=0; i<bufferSize; i++){
        if((buffer[i/8] >> (i%8)) & 1)
            count++;
    }
    return count;
}

void BloomFilter::initBloom(){
    int i=0;
    for(i=0; i<arraySize; i++){
        buffer[i]=0;
    }
    m_numberOnes = 0;
	
}

int BloomFilter::getNumberOnes(){
    return m_numberOnes;
}


void BloomFilter::copyBloom(BloomFilter *bf){
    memcpy(buffer, bf->buffer, bufferSize);
    m_numberOnes = bf->getNumberOnes();
}

unsigned char * BloomFilter::getBuffer() const {
	return buffer;
 }
 
float BloomFilter::compare(BloomFilter* bf){
	int i;
	int counter=0;
	const unsigned char * temp_buffer = bf->getBuffer();
	for(i=0; i<bufferSize; i++){
		if((i%8==0)&&((temp_buffer[i/8] & buffer[i/8]) == 0)){
			i+=7;
			continue;
		}
		if(((temp_buffer[i/8] >> (i%8)) & 1) & ((buffer[i/8] >> (i%8)) & 1))
			counter++;
	}

	if(m_numberOnes < bf->getNumberOnes())
		return (float)(counter/(m_numberOnes*1.0));
	else 
		return (float)(counter/(bf->getNumberOnes()*1.0));

}

void BloomFilter::merge(BloomFilter* bf){
	int i;
	const unsigned char * temp_buffer = bf->getBuffer();
	for(i=0; i<arraySize; i++){
		buffer[i] &= temp_buffer[i];
	}
}

unsigned long long BloomFilter::getCompareCount(){
	return compareCount;
}

}
