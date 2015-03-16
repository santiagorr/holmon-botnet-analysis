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
#include "Client.hpp"

namespace NXAnalyzer{

int Client::clientCounter = 0;

Client::Client(uint32_t sip4,uint64_t timestamp):
 name(sip4),
 smartCounter(0),
 requestCounter(0),
 time_stamp(timestamp){
    uid = clientCounter++;
	bloomfilter = new BloomFilter();
 }

Client::Client(uint32_t sip4,uint64_t timestamp, int bufferSize, int numHash):
 name(sip4),
 smartCounter(0),
 requestCounter(0),
 time_stamp(timestamp){
    uid = clientCounter++;
	bloomfilter = new BloomFilter(bufferSize, numHash);
 }
 
 Client::~Client()
{
	delete bloomfilter;
}
 
void Client::hit(unsigned char* domain, int len)
{
    requestCounter++;
    if(!bloomfilter->addDomain(domain, len))
        smartCounter++;
}

uint64_t Client::getTimestamp(){
    return time_stamp;
}


int Client::getSmartCounter(){
    return smartCounter;
}

void Client::initClient(){
    smartCounter=0;
    bloomfilter->initBloom();
}

uint32_t Client::getName(){
    return name;
}

void Client::flushClient(uint64_t timestamp){
	smartCounter=0;
	requestCounter=0;
	bloomfilter->initBloom();
    time_stamp = timestamp;
}

}