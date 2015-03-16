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
#include "ClientList.hpp"

namespace NXAnalyzer{

ClientList::ClientList():
 number_clients(0){
	bloomFilter = new BloomFilter();
}

ClientList::ClientList(Client* client):
number_clients(1){
	bloomFilter = new BloomFilter();
    map.insert(unordered_map::value_type(client->getName(), client));
    bloomFilter->copyBloom(client->bloomfilter);
}

ClientList::ClientList(int bufferSize, int numHash):
 number_clients(0){
	bloomFilter = new BloomFilter(bufferSize, numHash);
 }

Client* ClientList::retrive(uint32_t sip4, uint64_t timestamp){
	unordered_map::iterator map_it;
	map_it = map.find(sip4);
    Client* client;
    if (map_it == map.end()){
        return NULL;
    }
	client = map_it->second;
	return client;

}

void ClientList::putClient(Client* client){
    map.insert(std::make_pair(client->getName(), client));
	
    number_clients++;
}

Client* ClientList::removeClient(Client* client){
    map.erase(client->getName());
    return client;
}

bool ClientList::contains(Client* client){
    if(map.find(client->getName()) == map.end()){
        return false;
    }
    return true;
}


bool ClientList::contains(uint32_t IP){
  if(map.find(IP) == map.end()){
        return false;
    }
    return true;
}

Client* ClientList::get(uint32_t IP){
    if(map.find(IP) == map.end()){
        return NULL;
    }
    return map.find(IP)->second;
}

int ClientList::size(){
    return (int)map.size();

}

void ClientList::clear(){

    map.clear();
	bloomFilter->initBloom();
}

Client* ClientList::getclient(int i){
	if((i < 0)||(i>=(int)map.size()))
		return NULL;
	unordered_map::iterator map_it;

	for(map_it=map.begin(); map_it != map.end(); map_it++){
		if (i==0)
			return map_it->second;
		
		i--;
	}
	return NULL;
}

ClientList::~ClientList()
{
    map.clear();
	delete bloomFilter;
}

int ClientList::getID()
{
	return clientlist_tid;
}
void ClientList::putID(int x)
{
	clientlist_tid = x;
}

}