/* Copyright (c) 2011, NEC Europe Ltd, Consorzio Nazionale 
 * Interuniversitario per le Telecomunicazioni, Institut 
 * Telecom/Telecom Bretagne, ETH Zürich, INVEA-TECH a.s. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the names of NEC Europe Ltd, Consorzio Nazionale 
 *      Interuniversitario per le Telecomunicazioni, Institut Telecom/Telecom 
 *      Bretagne, ETH Zürich, INVEA-TECH a.s. nor the names of its contributors 
 *      may be used to endorse or promote products derived from this software 
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT 
 * HOLDERBE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
 */

#include "IPBlocks.hpp"
#include "toolfunctions.hpp"

#if 0
int maxClusterSize_;
unsigned int maxNumClusters_;
float clusteringThreshold_;
float domainCountThreshold_;
#endif
GeoIP *geodb_;

IPBlock::IPBlock(uint32_t first, uint32_t last)
{
	/* If the ip block contains only one ip address that first = last */
	m_first = first;
	m_last = last;
	m_AS = getAsnAndOrganization(first);
	m_dirtyClusters = false;
#if USE_PREFER_CNAME
	m_preferCname = false;
#endif
}

IPBlock::~IPBlock()
{
	DomainClusterMap::iterator it;
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		delete it->second;
		delete it->first;
	}
}

bool IPBlock::contains(uint32_t ip)
{
	if (ip >= m_first && ip <= m_last)
		return true;
	else
		return false;
}

int IPBlock::getIPIndex(uint32_t ip)
{
	assert(ip >= first() && ip <= last());
	 return (ip - first());
}

bool IPBlock::hitDomainAndIP(DomainStr *dom, uint32_t ip,
	bool createBackRef, int maxClusterSize, float clusteringThreshold)
{
	/* Find the cluster to which this domain belongs */
	DomainCluster *clustVal;
	clustVal = getClusterForDomain(dom, clusteringThreshold);

	if (clustVal == NULL)
		return false;

	if (clustVal->m_isCollapsed) {
	/* Make sure that we remember the collapsed cluster's center for
	 * the next round. Note that it is especially important to
	 * remember the weight of this cluster (i.e., the number of
	 * domains that were in the cluster before collapsing it).
	 */
		if (clustVal->len() < maxClusterSize) {
			bool res = clustVal->add(dom);
			if (res && createBackRef)
				dom->addIPBlock(this);
		}
	}

	if (ip) {
		int ipIndex = getIPIndex(ip);
		clustVal->setIpActive(ipIndex);
	}
	return true;
}

DomainCluster* IPBlock::findBestCollapsedCluster(DomainStr *dom,
	float clusteringThreshold)
{
	DomainClusterMap::iterator it;
	DomainCluster *clustFound = NULL;
	float minVal = 1;
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		DomainCluster *clust = it->second;
		if (clust->isCollapsed()) {
			float dist = domainDist(it->first, dom);
			if (dist <= minVal) {
				minVal = dist;
				if (minVal <= clusteringThreshold)
					clustFound = clust;
			}
		}
	}
	return clustFound;
}

DomainCluster* IPBlock::getClusterForDomain(DomainStr *dom, float clusteringThreshold)
{
	DomainClusterMap::iterator it;
	DomainCluster *clustFound = NULL;
	
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		if (it->second->domainIsPresent(dom))
			clustFound = it->second;
	}

	if (clustFound)
		return clustFound;
	else
		return findBestCollapsedCluster(dom, clusteringThreshold);
}

#if USE_PREFER_CNAME
bool IPBlock::doPreferCname()
{
	return m_preferCname;
}
#endif

bool IPBlock::lt(IPBlock *ipb)
{
	return (m_last < ipb->m_first);
}

bool IPBlock::gt(IPBlock *ipb)
{
	return (m_first < ipb->m_last);
}

uint32_t IPBlock::len()
{
	return (m_last - m_first + 1);
}

uint32_t IPBlock::first()
{
	return m_first;
}

uint32_t IPBlock::last()
{
	return m_last;
}

std::string IPBlock::getAS()
{
	return m_AS;
}

DomainClusterMap* IPBlock::getClusters()
{
	return &m_clusters;
}

DomainClusterMap IPBlock::getCollapsedClusters()
{
	DomainClusterMap::iterator it;	
	DomainClusterMap result;
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		if (it->second->isCollapsed())
			result.insert(*it);
	}
	return result;
}

std::vector<DomainStr *>* IPBlock::getDomainsInClusters()
{
	DomainClusterMap::iterator clustIt;
	DomainStrSet::iterator domIt;
	DomainStrSet filter;
	auto domains = new std::vector<DomainStr *>;
	for (clustIt = m_clusters.begin(); clustIt != m_clusters.end(); clustIt++) {
		DomainStrSet *clusterDomains = clustIt->second->getDomains();
		for (domIt = clusterDomains->begin(); domIt != clusterDomains->end();
			domIt++) {
			DomainStrSet::iterator test;
			test = filter.find(*domIt);
			if (test == filter.end()) {
				domains->push_back(*domIt);
				filter.insert(*domIt);
			}
		}
	}
	
	return domains;
}

bool IPBlock::checkDoubleDomain(float clusteringThreshold)
{
	std::vector<DomainStr *> *domVec = getDomainsInClusters();
	for(unsigned int i = 0; i < domVec->size(); i++) {
		DomainCluster *res = getClusterForDomain(domVec->at(i),
			clusteringThreshold);
		if (res == NULL) {
			std::cout << "Duplicate!\n";
			return true;
		}
	}
	delete domVec;
	return false;
}

std::vector<DomainStr *> IPBlock::getKeysInClusters()
{
	std::vector<DomainStr *> res;
	DomainClusterMap::iterator it;
	for (it = m_clusters.begin(); it != m_clusters.end(); it++)
		res.push_back(it->first);
	return res;
}

void IPBlock::updateRange(uint32_t first, uint32_t last)
{
	m_first = first;
	m_last = last;
}

int IPBlock::getNumDomains()
{
	DomainClusterMap::iterator clustIt;
	DomainStrSet::iterator domIt;
	
	int numDomains = 0;

	for (clustIt = m_clusters.begin(); clustIt != m_clusters.end(); clustIt++) {
		DomainStrSet *clusterDomains = clustIt->second->getDomains();
		numDomains += clusterDomains->size();
	}
	return numDomains;
}

void IPBlock::createBackReferences()
{
	DomainClusterMap::iterator it;
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		if (!it->second->isCollapsed())
			it->second->setAllDomainsReference(this);
	}
}

int IPBlock::removeBackReferences()
{
	DomainClusterMap::iterator it;
	bool res = 0;
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		int numDom = it->second->removeAllDomainsReference(this);
		if (numDom)
			res += numDom;
	}
	return res;
}

void IPBlock::removeClusters()
{
	DomainClusterMap::iterator it;
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		/* Save old empty clusters*/
		if (it->second->getDomains()->size() == 0)
			continue;
		delete it->first;
		delete it->second;
	}
	m_clusters.clear();
}

DomainStr* IPBlock::addCluster(DomainStr *dom, int maxNumClusters, bool isCollapsed)
{
	DomainStr *newDom = new DomainStr(dom);
	/* A copy is needed only in m_clusters. */
	DomainCluster *cl = new DomainCluster(dom, isCollapsed);
	cl->initActiveIPs(len());
	m_clusters.insert(std::pair<DomainStr *, DomainCluster *>(newDom, cl));
#if USE_PREFER_CNAME
	if (m_clusters.size() > maxNumClusters * len())
		m_preferCname = true;
#endif
	return newDom;
}

void IPBlock::addToCluster(DomainStr *dom, DomainStr *key, int maxClusterSize)
{
	DomainClusterMap::iterator it;
	it = m_clusters.find(key);
	/* The key shold be already present inside the map. */
	assert(it != m_clusters.end());
	
	it->second->add(dom);
	if (it->second->len() > maxClusterSize && !it->second->isCollapsed())
		it->second->m_isCollapsed = true;
}

/* This function check if a certain domain "fit" in a cluster of this IPBlock,
 * if it does, gives back the distance. */
float IPBlock::checkDomain(DomainStr *dom, float clusteringThreshold)
{
	/* Find the cluster to which this domain belongs */
	DomainCluster *clustVal;
	clustVal = getClusterForDomain(dom, clusteringThreshold);

	if (clustVal)
		return 0.0;

	if (m_clusters.size() == 0)
		return 1.0;
	
	/* We already have clusters in this block, let's see if we can find one
	 * where dom fits. */
	DomainClusterMap::iterator it;
	float minDist = 1.0;
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		/* Here we do not need to check again for collapsed clusters here
		 * again. If dom is close enough to such a collapsed cluster, this
		 * was found already above in hitDomainAndIP. 
		 */
		 if (it->second->m_isCollapsed)
		 	continue;
	/* We just need to find a cluster that is a good enough representative,
	 * not necessarily the *best cluster
	 */
		float dist = domainDist(it->first, dom);
		if (dist <= minDist) {
			minDist = dist;
			if (dist <= clusteringThreshold / 2)
				break;
		}
	}
	return minDist;	
}


int IPBlock::addDomain(DomainStr* dom, uint32_t ip, float *minDistRet,
	bool createBackRef, int maxClusterSize, int maxNumClusters, 
	float clusteringThreshold)
{
	/* Lets's see if we can find a cluster for this domain name, either we find
	 * one that is sufficiently similar to the domain name, or we create a new
	 * cluster. */	

	if (hitDomainAndIP(dom, ip, true, maxClusterSize, clusteringThreshold)) {
		if (minDistRet)
			*minDistRet = 0.0;
		return 0;
	}

	if (createBackRef)
		dom->addIPBlock(this);
	
	/* This is a new mapping, let's find a cluster for it */
	float minDist = 1.0;
	DomainStr *minKey = NULL;
	
	if (m_clusters.size() == 0) {
		/* Not a single cluster yet: create one for this dom. */
		DomainStr *newClusterCenter = addCluster(dom, maxNumClusters, false);

		if (ip) {
			int ipIndex = getIPIndex(ip);
			m_clusters[newClusterCenter]->setIpActive(ipIndex);
		}

		if (minDistRet)
			*minDistRet = 0.0;
		return 2;
	}
	/* We already have clusters in this block, let's see if we can find one
	 * where dom fits. */
	DomainClusterMap::iterator it;
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		/* Here we do not need to check again for collapsed clusters here
		 * again. If dom is close enough to such a collapsed cluster, this
		 * was found already above in hitDomainAndIP. 
		 */
		 if (it->second->m_isCollapsed)
		 	continue;
	/* We just need to find a cluster that is a good enough representative,
	 * not necessarily the *best cluster
	 */
		float dist = domainDist(it->first, dom);
		if (dist <= minDist) {
			minDist = dist;
			minKey = it->first;
		}
	}
	
	if (minKey == NULL)
		minDist = 1.0;

	if (minDist <= clusteringThreshold) {
		addToCluster(dom, minKey, maxClusterSize);

		if (minDistRet)
			*minDistRet = minDist;
		return 1;
	}
#if USE_PREFER_CNAME
	if (doPreferCname())
		return 3;
	else {
		DomainStr *newClusterCenter = addCluster(dom, maxNumClusters, false);
	
		if (ip) {
			int ipIndex = getIPIndex(ip);
			m_clusters[newClusterCenter]->setIpActive(ipIndex);
		}
	
		m_dirtyClusters = true;
	}
#else
	if (m_clusters.size() <= maxNumClusters * this->len()) {
		/* We found no matching cluster */
		DomainStr *newClusterCenter = addCluster(dom, maxNumClusters, false);
	
		if (ip) {
			int ipIndex = getIPIndex(ip);
			m_clusters[newClusterCenter]->setIpActive(ipIndex);
		}
	
		m_dirtyClusters = true;
	} else
		return 3;
#endif
	if (minDistRet)
		*minDistRet = minDist;
	return 2;
	
}

/* This function will remove all the empty clusters (clusters without domains)
 * and will delete all the domains inside all the clusters. */
void IPBlock::reinitializeClusters(int maxClusterSize, int maxNumClusters)
{
	DomainClusterMap::iterator it;
	std::vector<DomainClusterMap::iterator> clustersToDelete;
	/* First let's remove empty clusters. */
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		int len = it->second->len();
		if (len == 0)
			clustersToDelete.push_back(it);
		else {
			if (it->second->isCollapsed() && len < maxClusterSize)
				it->second->m_isCollapsed = false;
		}
			
	}

	for (unsigned int i = 0; i < clustersToDelete.size(); i++) {
		delete clustersToDelete.at(i)->first;
		delete clustersToDelete.at(i)->second;
		m_clusters.erase(clustersToDelete.at(i));
	}

#if USE_PREFER_CNAME
	if (m_clusters.size() <= maxNumClusters * len())
		m_preferCname = false;
#endif

	/* Now let's remove the domains from the remaining clusters. */
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		it->second->removeAllDomainsReference(this);
		DomainStrSet *domains = it->second->getDomains();
		domains->clear();
	}
}

void IPBlock::setIPsInactive()
{
	DomainClusterMap::iterator it;

	for (it = m_clusters.begin(); it != m_clusters.end(); it++)
		it->second->setAllIPsInactive();
}

std::vector<bool> IPBlock::getActiveIPs()
{
	DomainClusterMap::iterator it;
	std::vector<bool> result(len(), false);

	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		assert(it->second->m_activeIPs.size() == len());

		for (unsigned int i = 0; i < it->second->m_activeIPs.size(); i++) {
			bool res = result.at(i) || it->second->m_activeIPs.at(i); 
			result.at(i) = res;
		}
	}
	return result;
}

void IPBlock::doCluster(int maxClusterSize, int maxNumClusters,
	float clusteringThreshold)
{
	DomainClusterMap::iterator clustIt;
	DomainStrSet::iterator domIt;

	/* Compute the new clusters for all domains stored in this IPBlock, in this
	 * case we have to exclude the collapsed clusters, because the domain
	 * contained in this cluster is not present in the domain factory, we will
	 * add those clusters later */
	
	std::vector<DomainStr *> *domVec;
	domVec = this->getDomainsInClusters();
	DomainClusterMap newClusters = domainCluster(domVec, clusteringThreshold);
	delete domVec;
	
	#if 0
	DomainClusterMap collapsedClusters = getCollapsedClusters();

	/* Also, add the collapsed clusters of this IPBlock again. We need to do
	 * the latter in order to not lose the information about them. */
	for (clustIt = collapsedClusters.begin();
		clustIt != collapsedClusters.end(); clustIt++)
		newClusters.insert(*clustIt);
	#endif
	/* Correct the active IPs setting per cluster, if necessary.*/
	/* Remember to which cluster each of the domains belonged so far, in
	 * order to be able to set the active IPs per new cluster accordingly
	 * */
	std::vector<bool> newActiveIPs;
	std::unordered_map<DomainStr *, DomainStr *> domainToCluster;		
	for (clustIt = m_clusters.begin(); clustIt != m_clusters.end(); clustIt++) {
		DomainStrSet *domains = clustIt->second->getDomains();
		for (domIt = domains->begin(); domIt != domains->end(); domIt++)
			domainToCluster.insert(std::pair<DomainStr *, 
				DomainStr*>(*domIt, clustIt->first));
	}

	for (clustIt = newClusters.begin(); clustIt != newClusters.end(); clustIt++) {
		#if 0
		if (clustIt->second->isCollapsed())
			continue;
		#endif
		newActiveIPs.assign(len(), false);
		DomainStrSet *domains = clustIt->second->getDomains();
		for (domIt = domains->begin(); domIt != domains->end(); domIt++) {
			std::unordered_map<DomainStr *, DomainStr *>::iterator test;
			test = domainToCluster.find(*domIt);
			DomainCluster *oldCluster = m_clusters[test->second];
			/* OR bit by bit, and check if the vector is all true,
			 * in that case interrupt the cycle */
			bool all_true = true;
			for (unsigned int i = 0; i < len(); i++) {
				newActiveIPs.at(i) = 
					newActiveIPs.at(i) || oldCluster->m_activeIPs.at(i);
				all_true = all_true && newActiveIPs.at(i);
			}
			if (all_true)
				break;
		}
		clustIt->second->m_activeIPs = newActiveIPs;
	}

	/* if there are many different domain names: fall back to preferring the
	 * CNAME instead of the queried domain name, probably we find more
	 * structure in them (as we're probably dealing with a CDN here, which
	 * hosts many different domains but often uses CNAME based aliasing).  note
	 * however that this doesn't avoid that we still might end up with many
	 * different domains/CNAMES again.
	 */
#if USE_PREFER_CNAME
	if (newClusters.size() > maxNumClusters * len())
		m_preferCname = true;
#endif

	for (clustIt = m_clusters.begin(); clustIt != m_clusters.end(); clustIt++) {
		if (clustIt->second->getDomains()->size() == 0)
			newClusters.insert(*clustIt);
	}

	/* Everything is clustered now, remember it. */
	removeClusters();
	m_clusters = newClusters;

	m_dirtyClusters = false;

	/* Every time the container is modified we have to start again this loop,
	 * otherwise the iterator could be no more consistent with the container.*/
	for(clustIt = newClusters.begin(); clustIt != newClusters.end(); clustIt++) {
		#if 0
		if (clustIt->second->isCollapsed())
			continue;
		#endif
		if (clustIt->second->len() <= maxClusterSize)
			continue;
		if (clustIt->second->clusterDispersion(0) > clusteringThreshold)
			continue;
		clustIt->second->m_isCollapsed = true;
	}
}

void IPBlock::cluster(int maxClusterSize, int maxNumClusters,
	float clusteringThreshold)
{
	if (!m_dirtyClusters)
		return;

	if (getNumDomains() == 0) {
		/* FIXME: As we are not removing clusters without domains, we should
		 * probably also skip this*/

		/* There are no more domains in this IPBlock, re-initialize the
		 * clusters. */
		removeClusters();
		m_dirtyClusters = false;
		return;
	}
	/* Remove all the clusters that contain no domains. */
	
	#if 0
	std::vector<DomainClusterMap::iterator> clusterKeyToRemove;
	DomainClusterMap::iterator it;
	for (it = m_clusters.begin(); it != m_clusters.end(); it++) {
		if (!it->second->len())
			clusterKeyToRemove.push_back(it);
	}
	
	for (unsigned int i = 0; i < clusterKeyToRemove.size(); i++) {
		/* These clusters should be empty therefore there is no need to remove
		 * the back references. */
		delete clusterKeyToRemove.at(i)->first;
		delete clusterKeyToRemove.at(i)->second;
		m_clusters.erase(clusterKeyToRemove.at(i));
	}
	#endif

	/* As there are domains in this IPBlock, there must also be clusters.
	 * */
	int numClusters = m_clusters.size();
	assert(numClusters);

	if (numClusters == 1) {
		/* There's only one cluster. All domains in that cluster MUST be
		 * well represented by the cluster's center, else they wouldn't be
		 * in there. Therefore there's no need to recluster.
		 */
		 m_dirtyClusters = false;
	} else {
		/* We have domains in this IPBlock and have more than one cluster.
		 * It could be that we meanwhile flushed inactive domains,
		 * therefore reclustering could result in a lower number of
		 * clusters.
		 */
		 doCluster(maxClusterSize, maxNumClusters, clusteringThreshold);
	}
}

void DNSMap::initWithTopQueriedDomains(std::string fileName)
{
	std::ifstream f; 
	f.open(fileName, std::fstream::out);
	std::string line;
	
	if (!f.is_open())
		throw std::runtime_error("Cannot open top queried domains");

	while (1) {
		getline(f, line);
		std::vector<std::string> line_vec;
		boost::split(line_vec, line, boost::is_any_of(" "));
		if (line_vec.size() < 2) {
			if (f.eof())
				break;
			continue;
		}
		std::string *domain = &line_vec[0];
		std::string *ipList = &line_vec[1];

		std::vector<std::string> ip_list_vec;
		boost::split(ip_list_vec, *ipList, boost::is_any_of(","));
		
		for (unsigned int i = 0; i < ip_list_vec.size(); i++) {
			uint32_t ip = (uint32_t)inet_addr(ip_list_vec.at(i).c_str());
			add(ip, domain, domain, 1, 0);
		}
		if (f.eof())
			break;
	}
	f.close();
}

void DNSMap::loadt(std::string fileName)
{
	std::ifstream f; 
	f.open(fileName, std::fstream::out);
	std::string line;
	
	if (!f.is_open())
		throw std::runtime_error("Cannot open load file");

	while (1) {
		getline(f, line);
		std::vector<std::string> line_vec;
		boost::split(line_vec, line, boost::is_any_of(" "));
		if (line_vec.size() < 2) {
			if (f.eof())
				break;
			continue;
		}
		/* Parse the IP address of the IPBlock */
		uint32_t ipIn = (uint32_t)atoi(line_vec[0].c_str());
		uint32_t ipFin = (uint32_t)atoi(line_vec[1].c_str());
		IPBlock *ipb = new IPBlock(ipIn, ipFin);

		/* Parse the clusters key of the IPblock */
		std::string clusters = line_vec[2];
		std::vector<std::string> clusters_vec;
		boost::split(clusters_vec, clusters, boost::is_any_of(";"));
		
		for (unsigned int i = 0; i < clusters_vec.size() - 1; i++) {
			std::string keyDom = clusters_vec.at(i);
			bool isCollapsed = false;
			if (keyDom.at(0) == '*') {
				isCollapsed = true;
				keyDom = keyDom.substr(1, keyDom.size());
			}
			//if (keyDom.at(0) == '.')
			//	std::cout << keyDom << "\n";
			DomainStr *ckDname = m_factory->makeDomainStr(&keyDom);
			ipb->addCluster(ckDname, m_maxNumClusters, isCollapsed);
		}
				/* Check if also the domains have been exported */
			#if 0
			} else {
				std::vector<std::string> keyDom_vec;
				boost::split(keyDom_vec, keyDom, boost::is_any_of(":"));
				/* If the domains have not been exported */
				if (keyDom_vec.size() <= 1) {
					DomainStr *ckDname = m_factory->makeDomainStr(&clusters_vec.at(i));
					ipb->addCluster(ckDname, m_maxNumClusters, false);
				} else {
					std::string key = keyDom_vec[0];
					std::string domains = keyDom_vec[1];
					std::vector<std::string> domains_vec;
					boost::split(domains_vec, domains, boost::is_any_of(","));
					DomainStr *ckDname = m_factory->makeDomainStr(&clusters_vec.at(i));
					ipb->addCluster(ckDname, m_maxNumClusters, false);
					for (unsigned int i = 0; i < domains_vec.size(); i++) {
						DomainStr *dom = m_factory->makeDomainStr(&domains_vec.at(i));
						dom->addIPBlock(ipb);
						ipb->addToCluster(dom, ckDname, m_maxClusterSize);
					}
				}
			}
		#endif
		insertIPBlock(ipb, NULL);

		if (f.eof())
			break;
	}
	f.close();
}

void DNSMap::dumpt(std::string prefix, uint32_t c_time)
{
	std::wfstream f;
	std::string dumpFile = prefix;

	if (c_time) {
		std::ostringstream convert;
		convert << c_time;
		dumpFile += convert.str();
		dumpFile += ".txt";
	} else
		dumpFile += "final.txt"; 

	std::locale mylocale("");
	f.open(dumpFile, std::fstream::out);
	if (!f.is_open())
		throw std::runtime_error("Cannot open dumpt file");
	/* Defined to itareate on m_forest */
	std::unordered_map<uint32_t, RBTree *>::iterator forIt;
	/* Defined to iterate on every tree in the forest */
	RBTree::iterator treeIt;
	for (forIt = m_forest.begin(); forIt != m_forest.end();
		forIt++) {
		for (treeIt = forIt->second->begin(); treeIt !=
		forIt->second->end(); treeIt++) {
			IPBlock *ipb = treeIt->second;
			//ipb->cluster();
			DomainClusterMap *clusters;
			clusters = ipb->getClusters();
			if (clusters->size()) {
				f.imbue(std::locale("C"));
				f << ipb->first() << L" ";
				f << ipb->last() << L" ";
				f.imbue(mylocale);
				DomainClusterMap::iterator it;
				#if 1
				std::vector<std::wstring> orderedString;
				for (it = clusters->begin(); it != clusters->end(); it++) {
					std::wstring toAdd;
					if (it->second->isCollapsed())
						toAdd = L"*";
					toAdd += it->first->getString();
					orderedString.push_back(toAdd);
				
				}

				std::sort(orderedString.begin(), orderedString.end());
				for (unsigned int i = 0; i < orderedString.size(); i++)
					f << orderedString[i] << L";";
				#else
				it = clusters->begin();
				if (it->second->isCollapsed())
					f << L"*";
				f << *it->first;
				it++;
				while (it != clusters->end()) {
					f << L";";
					if (it->second->isCollapsed())
						f << L"*";
					f << *it->first;
					it++;
				}
				#endif
				f << "\n";	
				f.flush();
			}
		}
	}
	f.close();
}

DNSMap::DNSMap(std::string *tldNames, int netmask, int maxClusterSize, 
	int maxNumClusters, float clusteringThreshold, float domainCountThreshold)
{
	m_factory = new DomainStrFactory(tldNames);
	assert(netmask <= 32 && netmask >= 0);

	m_maxClusterSize = maxClusterSize;
	m_maxNumClusters = maxNumClusters;
	m_clusteringThreshold = clusteringThreshold;
	m_domainCountThreshold = domainCountThreshold;

	m_netmask = netmask;
	m_doOutputSuspicious = false;
}

DNSMap::~DNSMap()
{
	delete m_factory;
	m_suspiciousFile.flush();
	m_suspiciousFile.close();
	std::unordered_map<uint32_t, RBTree *>::iterator it;
	for (it = m_forest.begin(); it != m_forest.end(); it++)
		delete it->second;
}

std::string DNSMap::setSuspiciousFile(std::string prefix, uint32_t timestamp)
{
	std::string fileName = prefix;
	std::ostringstream convert;
	convert << timestamp;
	fileName += convert.str();
	fileName += ".txt";

	if (m_suspiciousFile.is_open()) {
		m_suspiciousFile.flush();
		m_suspiciousFile.close();
	}
	
	m_suspiciousFile.open(fileName);
	
	if (!m_suspiciousFile.is_open())
		throw std::runtime_error("Cannot open Suspicious file");

	return fileName;
}

void DNSMap::setDoOutputSuspicious()
{
	m_doOutputSuspicious = true;
}

bool DNSMap::getDoOutputSuspicious()
{
	return m_doOutputSuspicious;
}

RBTree* DNSMap::createTree(uint32_t ind)
{
	RBTree *rbt = new RBTree;
	m_forest.insert(std::pair<uint32_t, RBTree *>(ind, rbt));
	return rbt;
}

RBTree* DNSMap::findTree(uint32_t ipAddr)
{
	uint32_t ipIdx = ipAddr >> (32 - m_netmask);

	std::unordered_map<uint32_t, RBTree *>::iterator it;
	it = m_forest.find(ipIdx);
	if (it != m_forest.end())
		return it->second;
	else
		return createTree(ipIdx);
}

bool DNSMap::insertIPBlock(IPBlock *ipb, RBTree *iptree)
{
	RBTree *tree;
	if (iptree == NULL)
		tree = findTree(ipb->first());
	else
		tree = iptree;
	
	bool it = (tree->insert(std::pair
		<uint32_t, IPBlock *>(ipb->first(), ipb))).second;
	
	return it;//const_cast<IPBlock *>(it->second);
}

void DNSMap::removeIPBlockFromTree(IPBlock *ipb, RBTree *tree)
{
	assert(ipb && tree);
	
	tree->erase(ipb->first());
	delete ipb;
}

void DNSMap::extractStatistics()
{

	int ipCnt = 0; 
	int ipbCnt = 0;
	int collapsedClusterCnt = 0; 
	int domainCnt = 0;
	int preferCnameCnt = 0;
	float clustersIPBlockAvg = 0; 
	float clustersIPBlockStd = 0;
	std::unordered_map<uint32_t, RBTree *>::iterator outIt;
	RBTree::iterator inIt;

	domainCnt = m_factory->getNumDomains();

	for (outIt = m_forest.begin(); outIt != m_forest.end(); outIt++) {
		for (inIt = outIt->second->begin(); inIt != outIt->second->end();
			inIt++) {
			ipCnt += inIt->second->len();			
			ipbCnt++;
			DomainClusterMap collClusters = inIt->second->getCollapsedClusters();
			DomainClusterMap  *clusters = inIt->second->getClusters();
			collapsedClusterCnt +=collClusters.size();
			clustersIPBlockAvg += clusters->size();
			if (inIt->second->m_preferCname == true)
				preferCnameCnt++;
		}
	}

	clustersIPBlockAvg /= ipbCnt; 

	for (outIt = m_forest.begin(); outIt != m_forest.end(); outIt++) {
		for (inIt = outIt->second->begin(); inIt != outIt->second->end();
			inIt++) {
			DomainClusterMap  *clusters = inIt->second->getClusters();
			float diff = clusters->size() - clustersIPBlockAvg;
			clustersIPBlockStd += diff * diff;
		}
	}

	clustersIPBlockStd /= ipbCnt; 

	std::cerr << "IPs/IPBlocks: " << ipCnt << "/" << ipbCnt << "\n"; 
	std::cerr << "domains: " << domainCnt << "\n";
	std::cerr << "Clusters per IPBlock avg: " << clustersIPBlockAvg << "\n"; 
	std::cerr << "Clusters per IPBlock std: " << sqrt(clustersIPBlockStd) << "\n"; 
	std::cerr << "Collapsed clusters: " << collapsedClusterCnt << "\n";
	std::cerr << "Blocks Preferring CNAMEs: " << preferCnameCnt << "\n";

	return;
}

int DNSMap::removeEmptyIPBlocks()
{
	 /* Removes all IPBlocks that with empty <domains> set.  NOTE: this should
	  * be used only at the end of a time bin, as only then the IPBlocks'
	  * <domains> set is properly filled. Remember that we empty <domains> at
	  * every begin of a new time bin!  returns the number of deleted IPBlocks
	  */
	 std::unordered_map<IPBlock *, RBTree *> nodesToDelete;
	 /* Defined to itareate on m_forest */
	 std::unordered_map<uint32_t, RBTree *>::iterator forIt;
	 /* Defined to iterate on every tree in the forest */
	 RBTree::iterator treeIt;
	 for (forIt = m_forest.begin(); forIt != m_forest.end();
	 	forIt++) {
		for (treeIt = forIt->second->begin(); treeIt !=
		forIt->second->end(); treeIt++) {
			IPBlock *ipb = treeIt->second;
			if (ipb->getNumDomains() == 0)
				/* This block does not contain any domains ad can
				 * therefore be delated. */
				nodesToDelete.insert(std::pair<IPBlock *, RBTree *>
					(ipb, forIt->second));

		}
	}
	/* We can not delete from the tree while iterating over it, therefore
	 * we do the deletions here.
	 */
	 std::unordered_map<IPBlock *, RBTree *>::iterator it;
	 for (it = nodesToDelete.begin(); it != nodesToDelete.end(); it++) {
		RBTree *tree = it->second;
		IPBlock *ipb = it->first;
		tree->erase(ipb->first());
		delete ipb;
	}

	return nodesToDelete.size();
}

int DNSMap::removeDomainsFromAllIPBlocks()
{
	/* Remove all the domains that are no more used by any blocks. */
	int removed = m_factory->flushEmptyDomains();	
	/* Defined to itareate on m_forest */
	std::unordered_map<uint32_t, RBTree *>::iterator forIt;
	/* Defined to iterate on every tree in the forest */
	RBTree::iterator treeIt;
	for (forIt = m_forest.begin(); forIt != m_forest.end();
		forIt++) {
		for (treeIt = forIt->second->begin(); treeIt !=
			forIt->second->end(); treeIt++) {
			IPBlock *ipb = treeIt->second;
			ipb->reinitializeClusters(m_maxClusterSize, m_maxNumClusters);
			ipb->setIPsInactive();
		}
	}
	return removed;
}

void DNSMap::reclusterAllBlocks()
{
	/* Defined to itareate on m_forest */
	std::unordered_map<uint32_t, RBTree *>::iterator forIt;
	for (forIt = m_forest.begin(); forIt != m_forest.end();
		forIt++) {
		RBTree *tree = forIt->second;
		RBTree::iterator it;
		for (it = tree->begin(); it != tree->end(); it++)
			it->second->cluster(m_maxClusterSize, m_maxNumClusters,
				m_clusteringThreshold);
	}
}

int DNSMap::mergeAllBlocks()
{
	int numBlockMergeCnt = 0;
	m_recentlyMergedBlocks.clear();
	/* Defined to itareate on m_forest */
	std::unordered_map<uint32_t, RBTree *>::iterator forIt;
	for (forIt = m_forest.begin(); forIt != m_forest.end();
		forIt++) {
		RBTree *tree = forIt->second;
		/* We have to check for the case in which this tree is now empty,
		 * otherwise the next function would crash */
		if (!tree->size())
			continue;
		IPBlock *node = tree->begin()->second;
		IPBlock *next = nextNode(node, tree);
		while (next) {
			if (mergeConditionMet(node, next)) {
				mergeIPBlocks(node, next, tree);
				numBlockMergeCnt++;
				m_recentlyMergedBlocks.insert(node->first());
			} else
				node = next;
			next = nextNode(node, tree);
		}
	}
	return numBlockMergeCnt;
}

int DNSMap::splitAllBlocks()
{
	int numBlockSplitCnt = 0;
	/* Defined to itareate on m_forest */
	std::unordered_map<uint32_t, RBTree *>::iterator forIt;
	for (forIt = m_forest.begin(); forIt != m_forest.end();
		forIt++) {
		RBTree *tree = forIt->second;
		/* We have to check for the case in which this tree is now empty,
		 * otherwise the next function would crash */
		if (!tree->size())
			continue;
		IPBlock *node = tree->begin()->second;
		while (node) {
			if (node->len() > 1 &&
				m_recentlyMergedBlocks.find(node->first()) == m_recentlyMergedBlocks.end()) {
				/* Define blocks used to evaluate the split condition */
				IPBlock *ipb1, *ipb2;
				splitIPBlock(node, tree, &ipb1, &ipb2);
				
				/* From how we built them, the two blocks have to be neighbor
				 * for sure, otherwise we have a bug. */
				assert(ipb1->last() + 1 == ipb2->first());

				if (!mergeConditionMet(ipb1, ipb2)) {
					numBlockSplitCnt++;
                    /* Update the back-references in the DomainStr
                     * objects: remove references to the deleted block,
                     * and create reference to the new blocks.
					 */

					node->removeBackReferences();
					//node->removeBackReferences();
					ipb1->createBackReferences();
					ipb2->createBackReferences();
					/* Insert the new blocks and remove the old one. */
					removeIPBlockFromTree(node, tree);
					insertIPBlock(ipb1, tree);
					insertIPBlock(ipb2, tree);
					/* We continue with the block following the ones we just
					 * created by splitting <ipb>. That means that these new
					 * blocks will at earliest be further split in the next
					 * iteration of splitAndMerge.
					 */
					node = ipb2;
				} else {
					delete ipb1;
					delete ipb2;
				}
			}
			node = nextNode(node, tree);
		}
	}
	return numBlockSplitCnt;
}

void DNSMap::getNode(uint32_t ip, RBTree **tree, IPBlock **ipb)
{
	RBTree *iptree = findTree(ip);
	
	if (iptree->empty()) {
		*tree = iptree;
		*ipb = NULL;
		return;
	}

	RBTree::iterator blockIt = iptree->upper_bound(ip);
	/* Because we want the IPBlock in the tree that starts at an IP
	 * address that is closest to ip, and smaller that ip. */
	--blockIt;
	if (blockIt == iptree->end()) {
		*tree = iptree;
		*ipb = NULL;
		return;
	}

	IPBlock *containingIPBlock = const_cast<IPBlock *>(blockIt->second);
	
	if (ip >= containingIPBlock->first() && ip <=
		containingIPBlock->last()) {
		*tree = iptree;
		*ipb = containingIPBlock;
		return;
	} else {
		*tree = iptree;
		*ipb = NULL;
		return;		
	}
}

IPBlock* DNSMap::nextNode(IPBlock *ipb, RBTree *tree)
{
	RBTree::iterator it = tree->upper_bound(ipb->first());
	if (it != tree->end()) {
		IPBlock *right = const_cast<IPBlock *>(it->second);
		return right; 
	} else
		return NULL;
}

IPBlock* DNSMap::getRightNeighbor(IPBlock *ipb, RBTree *tree)
{
	RBTree::iterator it = tree->upper_bound(ipb->first());
	if (it != tree->end()) {
		IPBlock *right = const_cast<IPBlock *>(it->second);
		if (ipb->last() == right->first() - 1)
			return right; 
	}
	return NULL;
}

IPBlock* DNSMap::getLeftNeighbor(IPBlock *ipb, RBTree *tree)
{
	RBTree::iterator it = tree->lower_bound(ipb->first());
	it--;
	if (it != tree->end()) {
		IPBlock *left = const_cast<IPBlock *>(it->second);
		if (ipb->first() == left->last() + 1)
			return left; 
	}
	return NULL;
}

void DNSMap::mergeIPBlocks(IPBlock *master, IPBlock *slave, 
 	RBTree *tree)
{
	/* Find out which IPs in the new block were set to active in any of the
	 * clusters of the two old blocks. Then update the IP range of this to
	 * contain also the IPs of other. */
	std::vector<bool> newActiveIPs = master->getActiveIPs();
	std::vector<bool> slaveActiveIPs = slave->getActiveIPs();
	
	/* Merge the two vectors in order to create a new and bigger IPBlock.
     */
	for (unsigned int i = 0; i < slaveActiveIPs.size(); i++)
		newActiveIPs.push_back(slaveActiveIPs.at(i));

	/* Let's move all the clusters from the slave to the master. It is also
	 * needed to update the back references of every domains contained in the
	 * slave ipblock. */
	slave->removeBackReferences();

	DomainClusterMap *masterClusters = master->getClusters();
	DomainClusterMap::iterator it;
	for (it = masterClusters->begin(); it != masterClusters->end(); it++)
		it->second->m_activeIPs = newActiveIPs;

	master->updateRange(master->first(), slave->last());

	/* We increased the length of this block, so now we can have more clusters */
#if USE_PREFER_CNAME
	master->m_preferCname = false;
#endif

	/* At this point we can be sure that all the back references of the former
	 * domains of this block have been removed*/
	tree->erase(slave->first());
	/* In this way we eliminate the references to clusters and cluster centers,
	 * therefore the IPBlock destructor will not delete those elements. */
	//slave->removeClusters(true, true);
	delete slave;
}

IPBlock* DNSMap::createNewIPBlock(uint32_t firstIP, uint32_t lastIP,
	std::unordered_map<DomainStrSet *, std::vector<bool>>
	*domainsAndActiveIPs)
{
	IPBlock *newipb =  new IPBlock(firstIP, lastIP);
	std::unordered_map<DomainStrSet *, 
		std::vector<bool>>::iterator it;

	for (it = domainsAndActiveIPs->begin();
		it != domainsAndActiveIPs->end(); it++) {
		DomainStrSet *domains = it->first;
		std::vector<bool> *activeIPs = &it->second;
		DomainStrSet::iterator itDom;
		for (itDom = domains->begin(); itDom != domains->end();
			itDom++) {
			newipb->addDomain(*itDom, 0, NULL, false, m_maxClusterSize,
			m_maxNumClusters, m_clusteringThreshold);
			for (unsigned int i = 0; i < activeIPs->size(); i++) {
				if (activeIPs->at(i))
					newipb->hitDomainAndIP(*itDom, firstIP + i, false,
						m_maxClusterSize, m_clusteringThreshold);
			}
		}
	}
	newipb->cluster(m_maxClusterSize, m_maxNumClusters, m_clusteringThreshold);
	return newipb;
}

void DNSMap::splitIPBlock(IPBlock *ipb, RBTree *tree, IPBlock **ipb1, 
	IPBlock **ipb2)
{
	ipb->cluster(m_maxClusterSize, m_maxNumClusters, m_clusteringThreshold);
	int splitIndex = int((float)ipb->len()/2.0);
	std::unordered_map<DomainStrSet *,
		std::vector<bool>> domainsIpb1;
	std::unordered_map<DomainStrSet *,
		std::vector<bool>> domainsIpb2;

	DomainClusterMap::iterator it;
	for (it = ipb->getClusters()->begin(); 
		it != ipb->getClusters()->end(); it++) {
		DomainCluster *clust = it->second;
		
		bool isTrueActive1 = false;
		bool isTrueActive2 = false;

		std::vector<bool> activeIPsForIpb1;
		for (int i = 0; i < splitIndex; i++) {
			activeIPsForIpb1.push_back(clust->m_activeIPs.at(i));
			if (clust->m_activeIPs.at(i))
				isTrueActive1 = true;
		}

		std::vector<bool> activeIPsForIpb2;
		for (unsigned int i = splitIndex; i < clust->m_activeIPs.size(); i++) {
			activeIPsForIpb2.push_back(clust->m_activeIPs.at(i));
			if (clust->m_activeIPs.at(i))
				isTrueActive2 = true;
		}
		
		if (isTrueActive1)
			domainsIpb1.insert(std::pair<DomainStrSet *,
			std::vector<bool>>(clust->getDomains(), activeIPsForIpb1));
		
		if (isTrueActive2)
			domainsIpb2.insert(std::pair<DomainStrSet *,
			std::vector<bool>>(clust->getDomains(), activeIPsForIpb2));
	}
	
	//assert(domainsIpb1.size() || domainsIpb2.size());

	*ipb1 = createNewIPBlock(ipb->first(), ipb->first() + splitIndex - 1,
		&domainsIpb1);

	*ipb2 = createNewIPBlock(ipb->first() + splitIndex, ipb->last(),
		&domainsIpb2);
}

std::string DNSMap::getNetmask()
{
	return '/' + boost::lexical_cast<std::string>(m_netmask);
}

void DNSMap::writeSuspicious(uint32_t timestamp, std::string *dname, 
	uint32_t ip, uint32_t clientID, float minDist, float minDistNeighbor)
{
	DomainStr *d = m_factory->getDomainStr(dname);
	int numBlocks;
	if (d)
		numBlocks = d->m_ipblocks.size();
	else
		numBlocks = 0;
	m_suspiciousFile << timestamp << " ";
	m_suspiciousFile << *dname << " ";
	m_suspiciousFile << ip << " ";
	if (clientID == 0)
		m_suspiciousFile << "None ";
	else
		m_suspiciousFile << clientID << " ";
	m_suspiciousFile.precision(2);
	m_suspiciousFile << minDist << " ";
	m_suspiciousFile << numBlocks << " ";
	m_suspiciousFile << minDistNeighbor << "\n";
	m_suspiciousFile.flush();
}

bool DNSMap::add(uint32_t ip, std::string *qname, std::string *cname,
	uint32_t timestamp, int clientID)
{
	/* Get the DomainStr corresponding to the dname from the factory.
	 * This ensure that there's always exactly one object for an
	 * existing dname, no metter in how many IPBlocks this object
	 * appears. */
	if (qname->size() == 0 || cname->size() == 0 ||
		ip == 0 || timestamp == 0)
		return false;

	DomainStr *dom = m_factory->makeDomainStr(qname);
	RBTree *tree;
	IPBlock *containingIPBlock;
	getNode(ip, &tree, &containingIPBlock);
	
	if (containingIPBlock == NULL) {
		/* We could not find a block that contains <ip>, let's create a
		 * new one and insert it into the tree. */	
		IPBlock *newipb = new IPBlock(ip, ip);
		newipb->addDomain(dom, ip, NULL, true, m_maxClusterSize,
			m_maxNumClusters, m_clusteringThreshold);
		insertIPBlock(newipb, tree);
		
        // FIXME, testing
		if (m_doOutputSuspicious) {
            writeSuspicious(timestamp, qname, ip, clientID, 1.0, -1);
        }
	
		return false;
	}
	/* We found an existing block for this ip, let's try to add this
	 * mapping to the block. */

    /* Could be that this is an IP block belonging to a CDN. For these
     * there are many different domain names, which often share the same
     * canonical name. Note that in case there exists no CNAME in the
     * captured DNS response, the cname==dname
	 */
	
	//if (containingIPBlock->doPreferCname() && *qname != *cname)
	//	dom = m_factory->makeDomainStr(cname);

	float minDist;
	int addResultCode = containingIPBlock->addDomain(dom, ip, &minDist, 
		true, m_maxClusterSize, m_maxNumClusters, m_clusteringThreshold);

	#if 1 
	if (addResultCode == 2) {
		/* if 0 or 1 mean that we were able to integrate the mapping in the
		 * block without changing the clusters. Instead if 2 this means that we
		 * have a new cluster configuration, this is suspicious*/
		
		if (m_doOutputSuspicious && minDist > 0.0) {
			IPBlock *right = getRightNeighbor(containingIPBlock, tree);
			IPBlock *left = getLeftNeighbor(containingIPBlock, tree);
			
			float rightDist = 1.0;
			if (right)
				rightDist = right->checkDomain(dom, m_clusteringThreshold);
			
			float leftDist = 1.0;
			if (left)
				leftDist = left->checkDomain(dom, m_clusteringThreshold);
			
			float minDistNeighbor = rightDist < leftDist ? rightDist:leftDist;

			writeSuspicious(timestamp, qname, ip, clientID, minDist, minDistNeighbor);
			/*FIXME*/
			m_lastNumBlocks = dom->m_ipblocks.size();
			m_lastWeight = minDist;
			return true;
		}
	}
	#else

	if (m_doOutputSuspicious) {
		IPBlock *right = getRightNeighbor(containingIPBlock, tree);
		IPBlock *left = getLeftNeighbor(containingIPBlock, tree);
		
		float rightDist = 1.0;
		if (right)
			rightDist = right->checkDomain(dom, m_clusteringThreshold);
		
		float leftDist = 1.0;
		if (left)
			leftDist = left->checkDomain(dom, m_clusteringThreshold);
		
		float minDistNeighbor = rightDist < leftDist ? rightDist:leftDist;

		writeSuspicious(timestamp, qname, ip, clientID, minDist + addResultCode, minDistNeighbor);
		/*FIXME*/
		m_lastNumBlocks = dom->m_ipblocks.size();
		m_lastWeight = minDist;
		return true;
	}
	#endif

	return false;
}

int DNSMap::getNumberOfIPs()
{
	int cnt = 0;
	std::unordered_map<uint32_t, RBTree *>::iterator outIt;
	RBTree::iterator inIt;

	for (outIt = m_forest.begin(); outIt != m_forest.end(); outIt++) {
		for (inIt = outIt->second->begin(); inIt != outIt->second->end();
			inIt++) {
			cnt += inIt->second->len();
		}
	}
	return cnt;
}

void DNSMap::printTree(RBTree *tree, uint32_t ipIn, uint32_t ipFin)
{
	RBTree::iterator it;
	for (it = tree->begin(); it != tree->end(); it++) {
		uint32_t ip = it->second->first();
		if (ip >= ipIn && ip <= ipFin) {
			std::cout << it->first << " -> ";
			std::cout << it->second->first() << " ";
			std::cout << it->second->last() << "\n";
		}
	}
}

std::string ip_to_string(uint32_t ip)
{
    char addr_buffer[INET_ADDRSTRLEN];
    //inet_ntop expects network byte order
    uint32_t flipped_ip=htonl(ip);
    
    if(!inet_ntop(AF_INET, &flipped_ip, addr_buffer, INET_ADDRSTRLEN))
        throw std::runtime_error("cannot convert ip address");
    return std::string (addr_buffer);
}

std::string getAsnAndOrganization(uint32_t ip)
{
	char *as = GeoIP_name_by_addr(geodb_, ip_to_string(ip).c_str());
	if (as) {
		std::string asn(as);
		delete as;
		if (asn[0] == 'A' && asn[1] == 'S') {
			unsigned int first_space = asn.find(" ");
			if (first_space != asn.npos)
				return asn.substr(0, first_space);
		}
	}
	return "";
}

bool DNSMap::mergeMatch(std::multimap<int, DomainStr *> *x,
	std::multimap<int, DomainStr *> *y, int numDomains,
	std::unordered_map<size_t, float> *distances)
{
	int numMatchingDomains = 0;
	int domainsLeft = numDomains;
	std::multimap<int, DomainStr *>::reverse_iterator itx, ity;

	std::unordered_map<size_t, float>::iterator it;

	for (itx = x->rbegin(); itx != x->rend(); itx++) {
		/* The clusters are sorted according to the number of domains the
		 * contain, in decreasing order. if <v1> is empty, no other cluster
		 * will therefore contain anything, therefore we can break here.
		 */
		if (itx->first == 0)
			break;
		for (ity = y->rbegin(); ity != y->rend(); ity++) {
			DomainStr *keyx = itx->second;
			DomainStr *keyy = ity->second;
			it = distances->find((size_t)keyx + size_t(keyy));
			float dist;
			if (it == distances->end()) {
				dist = domainDist(keyx, keyy);
				distances->insert(std::pair<size_t, float>
					((size_t)keyx + size_t(keyy),dist));
			} else
				dist = it->second;
			if (dist <= m_clusteringThreshold) {
				numMatchingDomains += itx->first;
				break;
			}
		}

		assert(numMatchingDomains <= numDomains);
		
		/* At the end of every internal loop we check if we already found
		 * enough matches */
		if ((float)numMatchingDomains/(float)numDomains >= m_domainCountThreshold)
			return true;

		domainsLeft -= itx->first;
		/* If the number of remaining domains is too small to satisfy the
		 * condition above it does not make sense to keep searching. */
		
		if ((float)(numMatchingDomains + domainsLeft)/(float)numDomains <
			m_domainCountThreshold)
			return false;
	}
	return false;
}

bool DNSMap::mergeConditionMet(IPBlock *ipb1, IPBlock *ipb2)
{
	/* First of all the two blocks needs to be neighbor */
	if (ipb1->last() + 1 != ipb2->first())
		return false;

	/* if the blocks belong to different autonomous systems, we don't merge
	 * them.
     */
	if (ipb1->getAS() != ipb2->getAS())
        return false;
	
    /* For evaluating the merging condition, we need an up-to-date cluster
     * configuration. maybe we delayed that computation until here, so let's
     * check.
	 */

	ipb1->cluster(m_maxClusterSize, m_maxNumClusters, m_clusteringThreshold);
	ipb2->cluster(m_maxClusterSize, m_maxNumClusters, m_clusteringThreshold);
	
	int numDomainsIpb1 = ipb1->getNumDomains();
	int numDomainsIpb2 = ipb2->getNumDomains();

	if (!numDomainsIpb1 || !numDomainsIpb2)
		return false;

	/* Create a multimap <int, DomainStr>, where the key is the size of the
	 * cluster and the value is the key of the cluster. In this way we have a
	 * sorted structure that should speed up the following processing. */

	std::multimap<int, DomainStr *> orderedClusters1;
	DomainClusterMap::iterator iter1;
	DomainClusterMap *clusters1 = ipb1->getClusters();
	for (iter1 = clusters1->begin(); iter1 != clusters1->end(); iter1++) {
		orderedClusters1.insert(std::pair<int, DomainStr *>(iter1->second->len(),
			iter1->first));
	}


	std::multimap<int, DomainStr *> orderedClusters2;
	DomainClusterMap::iterator iter2;
	DomainClusterMap *clusters2 = ipb2->getClusters();
	for (iter2 = clusters2->begin(); iter2 != clusters1->end(); iter2++) {
		orderedClusters2.insert(std::pair<int, DomainStr *>(iter2->second->len(),
			iter2->first));
	}
	
    /* We cache the distances between the cluster centers here to avoid that we
     * have to recompute them again and again. */
	std::unordered_map<size_t, float> distances;

	bool doMerge = false;
	doMerge = mergeMatch(&orderedClusters1, &orderedClusters2, numDomainsIpb1, &distances);

	if (doMerge)
		doMerge = mergeMatch(&orderedClusters2, &orderedClusters1, numDomainsIpb2, &distances);

	return doMerge;

}

bool operator<(const IPBlock& m1, const IPBlock& m2)
{
	return m1.m_first < m2.m_first;
}

bool operator<=(const IPBlock& m1, const IPBlock& m2)
{
	return m1.m_first <= m2.m_first;
}

bool operator>(const IPBlock& m1, const IPBlock& m2)
{
	return m1.m_first > m2.m_first;
}

bool operator>=(const IPBlock& m1, const IPBlock& m2)
{
	return m1.m_first >= m2.m_first;
}

bool operator==(const IPBlock& m1, const IPBlock& m2)
{
	return m1.m_first == m2.m_first;
}

bool operator!=(const IPBlock& m1, const IPBlock& m2)
{
	return m1.m_first == m2.m_first;
}

std::wfstream& operator<<(std::wfstream& output, IPBlock& m)
{
	output << "IPBlock: " << m.m_first << "\n";
	output << "Dirty: " << m.m_dirtyClusters << "\n";
	output << "Range: " << m.m_first << " - " << m.m_last << "\n";
	output << "Domains:" << "\n";
	
	DomainStrSet::iterator its;
	DomainClusterMap::iterator itc;
	for (itc = m.m_clusters.begin(); itc != m.m_clusters.end(); itc++) {
		output << *(itc->first) << "\t";
		output << *(itc->second) << "\n";
	}
	output << "\n";
	return output;
}

std::wostream& operator<<(std::wostream& output, IPBlock& m)
{
	output << "IPBlock: " << m.m_first << "\n";
	output << "Dirty: " << m.m_dirtyClusters << "\n";
	output << "Range: " << m.m_first << " - " << m.m_last << "\n";
	output << "Domains:" << "\n";
	
	DomainStrSet::iterator its;
	DomainClusterMap::iterator itc;
	for (itc = m.m_clusters.begin(); itc != m.m_clusters.end(); itc++) {
		output << *(itc->first) << ": ";
		output << *(itc->second) << "\n";
	}
	output << "\n";
	return output;
}

std::wfstream& operator<<(std::wfstream& output, DNSMap& m)
{
	std::unordered_map<uint32_t, std::map<uint32_t, IPBlock *> *>::iterator outIt;
	std::map<uint32_t, IPBlock *>::iterator inIt;

	for (outIt = m.m_forest.begin(); outIt != m.m_forest.end(); outIt++) {
		output << "Tree: " << outIt->first << "\n";
		for (inIt = outIt->second->begin(); inIt !=
			outIt->second->end(); inIt++) {
			output << *inIt->second;
		}
	}
	return output;
}
