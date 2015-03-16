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

#include "DomainCluster.hpp"
#include "toolfunctions.hpp"

std::wstring DomainStr::removePoints(std::wstring str)
{
	std::wstring::iterator it;
	for (it = str.begin(); it != str.end(); it++) {
		if (*it == '.')
			str.erase(it);
	}
	return str;
}

/* This fuction extracts the tld from a string representing the dname,
 * in case there is not a matching within the tldSet, it returns a
 * void string: "" */
std::wstring DomainStr::tldMatcher(std::wstring *dname,
	std::set<std::wstring> *tldSet)
{
	std::vector<std::wstring> chunks;
	boost::split(chunks, *dname, boost::is_any_of(L"."));
	
	std::wstring test = L""; 
	std::wstring startest = L"";
	std::wstring bestMatch = L"";
	
	while (chunks.size()) {
		test = chunks.back() + test;
		std::set<std::wstring>::iterator check; 
		check = tldSet->find(test);
		if (check != tldSet->end())
			bestMatch = test;
		else {
			check = tldSet->find(L"*" + startest);
			if (check != tldSet->end())
				bestMatch = test;
		}
		chunks.pop_back();
		test = L"." + test;
		startest = test;
	}
	
	return bestMatch;
}

std::wstring punycodeDecoder(std::string *encoded)
{
	char *decodedCharArray;

	idna_to_unicode_lzlz(encoded->c_str(), &decodedCharArray, 0);

	std::wstring decoded;
	char *charPtr = decodedCharArray; 
	while(*charPtr != '\0') {
		wchar_t pwc;
		char *pmb = charPtr;
		charPtr += mbtowc(&pwc, pmb, 10);
		decoded += pwc;
	}
	delete decodedCharArray;
	return decoded;
}

/* Constructor used by the DomainStrFactory class */
DomainStr::DomainStr(std::string *idnaDname, std::set<std::wstring> *tldSet,
	bool getTLD)
{
	std::vector<std::wstring> splitView;
	std::wstring tld;

	std::wstring dname = punycodeDecoder(idnaDname); 

	if (getTLD) {
		tld = tldMatcher(&dname, tldSet);
		if (tld != L"") {
			if (dname.length() > tld.length()) {
				std::wstring shortDomain =
					dname.substr(0, dname.length() - 1 - tld.length());

				boost::split(splitView, shortDomain,
					boost::is_any_of("."));
			}
			//splitView.push_back(removePoints(tld));
			splitView.push_back(tld);
		} else
			boost::split(splitView, dname, boost::is_any_of(L"."));	
	} else
		boost::split(splitView, dname, boost::is_any_of(L"."));
	
	std::vector<std::wstring>::reverse_iterator it;
	for (it = splitView.rbegin(); it != splitView.rend(); it++)
		m_rSplitView.push_back(*it);

	m_domainLevels = m_rSplitView.size();
}

/* Contructor used to build the median. */
DomainStr::DomainStr(std::vector<std::wstring> *dnameVec)
{
	//m_tld = "";
	for (unsigned int i = 0; i < dnameVec->size(); i++)
		m_rSplitView.push_back(dnameVec->at(i));
	m_domainLevels = m_rSplitView.size();
}

/* Copy constructor. */
DomainStr::DomainStr(DomainStr *dom)
{
	//m_tld = dom->m_tld;
	m_rSplitView = dom->m_rSplitView;
	m_ipblocks = dom->m_ipblocks;
	m_domainLevels = dom->m_domainLevels;
}

/* Void constructor. */
DomainStr::DomainStr()
{
}

void DomainStr::addIPBlock(IPBlock *ip)
{
	m_ipblocks.insert(ip);
}

bool DomainStr::removeIPBlock(IPBlock *ipb, bool warn)
{
	assert(ipb);
	if (m_ipblocks.erase(ipb))
		return true;
	else
		return false;
	#if 0	
	if (!res && warn) {
		std::cout << "WARNING: cannot remove IPBlock: ";
	}
	#endif
}

std::wstring DomainStr::getString()
{
	std::wstring res;
	if (m_rSplitView.size() > 1) {
		for (int j = m_rSplitView.size() - 1; j > 0; j--) {
			if (m_rSplitView.at(j) != L"") {
				res += m_rSplitView.at(j);
				res += L".";
			}
		}
		res += m_rSplitView.at(0);
	} else {
		res += L".";
		res += m_rSplitView.at(0);
	}

	return res;
}

bool operator==(const DomainStr& m1, const DomainStr& m2)
{
	return (m1.m_rSplitView == m2.m_rSplitView &&
			m1.m_domainLevels == m2.m_domainLevels);
}

bool operator!=(const DomainStr& m1, const DomainStr& m2)
{
	return !(m1 == m2);
}

std::wfstream& operator<<(std::wfstream& output, DomainStr& m)
{
	if (m.m_rSplitView.size() > 1) {
		for (int j = m.m_rSplitView.size() - 1; j > 0; j--) {
			if (m.m_rSplitView.at(j) != L"")
				 output << m.m_rSplitView.at(j) << L".";
		}
		output << m.m_rSplitView.at(0);
	} else
		output << L"." << m.m_rSplitView.at(0);
	return output;
}

std::wostream& operator<<(std::wostream& output, DomainStr& m)
{
	if (m.m_rSplitView.size() > 1) {
		for (int j = m.m_rSplitView.size() - 1; j > 0; j--) {
			if (m.m_rSplitView.at(j) != L"")
				 output << m.m_rSplitView.at(j) << L".";
		}
		output << m.m_rSplitView.at(0);
	} else
		output << "." << m.m_rSplitView.at(0);
	return output;
}

std::wstring stringToWstring(std::string *line)
{
	std::wstring decoded;
	const char *charPtr = line->c_str(); 
	while(*charPtr != '\0') {
		wchar_t pwc;
		const char *pmb = charPtr;
		charPtr += mbtowc(&pwc, pmb, 10);
		decoded += pwc;
	}
	return decoded;
}

DomainStrFactory::DomainStrFactory(std::string *tld_names)
{
	std::ifstream fin; 
	std::string line;
	/* Load TLD */
	fin.open(*tld_names);
	
	if (!fin)
		throw std::runtime_error("Cannot open the tld_names file");
	
    setlocale(LC_ALL, "");
	while (1) {
		getline(fin, line);
		if (!(line == "" || (line[0] == '/' && line[1] == '/'))) {
			std::wstring decoded = stringToWstring(&line);
			m_tldSet.insert(decoded);
		}
		if (fin.eof())
			break;
	}
	fin.close();
}

DomainStrFactory::~DomainStrFactory()
{
	std::unordered_map<std::string, DomainStr *>::iterator it;

	for (it = m_domainDict.begin(); it != m_domainDict.end(); it++) {
		delete it->second;
		m_domainDict.erase(it->first);
	}
}

int DomainStrFactory::getNumDomains()
{
	return m_domainDict.size();
}

DomainStr* DomainStrFactory::makeDomainStr(std::string *str)
{
	DomainStr *result;
	std::unordered_map<std::string, DomainStr *>::iterator it;

	it = m_domainDict.find(*str);
	if (it == m_domainDict.end()) {
		/* Element not found, the object has to be created*/
		result = new DomainStr(str, &m_tldSet);
		m_domainDict.insert(std::pair<std::string, DomainStr *>
			(*str, result));
	} else {
		/* The element already exist, the object does not need to be 
		 * created. */
		result = it->second;
	}
	return result;
}

DomainStr* DomainStrFactory::getDomainStr(std::string *str)
{
	DomainStr *result = NULL;
	std::unordered_map<std::string, DomainStr *>::iterator it;
	it = m_domainDict.find(*str);
	if (it != m_domainDict.end())
		result = it->second;
	return result;
}

int DomainStrFactory::flushEmptyDomains()
{
	std::vector<std::unordered_map<std::string, DomainStr *>::iterator> empty;
	std::unordered_map<std::string, DomainStr *>::iterator it;
	for (it = m_domainDict.begin(); it != m_domainDict.end(); it++) {
		if (!it->second->m_ipblocks.size())
			empty.push_back(it);
	}
	
	for (unsigned int i = 0; i < empty.size(); i++) {
		delete empty.at(i)->second;
		m_domainDict.erase(empty.at(i));
	}

	return empty.size();
}

std::wfstream& operator<<(std::wfstream& output, DomainCluster& m)
{
	DomainStrSet::iterator domains;
	for (domains = m.m_domains.begin(); domains != m.m_domains.end(); domains++) {
		output << **domains;
		output << L";";
	}

	return output;
}

std::wostream& operator<<(std::wostream& output, DomainCluster& m)
{
	DomainStrSet::iterator domains;
	for (domains = m.m_domains.begin(); domains != m.m_domains.end(); domains++) {
		output << **domains;
		output << L";";
	}

	return output;
}

DomainCluster::DomainCluster(bool isCollapsed)
{
	m_isCollapsed = isCollapsed;
}

DomainCluster::DomainCluster(DomainStr *domain, bool isCollapsed)
{
	m_domains.insert(domain);
	m_isCollapsed = isCollapsed;
}

DomainCluster::DomainCluster(std::vector<DomainStr *> *domains,
	bool isCollapsed)
{
	for (unsigned int i = 0; i < domains->size(); i++)
		m_domains.insert(domains->at(i));
	m_isCollapsed = isCollapsed;
}

bool DomainCluster::isCollapsed()
{
	return m_isCollapsed;
}

bool DomainCluster::domainIsPresent(DomainStr *dom)
{
	DomainStrSet::iterator test;
	test = m_domains.find(dom);
	return (test != m_domains.end());
}

DomainStrSet* DomainCluster::getDomains()
{
	return &m_domains;
}

void DomainCluster::setAllDomainsReference(IPBlock *ipb)
{
	DomainStrSet::iterator it;
	for (it = m_domains.begin(); it != m_domains.end(); it++)
		(*it)->addIPBlock(ipb);
}

int DomainCluster::removeAllDomainsReference(IPBlock *ipb)
{
	DomainStrSet::iterator it;
	int res = 0;
	for (it = m_domains.begin(); it != m_domains.end(); it++) {
		if(!(*it)->removeIPBlock(ipb))
			res++;
	}
	return res;
}

bool DomainCluster::add(DomainStr *dom)
{
	std::pair<DomainStrSet::iterator, bool> res;
	res = m_domains.insert(dom);
	return res.second;
}

void DomainCluster::multiAdd(std::vector<DomainStr *> *domVec)
{
	for (unsigned int i = 0; i < domVec->size(); i++)
		this->add(domVec->at(i));
}

void DomainCluster::del(DomainStr *dom)
{
	int res = m_domains.erase(dom);
	if (!res)
		std::cout << "WARNING: cannot remove DomainStr from Cluster.\n";
}

void DomainCluster::setIpActive(unsigned int ipIndex)
{
	if (m_activeIPs.size() > ipIndex)
		m_activeIPs.at(ipIndex) = true;
	else
		std::cout << "WARNING: Cluster does not contain IP index.\n";
}

void DomainCluster::initActiveIPs(int numIPs)
{
	m_activeIPs.assign(numIPs, false);
}

void DomainCluster::setAllIPsInactive()
{
	m_activeIPs.assign(m_activeIPs.size(), false);
}

int DomainCluster::len()
{
	return m_domains.size();	
}

float DomainCluster::clusterDispersion(unsigned int numSamples)
{
	DomainStrSet *domVec;
	if (numSamples && m_domains.size() > numSamples) {
		domVec = new DomainStrSet;
		while (domVec->size() != numSamples) {
			int i = rand() % m_domains.size();
			DomainStrSet::iterator it = m_domains.begin();
			std::advance(it, i);
			domVec->insert(*it);
		}
	} else
		domVec = &m_domains;
	
	if (domVec->size() == 1)
		return 0.0;
	
	float distSum = 0;
	int distCnt = 0;
	
	DomainStrSet::iterator i, j;

	for (i = domVec->begin(); i != domVec->end(); i++) {
		for (j = domVec->begin(); j != domVec->end(); j++) {
			if (*i != *j) {
				distCnt++;
				distSum += domainDist(*i, *j);
			}
		}
	}
	if (distCnt)
		return distSum / distCnt;
	else
		return -1;
}

float domainDist(DomainStr *d1, DomainStr *d2)
{
	std::vector<std::wstring> *sx = &d1->m_rSplitView;
	std::vector<std::wstring> *sy = &d2->m_rSplitView;
	
	if (*d1 == *d2)
		return 0.0;

	int minDlev, maxDlev, ind;
	
	int lx = d1->m_domainLevels;
	int ly = d2->m_domainLevels;
	if (lx > ly) {
		maxDlev = lx;
		minDlev = ly;
	} else {
		maxDlev = ly;
		minDlev = lx;
	}
	
	float dist = 0;
	/* TotalWeight will contain the sum of the longest domain levels of the two
	 * domains. Example:
	 * d1 = "a.bbb.c";
	 * d2 = "aa.b.c";
	 * totWeight=(len('aa')+len('bbb')+len('cc')=7
	 */
	float totWeight = 0;
	/* We consider the ratio of identical domain levels for the distance.
     * the weight of each identical domain level is computed as
     * 1/(offset+domainLevel), where domainLevel=0 is the top level domain. I.e.,
     * the less significant a domain level is, the less weight it gets. <offset>
     * is used to control the decline rate of the weight from one level to the
     * next.
	 */
	float offset = 3.0;
	/* First compare all domain levels which exist in both domains, starting
	 * from the top-level-domain. */
	for (ind = 0; ind < minDlev; ind++) {
		float lWeight, pWeight, weight;
		
		std::wstring *curSx = &sx->at(ind); 
		std::wstring *curSy = &sy->at(ind);
		
		if (curSx->size() > curSy->size())
			lWeight = curSx->size();
		else
			lWeight = curSy->size();
		
		if (ind == 0 || ind == 1)
			pWeight = 1/offset;
		else
			pWeight = 1/(offset + ind - 1);
		weight = lWeight * pWeight;
		
		if (*curSx != *curSy)
			dist += (1 - lev_u_ratio(curSx, curSy)) * weight;

		totWeight += weight;
	}

	/* Then we consider also the domain levels that exist only in one of the two
	 * domains. */
	if (lx != ly) {
		std::vector<std::wstring> *longer;
		if (lx > ly)
			longer = sx;
		else
			longer = sy;

		for (int ind = minDlev; ind < maxDlev; ind++) {
			float lWeight, pWeight, weight;
			lWeight = longer->at(ind).length();
			pWeight = 1/(offset + ind);
			weight = lWeight * pWeight;
			dist += weight;
			totWeight += weight;
		}
	}
	
	if (!totWeight)
		std::cout << "ERROR: totWeight is zero\n.";
	return dist/totWeight;
}

std::unordered_map<std::wstring, int> getLD(std::vector<DomainStr *> *data,
	unsigned int lev)
{
	std::unordered_map<std::wstring, int> domainLevels;

	/* Iterate over data to extract level information */
	std::vector<DomainStr *>::iterator it;
	for (it = data->begin(); it != data->end(); it++) {
		/* The key is the level, if present, or an empty string. */
		std::wstring key;
		if ((*it)->m_rSplitView.size() > lev)
			key = (*it)->m_rSplitView.at(lev);
		else
			key = L"";
		/* Search for the key and increment or introduce a new value. */
		std::unordered_map<std::wstring, int>::iterator iti;
		iti = domainLevels.find(key);
		if (iti != domainLevels.end())
			iti->second++;
		else
			domainLevels.insert(std::pair<std::wstring, int>(key, 1));
		}			
	return domainLevels;
}

DomainStr* domainMedian(std::vector<DomainStr *> *data, unsigned int numSamples)
{
	std::vector<DomainStr *> domVec;
	if (numSamples && data->size() > numSamples) {
		std::set<int> indSet;
		while (indSet.size() != numSamples) {
			int i = rand() % data->size();
			indSet.insert(i);
		}
		std::set<int>::iterator it;
		for (it = indSet.begin(); it != indSet.end(); it++)
			domVec.push_back(data->at(*it));
	} else
		domVec = *data;
	
	unsigned int indMax = 0;
	std::vector<DomainStr *>::iterator it;
	for (it = domVec.begin(); it != domVec.end(); it++) {
		if ((*it)->m_rSplitView.size() > indMax)
			indMax = (*it)->m_rSplitView.size();
	}

	std::vector<std::wstring> medianVec;
	for (unsigned int i = 0; i < indMax; i++) {
		std::unordered_map<std::wstring, int> occWithWeights =
			getLD(&domVec, i);
		std::unordered_map<std::wstring, int>::iterator it;
		std::vector<std::wstring> domainLevels;
		std::vector<int> levelWeights;
		for (it = occWithWeights.begin(); it != occWithWeights.end();
			it++) {
			domainLevels.push_back(it->first);
			levelWeights.push_back(it->second);
		}
		/* Initialize the length. */
		size_t ldLength = 0;
		lev_wchar *ldMedian =
			lev_median(&domainLevels, &levelWeights, &ldLength);
		if (ldLength) {
			std::wstring median(ldMedian, ldLength);
			medianVec.push_back(median);
		}
		free(ldMedian);
	}
	/* We construct the final median now directly from the constructed parts, i.e.
	 * we don't let the DomainStr constructor split it in parts which might be
	 * different from the parts we found here, and would therefore impair the
	 * alignment for comparisons later.
	 */
	DomainStr* ret = new DomainStr(&medianVec);
	return ret;
}

void recursiveClustering(DomainClusterMap *clusters,
	std::vector<DomainStr *> *domains, float th)
{
	if (domains->size() == 0)
		return;
	if (domains->size() == 1) {
		DomainCluster *ptrc = new DomainCluster(domains->at(0));
		clusters->insert(std::pair<DomainStr *, DomainCluster *>
			(new DomainStr(domains->at(0)), ptrc));
		return;
	}

	DomainStr *clusterCenter = domainMedian(domains, 0);
	std::vector<DomainStr *> good, bad;
	std::vector<float> badDist;
	
	for(unsigned int i = 0; i < domains->size(); i++) {
		float dist = domainDist(domains->at(i), clusterCenter);
		if (dist <= th)
			good.push_back(domains->at(i));
		else {
			bad.push_back(domains->at(i));
			badDist.push_back(dist);
		}
	}
	
	/* At this point there are 4 possible situation: */
	if (good.size()) {
		if (bad.size()) {
			/* There are good clustered domains but there are also bad
			 * clustered domains, therefore we need to go on with the
			 * clustering. In this case we also need to delete the prevoiusly
			 * computed clusterCenter since we are not going to use it
			 * anywhere. */
			delete clusterCenter;
			recursiveClustering(clusters, &good, th);
			recursiveClustering(clusters, &bad, th);
		} else {
			/* All the domains are good clustered, therefore we can insert the
			 * new cluster, we do not need to recompute the clusterCenter,
			 * since we already computed it before. */
			DomainCluster *ptrc = new DomainCluster(&good);
			clusters->insert(std::pair<DomainStr *, DomainCluster *>
				(clusterCenter, ptrc));
		}
	} else {
		/* None of the domains is good clustered, we need to find a new
		 * configuration, to do that we use the k_means function to tra to
		 * separate the domains into separate clusters. */
		std::set<int> badInd1, badInd2;
		k_means(&badDist, &badInd1, &badInd2);
		if (badInd1.size() == 0 || badInd2.size() == 0) {
			/* This was pointless, it is impossible to split this set of
			 * domains into different clusters, therefore we will assign a
			 * separate clusters for each domain. */
			for (unsigned int i = 0; i < bad.size(); i++) {
				DomainCluster *ptrc = new DomainCluster(bad.at(i));
				clusters->insert(std::pair<DomainStr *, DomainCluster *>
					(new DomainStr(bad.at(i)), ptrc));
			}
		} else {
			/* This was useful, now we can go on further with clustering. */
			std::vector<DomainStr *> bad1, bad2;
			std::set<int>::iterator it;
			for (it = badInd1.begin(); it != badInd1.end(); it++)
				bad1.push_back(bad.at(*it));
			for (it = badInd2.begin(); it != badInd2.end(); it++)
				bad2.push_back(bad.at(*it));
			
			recursiveClustering(clusters, &bad1, th);
			recursiveClustering(clusters, &bad2, th);
		}
	}
}

DomainClusterMap domainCluster(std::vector<DomainStr *> *domains,
	float clusteringThreshold)
{
	DomainClusterMap result;
	recursiveClustering(&result, domains, clusteringThreshold);
	return result;
}
