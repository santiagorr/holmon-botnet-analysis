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

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <boost/algorithm/string.hpp>
#include <set>
#include <idna.h>

class IPBlock;
class DomainStr;
class DomainCluster;
/* FIXME: in all the function I'm using vectors, those needs to become sets. */

/* This class stores domain names. Contains the following attributes:
 * m_tld -> top level domain; 
 * rSplitView -> split version of the domain name;
 * ipblocks -> set of IPBlock instances to which the domain belongs;
 * domainLevels -> number of level for this domain;
 * isActive -> boolean flag to indicate if this domain is active in the last 
 * period (mainly for memory flushing);
 * weight -> weight of this domain, usually it is 1;
 */

typedef std::set<DomainStr *> DomainStrSet;
typedef std::unordered_map<DomainStr *, DomainCluster *> DomainClusterMap;

class DomainStr
{
	public:
		std::vector<std::wstring> m_rSplitView;
		std::set<IPBlock *> m_ipblocks;
		int m_domainLevels;

		friend bool operator==(const DomainStr& m1, const DomainStr& m2);
		friend bool operator!=(const DomainStr& m1, const DomainStr& m2);
		friend std::wfstream& operator<<(std::wfstream& output, DomainStr& m);
		friend std::wostream& operator<<(std::wostream& output, DomainStr& m);
		
		/* This function removes points from a given string. */
		std::wstring removePoints(std::wstring str);

		/* This fuction extracts the tld from a string representing the dname,
		 * in case there is not a matching within the tldSet, it returns a
		 * void string: "" */
		std::wstring tldMatcher(std::wstring *dname,
			std::set<std::wstring> *tldSet);

		/* Constructor used by the DomainStrFactory class */
		DomainStr(std::string *idnaDname, std::set<std::wstring> *tldSet,
			bool getTLD = true);
				/* Contructor used to build the median. */
		DomainStr(std::vector<std::wstring> *dnameVec);
				
		/* Copy constructor. */
		DomainStr(DomainStr *dom);
		
		
		/* Void constructor. */
		DomainStr();
		
		void addIPBlock(IPBlock *ip);
				
		bool removeIPBlock(IPBlock *ip, bool warn = true);

		std::wstring getString();
};

/* Function to convert from punycode char array to wstring unicode type. */
std::wstring punycodeDecoder(std::string *encoded);	

/* Function to convert from string to wstring */
std::wstring stringToWstring(std::string *line);

bool operator==(const DomainStr& m1, const DomainStr& m2);

bool operator!=(const DomainStr& m1, const DomainStr& m2);

std::wfstream& operator<<(std::wfstream& output, DomainStr& m);

/* This class is responsible fro creating new DomainStr object from an input
 * line. In this way only real existing domains are stored inside this class,
 * while all the medians computed to address clusters are not stored here. */
class DomainStrFactory
{
	public:
	/* A set which contain all the dname already instanciated, in this way, if 
	 * we see an already seen domain, the class gives back a pointer and it will
	 * not create another object. */
	std::unordered_map<std::string, DomainStr *> m_domainDict;
	
	/* We need to load the set of TLD in order to be able to create new
	 * DomainStr object */
	std::set<std::wstring> m_tldSet;

	DomainStrFactory(std::string *tldNames);
		
	~DomainStrFactory();
	
	int getNumDomains();

	DomainStr* makeDomainStr(std::string *str);
		
	DomainStr* getDomainStr(std::string *str);

	int flushEmptyDomains();
};
/* This class store a cluster, this is a set of domains that are close enough.
 * This class contains the following attributes:
 * domains -> stores all the domains in this cluster. In case the cluster is
 * collapsed this will store only the cluster center, the median of all the
 * previously contained domains;
 * activeIPs -> every cluster is mapped with an IPBlock, this says which of the 
 * ip addresses of the containing IPBlock are actually used by this cluster;
 * isCollapsed -> boolean to indicate if the cluster is collapsed.
 */
class DomainCluster
{
	public:
		DomainStrSet m_domains;
		std::vector<bool> m_activeIPs;
		bool m_isCollapsed;

		friend std::wfstream& operator<<(std::wfstream& output, DomainCluster& m);
		friend std::wostream& operator<<(std::wostream& output, DomainCluster& m);
		
		/* Plain constructor for collapsed clusters.*/
		DomainCluster(bool isCollapsed = false);

		/* Single constructor. Add a single DomainStr to the cluster.*/
		DomainCluster(DomainStr *domain, bool isCollapsed = false);

		/* Multiple constructor. Add multiple DomainStr to the cluster.*/
		DomainCluster(std::vector<DomainStr *> *domains,
			bool isCollapsed = false);
		
		bool domainIsPresent(DomainStr *dom);
		bool isCollapsed();
		
		DomainStrSet* getDomains();

		void setAllDomainsReference(IPBlock *ipb);
		
		int removeAllDomainsReference(IPBlock *ipb);
		
		/* Add a DomainStr to the cluster. */
		bool add(DomainStr *dom);
		
		/* Add multiple domains to the cluster. */
		void multiAdd(std::vector<DomainStr *> *domVec);

		void del(DomainStr *dom);
	
		void setIpActive(unsigned int ipIndex);

		void initActiveIPs(int numIPs);

		void setAllIPsInactive();

		int len();

		/* Computes the mean distance between elements in the given list of
		 * Domain objects (<domainObjs>). If the list contains more than
		 * <numSamples> objects, we pick <numSamples> random ones and compute
		 * the mean distance between them.
		 *
		 * returns the mean distance as float
		 */
		float clusterDispersion(unsigned int numSamples = 100);

};

std::wfstream& operator<<(std::wfstream& output, DomainCluster& m);

/* Compute the distance between two domains. The distance is computed from
 * three components:
 * 1. The average Levenshtein ratio between domain levels, weighted by the
 * relative length of that domain level. If one domain has
 * less levels than the other, we add additional Levenshtein ratios=1 for the
 * computation of the average.
 * 2. The relative number of domain levels. when both domains have the same
 * number of domain levels, the contribution of this is zero.
 * 3. The relative number of identical domain levels. when both domains are 
 * completely identical, the contribution of this is zero.
 */
float domainDist(DomainStr *d1, DomainStr *d2);

/* This function returns for a set of domain names in <data> a list of tuples
 * (domain-level, occurrences), where domain-level is the <i>-th domain level
 * of a domain (counted from the end, so the TLD is level one), and
 * occurrences is the total number of occurrences of this string at this level
 * across all domains in data. This also considers the weight of a domain,
 * e.g. a domain with weight=2 contributes to the number of occurrences with
 * two.

 * data -> a sector with domainStr;
 * level -> a positive integer
 */
std::unordered_map<std::wstring, int> getLD(std::vector<DomainStr *> *data,
	unsigned int lev);

#if 0
std::wstring string2wstring(std::string str);
std::string wstring2string(std::wstring str);
#endif

/*Compute the median Domain object from a list of Domain objects. The median
 * is defined as the string that is computed from the per-domain-level
 * Levenshtein string medians.

 * if <numSamples> is set to a value > 0, this number of samples will be
 * picked randomly from <domainObjs>, and the median is then computed from
 * this set.

 * returns a Domain object
 */
DomainStr* domainMedian(std::vector<DomainStr *> *data, unsigned int numSamples = 200);

/* Recursive function called by domainCluster. */
void recursiveClustering(DomainClusterMap *clusters,
	std::vector<DomainStr *> *domains, float th);

/* Clusters <domains> such that no domain has a distance more than
* <clusteringThreshold> to the cluster's center.
*
* 1. find median of domains + compute distances between all domains and the
* median
* 2. find all domains that have a distance to the median of less-equal-than
* <clusteringThreshold> -> this domains form a cluster now and are removed
* from all further processing
* 3. for all the others, continue from 1.
*
* NOTE: it might happen at step 2. that *no* domain is close enough to the
* median. In this case, we find two sets of domains with similar distances to
* the computed median using kmeans, and continue for each of them separately
* from 1. In case we cannot further cluster the domains by that procedure, we
* assign all remaining domain to separate clusters that contain only one
* domain each.
*
* domains: a list of <DomainStr> objects
* clusteringThreshold: a float between 0 and 1
*
* returns a dict with cluster centers as keys and WeakSets containing
* references to elements of <domains> as values
*/
DomainClusterMap domainCluster( std::vector<DomainStr *> *domains,
	float clusteringThreshold);

/* Computes the mean distance between elements in the given list of Domain
 * objects (<domainObjs>). If the list contains more than <numSamples>
 * objects, we pick <numSamples> random ones and compute the mean distance
 * between them.
 *
 * returns the mean distance as float
 */
float clusterDispersion(DomainStrSet *data, unsigned int numSamples = 100);
