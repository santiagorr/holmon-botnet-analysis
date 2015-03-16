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

#include <ostream>
#include <cassert>
#include <boost/lexical_cast.hpp>
#include <map>
#include <GeoIP.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <set>
#include <unordered_map>
#include <stdexcept>

#include "DomainCluster.hpp"

#define WITH_SPLIT 1


#define USE_PREFER_CNAME 1

#if 0
extern int maxClusterSize_;
extern unsigned int maxNumClusters_;
extern float clusteringThreshold_;
extern float domainCountThreshold_;
#endif
extern GeoIP *geodb_;

class IPBlock;

typedef std::map<uint32_t, IPBlock *> RBTree; 

/* This class stores blocks of IP addresses, specified by a start and an end IP
 * address. Each block contains a list of domain names that are hosted on the
 * block's IP addresses. This class has the following attributes:
 *
 * first -> first ip address of the block; last -> last ip address of the
 * block; domains -> a set the contains all the DomainStr that belong to this
 * block, in case of collapsed cluster, the collapsed DomainStr are removed;
 * clusters -> contains a map of all the clusters belonging to this block,
 * every cluster is addressed by its cluster center; dirty -> a flag that says
 * if this block need to be reclustered because something might have been
 * changed regarding the cluster configuration .
 */
class IPBlock
{
	uint32_t m_first, m_last;
	std::string m_AS;
	DomainClusterMap m_clusters;
	bool m_dirtyClusters;
	
	/* Those are static variables since we expect that the value will be
	 * the same for all the instances of this class. */
	/*static int m_maxClusterSize;
	static unsigned int m_maxNumClusters;
	static float m_clusteringThreshold;
	static float m_domainCountThreshold;*/
	
	public:


#if USE_PREFER_CNAME
	bool m_preferCname;
#endif
	friend bool operator<(const IPBlock& m1, const IPBlock& m2);
	friend bool operator<=(const IPBlock& m1, const IPBlock& m2);
	friend bool operator>(const IPBlock& m1, const IPBlock& m2);
	friend bool operator>=(const IPBlock& m1, const IPBlock& m2);
	friend bool operator==(const IPBlock& m1, const IPBlock& m2);
	friend bool operator!=(const IPBlock& m1, const IPBlock& m2);
	friend std::wfstream& operator<<(std::wfstream& output, IPBlock& m);
	friend std::wostream& operator<<(std::wostream& output, IPBlock& m);
	
	/* Single constructor. Add one DomainStr to domains. */
	IPBlock(uint32_t first, uint32_t last);
	
	/* Class destructor. */
	~IPBlock();
	
	/* Returns true if this block contains a certain ip address. */
	bool contains(uint32_t ip);
	
	int getIPIndex(uint32_t ip);
	
	/* NOTE: COMMENT NOT UPDATED!  If <dname> is in self.domains, we just set
	 * the corresponding DomainStr object in self.domains to 'active'. Also, we
	 * set the <ip> in the this DomainStr's cluster to active.
	 * 
	 * If <dname> is not in self.domains, but is close enough to a collapsed
	 * cluster (i.e., not more than self.clusteringThreshold away), we do the
	 * same for the cluster, *without remembering* <dname>.
	 * 
	 * In any of the these two cases we return True. If <dname> was neither
	 * directly contained nor close enough to a collapsed cluster, we return
	 * False.
	 */
	bool hitDomainAndIP(DomainStr *dom, uint32_t ip, bool createBackRef,
		int maxClusterSize, float clusteringThreshold);

	/* Find the collapsed cluster with the minimum distance of the cluster
	 * center to <dname>. Returns a tuple (clusterKey, cluster) if this
	 * distance is also <= self.clusteringThreshold. Else returns None.
	 */
	DomainCluster* findBestCollapsedCluster(DomainStr *dom, float clusteringThreshold);

	/* Returns a tuple (clusterKey, DomainCluster) describing the cluster to
	 * which dom belongs. Return NULL if dom is in none of the clusters. */
	DomainCluster* getClusterForDomain(DomainStr *dom, float clusteringThreshold);

#if USE_PREFER_CNAME
	bool doPreferCname();
#endif

	bool lt(IPBlock *ipb);

	bool gt(IPBlock *ipb);

	uint32_t len();

	uint32_t first();

	uint32_t last();

	std::string getAS();

	/* Gives back all the clusters */
	DomainClusterMap* getClusters();
	
	/* Gives back all the collapsed clusters, if any*/
	DomainClusterMap getCollapsedClusters();

	/* Gives back all the domains contained in the clusters. NOTE: This
	 * function allocates memory with new, therefore the colling function
	 * should that delete this */
	std::vector<DomainStr *>* getDomainsInClusters();

	bool checkDoubleDomain(float clusteringThreshold);
	
	/* Gives back all the clusters keys */
	std::vector<DomainStr *> getKeysInClusters();

	/* Creates the back references for this block for all the domains contained
	 * in all the clusters*/
	void createBackReferences();

	/* Removes the back references for this block for all the domains contained
	 * in all the clusters*/
	int removeBackReferences();

	void removeClusters();

	/* This function sets a new ip range for this block, overwriting the old
	 * range. NOTE: this does not update the activeIPs field in this IPBlocks
	 * clusters! */
	void updateRange(uint32_t first, uint32_t last);

	int getNumDomains();
	
	/* Adds a new cluster containing only dom. The key identifying the cluster
	 * is identical to dom but, is a new DomainStr object that is not being
	 * saved in m_domains or any lookup indexes.*/
	DomainStr* addCluster(DomainStr *dom, int maxNumClusters, bool isCollapsed);

	/* Adds dom to the cluster identifyed by key. If this causes the cluster
	 * size to exceed maxClusterSize, the cluster gets collapsed. */
	void addToCluster(DomainStr *dom, DomainStr *key, int maxClusterSize);

	/* Add a single new domain to this block.
	 * returns: 
	 * 0: if dom is already contained in this block or dom is close to an
	 * existing collapsed cluster.
	 * 1: if dom could be added to an existing, not collapsed cluster.
	 * 2: if we had to create a new cluster for dom, or we had to recluster
	 * everything again. */
	int addDomain(DomainStr* dom, uint32_t ip, float *minDistRet,
		bool createBackRef, int maxClusterSize, int maxNumClusters, 
		float clusteringThreshold);

	float checkDomain(DomainStr* d, float clusteringThreshold);
	
	void setDomainsInactive();

	void reinitializeClusters(int maxClusterSize, int maxNumClusters);

	void setIPsInactive();

	/* Gives a vector containing in each position the logic or of all the
	 * acviveIPs vectors of all the cluster that belong to this IPBlock. */
	std::vector<bool> getActiveIPs();

	/* Overwrite the old clusters and compute fresh clusters for this IPBlock.
	 * This function can be called assuming that is already known which cluster
	 * to merge, in that case the activeIPs is provided, or, in case this is
	 * not, we need to discover which IPs are active.  */
	void doCluster(int maxClusterSize, int maxNumClusters,
		float clusteringThreshold);

	/* Computes clusters for self.domains, given that this is required because
	 * something changed.
	 */
	void cluster(int maxClusterSize, int maxNumClusters,
		float clusteringThreshold);
};

/* This class stores IPBlocks in a set of Red-Black-Trees. The idea is to split
 * the entire IP address range in a number of ranges depending on the netmask
 * of an IP address. this way the depth of the tree can be controlled, at the
 * price of spreading the information amongst several tree that don't
 * communicate with each other, and which might show some nasty effects at the
 * edges of their IP ranges (e.g., when a certain domain maps half to one tree,
 * and half to the neighboring one). This contains the attributes:
 *
 * netmask -> defines the mask to separate single RBTree;
 * forest -> a set containing all the instanciated RBTree;
 * facory -> a factory class to instanciate DomainStr objects;
 * doOutputSuspicious -> a boolean.
 */
class DNSMap
{
	int m_netmask;
	std::unordered_map<uint32_t, RBTree *> m_forest;
	DomainStrFactory *m_factory;
	bool m_doOutputSuspicious;
	std::ofstream m_suspiciousFile;
	/* Those are static variables since we expect that the value will be
	 * the same for all the instances of this class. */
	int m_maxClusterSize;
	unsigned int m_maxNumClusters;
	float m_clusteringThreshold;
	float m_domainCountThreshold;
	std::set<uint32_t> m_recentlyMergedBlocks;

	public:

	/* FIXME */
	int m_lastNumBlocks;
	float m_lastWeight;

	friend std::wfstream& operator<<(std::wfstream& output, DNSMap& m);
	
	/* Constructor. */
	DNSMap(std::string *tldNames, int netmask, int maxClusterSize, 
		int maxNumClusters, float clusteringThreshold, float domainCountThreshold);

	/* Destructor. */
	~DNSMap();
	
	std::string setSuspiciousFile(std::string prefix, uint32_t timestamp);

	void setDoOutputSuspicious();

	bool getDoOutputSuspicious();

	/* Create a new RBTree to be added to the forest. */
	RBTree* createTree(uint32_t ind);
	
	/* Find an RBTree in the forest, if already existing, or creates a new
	 * one. */
	RBTree* findTree(uint32_t ipAddr);
	
	/* Inserts an IPBlock in the tree specified by the first IP adress in
	 * ipb or in iptree if not NULL. */
	bool insertIPBlock(IPBlock *ipb, RBTree *iptree);
	
	/* Removes the node that holds ipb from the corresponding tree. */
	void removeIPBlockFromTree(IPBlock *ipb, RBTree *tree);

	void extractStatistics();

	void reclusterAllBlocks();

	/* Run over all DNSMap in the <iptree> and remove all domains from the
	 * block that are not marked 'active'. Blocks that then do not contain
	 * *any* domains anymore are deleted from <iptree>. All domains in all
	 * remaining blocks are set to 'not active', and are therefore deleted in
	 * the next iteration, unless they are set active again in the meanwhile.

	 * returns the number of deleted IPBlocks
	 */
	int removeEmptyIPBlocks();
	
	int removeDomainsFromAllIPBlocks();

	int mergeAllBlocks();
	int splitAllBlocks();
	/* Returns a tuple with the node that contains ip and the corresponding
	 * RBTree that contains this node. Returns (none, RBTree) if no such node
	 * exists. */
	void getNode(uint32_t ip, RBTree **tree, IPBlock **ipb);

	/* Finds the node next to an IPBlock. If this does not exist we return
	 * NULL. */	
	IPBlock* nextNode(IPBlock *ipb, RBTree *tree);

	/* Finds the direct right neighbor of an IPBlock. This is defined as:
	 * ipb.last + 1 == right_neighbor.first. If this does not exist we return
	 * NULL. */	
	IPBlock* getRightNeighbor(IPBlock *ipb, RBTree *tree);

	/* Finds the direct left neighbor of an IPBlock. This is defined as:
	 * ipb.first == left_neighbor.last + 1. If this does not exist we return
	 * NULL. */	
	IPBlock* getLeftNeighbor(IPBlock *ipb, RBTree *tree);
	
	/* Merges two IPBlocks if they are similar enough (see
	 * _mergeConditionMet()). As a result of this operation the contents of
	 * slaveIpb will be written to masterIpb, and slaveIpb will be delated.
	 * Note that the slave has to be a direct right neighbor of the master else
	 * merging will fail any case.*/
	 void mergeIPBlocks(IPBlock *master, IPBlock *slave, 
	 	RBTree *tree);

	IPBlock* createNewIPBlock(uint32_t firstIP, uint32_t lastIP,
		std::unordered_map<DomainStrSet *, std::vector<bool>>
		*domainsAndActiveIPs);

    /*Split <ipb> in two halves.
    * Note: this does neither delete <ipb> from the DNSMap nor insert the new
    * blocks in it. Also, it doesn't create back-references to the new blocks
    * in the containing domains <ipblocks> field. All of this has to be done
    * outside of this function in case it is decided that the new blocks
    * should be kept.
    * returns the two new IPBlocks.
	*/
	void splitIPBlock(IPBlock *ipb, RBTree *tree, IPBlock **ipb1,
		IPBlock **ipb2);
	
	std::string getNetmask();
			
	/* 1. consider also the difference of domain ranges, so that e.g.
     *    multiple domains from the same network are considered less
     *    suspicious than completely scattered IPs;
     * 2. use memoize for this function, often we query for the same domain
     *    names many times subsequently, when there is more than one IP
     * 3. create structure for suspicious domains: if a domain is;
     *    suspicious, and triggers again this function, we don't need to do all
     *    the checks here.
	 */
	void writeSuspicious(uint32_t timestamp, std::string *dname, 
		uint32_t ip, uint32_t clientID, float minDist, float minDistNeighbor);
	
	/* Adds a new IP address/domain name mapping to the tree. Four things
	 * can happen: 
	 * 1. There already is a block that contains the mapping -> nothing is
	 * 	  done.
	 * 2. The IP is contained in the block, but not the Dname -> the dname
	 *    is split to create a new block that contains all the previous domain
	 *    names plus dname, and only one IP (<ip>).
	 * 3. There is no match yet -> a new block is created.
	 * 4. The closest block is a right neighbor of the new block to be
	 *    created -> the closest block is extended to contain also the new IP
	 *    address.
	 * Return true if a new block is added, else return false. */
	bool add(uint32_t ip, std::string *qname, std::string *cname,
		uint32_t timestamp, int clientID = 0);
	
	bool mergeMatch(std::multimap<int, DomainStr *> *x,
		std::multimap<int, DomainStr *> *y, int numDomains,
		std::unordered_map<size_t, float> *distances);
		
	/* Tests if two IPBlocks <ipb1> and <ipb2> should be merged.  Note that
	 * this function is not optimized, since the cluster are not sorted before
	 * to be passed to the _match function.
	 */
	bool mergeConditionMet(IPBlock *ipb1, IPBlock *ipb2);

	int getNumberOfIPs();
		
	void initWithTopQueriedDomains(std::string fileName);

	void loadt(std::string fileName);

	void dumpt(std::string prefix, uint32_t c_time);

	void printTree(RBTree *tree, uint32_t ipIn, uint32_t ipFin);
};

std::string ip_to_string(uint32_t ip);

std::string getAsnAndOrganization(uint32_t ip);

//const char* getStringFromDomain(DomainStr *dom);

#if 0
bool splitConditionMet(IPBlock *ipb, float domainCountTh = 0.5);
#endif
