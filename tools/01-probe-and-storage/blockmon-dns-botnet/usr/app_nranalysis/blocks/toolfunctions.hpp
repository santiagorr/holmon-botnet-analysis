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

#include <string>
#include <vector>
#include <set>
#include <wchar.h>

#define LEV_INFINITY 1e100

typedef char lev_byte;

typedef wchar_t lev_wchar;

/* used internally in make_usymlist */
typedef struct _HItem HItem;
struct _HItem {
  lev_wchar c;
  HItem *n;
};

/**
 * lev_edit_distance:
 * @len1: The length of @string1.
 * @string1: A sequence of bytes of length @len1, may contain NUL characters.
 * @len2: The length of @string2.
 * @string2: A sequence of bytes of length @len2, may contain NUL characters.
 * @xcost: If nonzero, the replace operation has weight 2, otherwise all
 *         edit operations have equal weights of 1.
 *
 * Computes Levenshtein edit distance of two strings.
 *
 * Returns: The edit distance.
 **/
size_t lev_distance(size_t len1, const lev_byte *string1,
	size_t len2, const lev_byte *string2, int xcost);

size_t lev_u_distance(size_t len1, const lev_wchar *string1, size_t len2,
	const lev_wchar *string2, int xcost);

/* Imported from Levenshtein.c (Python library)*/
float lev_ratio(std::string *s1, std::string *s2);

/* Imported from Levenshtein.c (Python library)*/
float lev_u_ratio(std::wstring *s1, std::wstring *s2);

/* free usmylist hash this is a separate function because we need it in more
 * than one place */
void free_usymlist_hash(HItem *symmap);

/* compute the sets of symbols each string contains, and the set of symbols
 * in any of them (symset).  meanwhile, count how many different symbols
 * there are (used below for symlist). */
lev_wchar* make_usymlist(std::vector<std::wstring> *strings, size_t *symlistlen);

/**
 * lev_u_greedy_median:
 * @n: The size of @lengths, @strings, and @weights.
 * @lengths: The lengths of @strings.
 * @strings: An array of strings, that may contain NUL characters.
 * @weights: The string weights (they behave exactly as multiplicities, though
 *           any positive value is allowed, not just integers).
 * @medlength: Where the length of the median should be stored.
 *
 * Finds a generalized median string of @strings using the greedy algorithm.
 *
 * Note it's considerably more efficient to give a string with weight 2
 * than to store two identical strings in @strings (with weights 1).
 *
 * Returns: The generalized median, as a newly allocated string; its length
 *          is stored in @medlength.
 **/
lev_wchar* lev_median(std::vector<std::wstring> *strings, 
		std::vector<int> *weights, size_t *medlength);

float compute_centroid(std::set<int> *clust, std::vector<float> *el_vec);

float abs_dist(float a, float b);

void k_means(std::vector<float> *toclust, std::set<int> *cluster1,
	std::set<int> *cluster2);
