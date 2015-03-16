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

#include <cstring>
#include <stdlib.h>
#include <math.h>
#include <cassert>
#include "toolfunctions.hpp"

size_t lev_distance(size_t len1, const lev_byte *string1,
	size_t len2, const lev_byte *string2, int xcost)
{
  size_t i;
  size_t *row;  /* we only need to keep one row of costs */
  size_t *end;
  size_t half;

  /* strip common prefix */
  while (len1 > 0 && len2 > 0 && *string1 == *string2) {
    len1--;
    len2--;
    string1++;
    string2++;
  }

  /* strip common suffix */
  while (len1 > 0 && len2 > 0 && string1[len1-1] == string2[len2-1]) {
    len1--;
    len2--;
  }

  /* catch trivial cases */
  if (len1 == 0)
    return len2;
  if (len2 == 0)
    return len1;

  /* make the inner cycle (i.e. string2) the longer one */
  if (len1 > len2) {
    size_t nx = len1;
    const lev_byte *sx = string1;
    len1 = len2;
    len2 = nx;
    string1 = string2;
    string2 = sx;
  }
  /* check len1 == 1 separately */
  if (len1 == 1) {
    if (xcost)
      return len2 + 1 - 2*(memchr(string2, *string1, len2) != NULL);
    else
      return len2 - (memchr(string2, *string1, len2) != NULL);
  }
  len1++;
  len2++;
  half = len1 >> 1;

  /* initalize first row */
  row = (size_t*)malloc(len2*sizeof(size_t));
  if (!row)
    return (size_t)(-1);
  end = row + len2 - 1;
  for (i = 0; i < len2 - (xcost ? 0 : half); i++)
    row[i] = i;

  /* go through the matrix and compute the costs.  yes, this is an extremely
   * obfuscated version, but also extremely memory-conservative and relatively
   * fast.  */
  if (xcost) {
    for (i = 1; i < len1; i++) {
      size_t *p = row + 1;
      const lev_byte char1 = string1[i - 1];
      const lev_byte *char2p = string2;
      size_t D = i;
      size_t x = i;
      while (p <= end) {
        if (char1 == *(char2p++))
          x = --D;
        else
          x++;
        D = *p;
        D++;
        if (x > D)
          x = D;
        *(p++) = x;
      }
    }
  }
  else {
    /* in this case we don't have to scan two corner triangles (of size len1/2)
     * in the matrix because no best path can go throught them. note this
     * breaks when len1 == len2 == 2 so the memchr() special case above is
     * necessary */
    row[0] = len1 - half - 1;
    for (i = 1; i < len1; i++) {
      size_t *p;
      const lev_byte char1 = string1[i - 1];
      const lev_byte *char2p;
      size_t D, x;
      /* skip the upper triangle */
      if (i >= len1 - half) {
        size_t offset = i - (len1 - half);
        size_t c3;

        char2p = string2 + offset;
        p = row + offset;
        c3 = *(p++) + (char1 != *(char2p++));
        x = *p;
        x++;
        D = x;
        if (x > c3)
          x = c3;
        *(p++) = x;
      }
      else {
        p = row + 1;
        char2p = string2;
        D = x = i;
      }
      /* skip the lower triangle */
      if (i <= half + 1)
        end = row + len2 + i - half - 2;
      /* main */
      while (p <= end) {
        size_t c3 = --D + (char1 != *(char2p++));
        x++;
        if (x > c3)
          x = c3;
        D = *p;
        D++;
        if (x > D)
          x = D;
        *(p++) = x;
      }
      /* lower triangle sentinel */
      if (i <= half) {
        size_t c3 = --D + (char1 != *char2p);
        x++;
        if (x > c3)
          x = c3;
        *p = x;
      }
    }
  }

  i = *end;
  free(row);
  return i;
}

size_t lev_u_distance(size_t len1, const lev_wchar *string1, size_t len2,
	const lev_wchar *string2, int xcost)
{
  size_t i;
  size_t *row;  /* we only need to keep one row of costs */
  size_t *end;
  size_t half;

  /* strip common prefix */
  while (len1 > 0 && len2 > 0 && *string1 == *string2) {
    len1--;
    len2--;
    string1++;
    string2++;
  }

  /* strip common suffix */
  while (len1 > 0 && len2 > 0 && string1[len1-1] == string2[len2-1]) {
    len1--;
    len2--;
  }

  /* catch trivial cases */
  if (len1 == 0)
    return len2;
  if (len2 == 0)
    return len1;

  /* make the inner cycle (i.e. string2) the longer one */
  if (len1 > len2) {
    size_t nx = len1;
    const lev_wchar *sx = string1;
    len1 = len2;
    len2 = nx;
    string1 = string2;
    string2 = sx;
  }
  /* check len1 == 1 separately */
  if (len1 == 1) {
    lev_wchar z = *string1;
    const lev_wchar *p = string2;
    for (i = len2; i; i--) {
      if (*(p++) == z)
        return len2 - 1;
    }
    return len2 + (xcost != 0);
  }
  len1++;
  len2++;
  half = len1 >> 1;

  /* initalize first row */
  row = (size_t*)malloc(len2*sizeof(size_t));
  if (!row)
    return (size_t)(-1);
  end = row + len2 - 1;
  for (i = 0; i < len2 - (xcost ? 0 : half); i++)
    row[i] = i;

  /* go through the matrix and compute the costs.  yes, this is an extremely
   * obfuscated version, but also extremely memory-conservative and relatively
   * fast.  */
  if (xcost) {
    for (i = 1; i < len1; i++) {
      size_t *p = row + 1;
      const lev_wchar char1 = string1[i - 1];
      const lev_wchar *char2p = string2;
      size_t D = i - 1;
      size_t x = i;
      while (p <= end) {
        if (char1 == *(char2p++))
          x = D;
        else
          x++;
        D = *p;
        if (x > D + 1)
          x = D + 1;
        *(p++) = x;
      }
    }
  }
  else {
    /* in this case we don't have to scan two corner triangles (of size len1/2)
     * in the matrix because no best path can go throught them. note this
     * breaks when len1 == len2 == 2 so the memchr() special case above is
     * necessary */
    row[0] = len1 - half - 1;
    for (i = 1; i < len1; i++) {
      size_t *p;
      const lev_wchar char1 = string1[i - 1];
      const lev_wchar *char2p;
      size_t D, x;
      /* skip the upper triangle */
      if (i >= len1 - half) {
        size_t offset = i - (len1 - half);
        size_t c3;

        char2p = string2 + offset;
        p = row + offset;
        c3 = *(p++) + (char1 != *(char2p++));
        x = *p;
        x++;
        D = x;
        if (x > c3)
          x = c3;
        *(p++) = x;
      }
      else {
        p = row + 1;
        char2p = string2;
        D = x = i;
      }
      /* skip the lower triangle */
      if (i <= half + 1)
        end = row + len2 + i - half - 2;
      /* main */
      while (p <= end) {
        size_t c3 = --D + (char1 != *(char2p++));
        x++;
        if (x > c3)
          x = c3;
        D = *p;
        D++;
        if (x > D)
          x = D;
        *(p++) = x;
      }
      /* lower triangle sentinel */
      if (i <= half) {
        size_t c3 = --D + (char1 != *char2p);
        x++;
        if (x > c3)
          x = c3;
        *p = x;
      }
    }
  }

  i = *end;
  free(row);
  return i;
}


void free_usymlist_hash(HItem *symmap)
{
  size_t j;

  for (j = 0; j < 0x100; j++) {
    HItem *p = symmap + j;
    if (p->n == symmap || p->n == NULL)
      continue;
    p = p->n;
    while (p) {
      HItem *q = p;
      p = p->n;
      free(q);
    }
  }
  free(symmap);
}

lev_wchar* make_usymlist(std::vector<std::wstring> *strings, size_t *symlistlen)
{
	lev_wchar *symlist;
	size_t i, j;
	HItem *symmap;
	
	size_t n = strings->size();

	j = 0;
	for (i = 0; i < n; i++)
		j += strings->at(i).length();

	*symlistlen = 0;
	if (j == 0)
		return NULL;

	/* find all symbols, use a kind of hash for storage */
	symmap = (HItem*)malloc(0x100*sizeof(HItem));
	if (!symmap) {
		*symlistlen = (size_t)(-1);
		return NULL;
	}
	/* this is an ugly memory allocation avoiding hack: most hash elements
	 * will probably contain none or one symbols only so, when p->n is equal
	 * to symmap, it means there're no symbols yet, afters insterting the
	 * first one, p->n becomes normally NULL and then it behaves like an
	 * usual singly linked list */
	for (i = 0; i < 0x100; i++)
		symmap[i].n = symmap;

	for (i = 0; i < n; i++) {
		std::wstring *stri = &strings->at(i);
		size_t str_length = stri->length();
		for (j = 0; j < str_length; j++) {
			int c = stri->at(j);
			int key = (c + (c >> 7)) & 0xff;
			HItem *p = symmap + key;
			if (p->n == symmap) {
				p->c = c;
				p->n = NULL;
				(*symlistlen)++;
				continue;
			}
			while (p->c != c && p->n != NULL)
				p = p->n;
			if (p->c != c) {
				p->n = (HItem*)malloc(sizeof(HItem));
				if (!p->n) {
					free_usymlist_hash(symmap);
					*symlistlen = (size_t)(-1);
					return NULL;
				}
				p = p->n;
				p->n = NULL;
				p->c = c;
				(*symlistlen)++;
			}
		}
	}
	/* create dense symbol table, so we can easily iterate over only characters
	 * present in the strings */
	{
		size_t pos = 0;
		symlist = (lev_wchar*)malloc((*symlistlen)*sizeof(lev_wchar));
		if (!symlist) {
			free_usymlist_hash(symmap);
			*symlistlen = (size_t)(-1);
			return NULL;
		}
		for (j = 0; j < 0x100; j++) {
			HItem *p = symmap + j;
			while (p != NULL && p->n != symmap) {
				symlist[pos++] = p->c;
				p = p->n;
			}
		}
	}

	/* free memory */
	free_usymlist_hash(symmap);

	return symlist;
}

lev_wchar* lev_median(std::vector<std::wstring> *strings, 
		std::vector<int> *weights, size_t *medlength)
{
	size_t i;  /* usually iterates over strings (n) */
	size_t j;  /* usually iterates over characters */
	size_t len;  /* usually iterates over the approximate median string */
	lev_wchar *symlist;  /* list of symbols present in the strings,
							we iterate over it insead of set of all
							existing symbols */
	size_t symlistlen;  /* length of symlistle */
	size_t maxlen;  /* maximum input string length */
	size_t stoplen;  /* maximum tried median string length -- this is slightly
						higher than maxlen, because the median string may be
						longer than any of the input strings */
	size_t **rows;  /* Levenshtein matrix rows for each string, we need to keep
					   only one previous row to construct the current one */
	size_t *row;  /* a scratch buffer for new Levenshtein matrix row computation,
					 shared among all strings */
	lev_wchar *median;  /* the resulting approximate median string */
	double *mediandist;  /* the total distance of the best median string of
							given length.  warning!  mediandist[0] is total
							distance for empty string, while median[] itself
							is normally zero-based */
	size_t bestlen;  /* the best approximate median string length */

	size_t n = strings->size();

	/* find all symbols */
	symlist = make_usymlist(strings, &symlistlen);
	if (!symlist) {
		*medlength = 0;
		if (symlistlen != 0)
			return NULL;
		else
			return (lev_wchar*)calloc(1, sizeof(lev_wchar));
	}

	/* allocate and initialize per-string matrix rows and a common work buffer */
	rows = (size_t**)malloc(n*sizeof(size_t*));
	if (!rows) {
		free(symlist);
		return NULL;
	}
	maxlen = 0;
	for (i = 0; i < n; i++) {
		size_t *ri;
		size_t leni = strings->at(i).length();
		if (leni > maxlen)
			maxlen = leni;
		ri = rows[i] = (size_t*)malloc((leni + 1)*sizeof(size_t));
		if (!ri) {
			for (j = 0; j < i; j++)
				free(rows[j]);
			free(rows);
			free(symlist);
			return NULL;
		}
		for (j = 0; j <= leni; j++)
			ri[j] = j;
	}
	stoplen = 2*maxlen + 1;
	row = (size_t*)malloc((stoplen + 1)*sizeof(size_t));
	if (!row) {
		for (j = 0; j < n; j++)
			free(rows[j]);
		free(rows);
		free(symlist);
		return NULL;
	}

	/* compute final cost of string of length 0 (empty string may be also
	 * a valid answer) */
	median = (lev_wchar*)malloc(stoplen*sizeof(lev_wchar));
	if (!median) {
		for (j = 0; j < n; j++)
			free(rows[j]);
		free(rows);
		free(row);
		free(symlist);
		return NULL;
	}
	mediandist = (double*)malloc((stoplen + 1)*sizeof(double));
	if (!mediandist) {
		for (j = 0; j < n; j++)
			free(rows[j]);
		free(rows);
		free(row);
		free(symlist);
		free(median);
		return NULL;
	}
	mediandist[0] = 0.0;
	for (i = 0; i < n; i++)
		mediandist[0] += strings->at(i).length() * (weights->at(i));

	/* build up the approximate median string symbol by symbol
	 * XXX: we actually exit on break below, but on the same condition */
	for (len = 1; len <= stoplen; len++) {
		lev_wchar symbol;
		double minminsum = LEV_INFINITY;
		row[0] = len;
		/* iterate over all symbols we may want to add */
		for (j = 0; j < symlistlen; j++) {
			double totaldist = 0.0;
			double minsum = 0.0;
			symbol = symlist[j];
			/* sum Levenshtein distances from all the strings, with given weights */
			for (i = 0; i < n; i++) {
				const lev_wchar *stri = strings->at(i).c_str();
				size_t *p = rows[i];
				size_t leni = strings->at(i).length();
				size_t *end = rows[i] + leni;
				size_t min = len;
				size_t x = len; /* == row[0] */
				/* compute how another row of Levenshtein matrix would look for median
				 * string with this symbol added */
				while (p < end) {
					size_t D = *(p++) + (symbol != *(stri++));
					x++;
					if (x > D)
						x = D;
					if (x > *p + 1)
						x = *p + 1;
					if (x < min)
						min = x;
				}
				minsum += min * weights->at(i);
				totaldist += x * weights->at(i);
			}
			/* is this symbol better than all the others? */
			if (minsum < minminsum) {
				minminsum = minsum;
				mediandist[len] = totaldist;
				median[len - 1] = symbol;
			}
		}
		/* stop the iteration if we no longer need to recompute the matrix rows
		 * or when we are over maxlen and adding more characters doesn't seem
		 * useful */
		if (len == stoplen
				|| (len > maxlen && mediandist[len] > mediandist[len - 1])) {
			stoplen = len;
			break;
		}
		/* now the best symbol is known, so recompute all matrix rows for this
		 * one */
		symbol = median[len - 1];
		for (i = 0; i < n; i++) {
			//const lev_wchar *stri = strings[i];
			std::wstring *stri = &strings->at(i);
			size_t *oldrow = rows[i];
			size_t leni = strings->at(i).length();
			size_t k;
			/* compute a row of Levenshtein matrix */
			for (k = 1; k <= leni; k++) {
				size_t c1 = oldrow[k] + 1;
				size_t c2 = row[k - 1] + 1;
				size_t c3 = oldrow[k - 1] + (symbol != stri->at(k - 1));
				row[k] = c2 > c3 ? c3 : c2;
				if (row[k] > c1)
					row[k] = c1;
			}
			memcpy(oldrow, row, (leni + 1)*sizeof(size_t));
		}
	}

	/* find the string with minimum total distance */
	bestlen = 0;
	for (len = 1; len <= stoplen; len++) {
		if (mediandist[len] < mediandist[bestlen])
			bestlen = len;
	}

	/* clean up */
	for (i = 0; i < n; i++)
		free(rows[i]);
	free(rows);
	free(row);
	free(symlist);
	free(mediandist);

	/* return result */
	{
		lev_wchar *result = (lev_wchar*)malloc(bestlen*sizeof(lev_wchar));
		if (!result) {
			free(median);
			return NULL;
		}
		memcpy(result, median, bestlen*sizeof(lev_wchar));
		free(median);
		*medlength = bestlen;
		return result;
	}
}

float lev_ratio(std::string *s1, std::string *s2)
{
	size_t lensum = s1->length() + s2->length();
	int ldist;
	
	if (lensum == 0)
		return 1.0;
	
	ldist =
		lev_distance(s1->length(), s1->c_str(), s2->length(), s2->c_str(), 1);
	
	return (float)(lensum - ldist)/(float)lensum;
}

float lev_u_ratio(std::wstring *s1, std::wstring *s2)
{
	size_t lensum = s1->length() + s2->length();
	int ldist;
	
	if (lensum == 0)
		return 1.0;
	
	ldist =
		lev_u_distance(s1->length(), s1->c_str(), s2->length(), s2->c_str(), 1);
	
	return (float)(lensum - ldist)/(float)lensum;
}

float compute_centroid(std::set<int> *clust, std::vector<float> *el_vec){
	float result = 0;
	std::set<int>::iterator it;
	
	for (it = clust->begin(); it != clust->end(); it++) {
		result += el_vec->at(*it);
	}
	return result/clust->size();
}

float abs_dist(float a, float b)
{
	return (a > b)?(a - b):(b - a);
}

void k_means(std::vector<float> *toclust, std::set<int> *cluster1,
	std::set<int> *cluster2)
{
	int n = toclust->size();
	assert(n > 1);
	
	float max = 0, min = 1;

	for (int i = 0; i < n; i++) {
		if (toclust->at(i) > max)
			max = toclust->at(i);
		if (toclust->at(i) < min)
			min = toclust->at(i);
	}

	bool some_point_is_moving = true;

	float c1 = min, c2 = max;
	while (some_point_is_moving) {
		some_point_is_moving = false;

		for (int i = 0; i < n; i++) {
			float d1 = abs_dist(toclust->at(i), c1);	
			float d2 = abs_dist(toclust->at(i), c2);	
			if (d1 < d2) {
				some_point_is_moving = cluster1->insert(i).second;
				cluster2->erase(i);
			} else {
				some_point_is_moving = cluster2->insert(i).second;
				cluster1->erase(i);		
			}
		}

		if (cluster1->size() == 0 || cluster2->size() == 0)
			break;
		c1 = compute_centroid(cluster1, toclust);
		c2 = compute_centroid(cluster2, toclust);

	}

	#if 0
	for (int i = 0; i < n; i++) {
		toclust->at(i) = round(toclust->at(i) * 10000)/10000;
		if (i % 2)
			cluster1->insert(i);
		else
			cluster2->insert(i);
	}

	int some_point_is_moving = 1;

	float c1, c2;
	while (some_point_is_moving) {
		some_point_is_moving = 0;
		if (cluster1->size() == 0 || cluster2->size() == 0)
			break;
		c1 = compute_centroid(cluster1, toclust);
		c2 = compute_centroid(cluster2, toclust);

		for (int i = 0; i < n; i++) {
			float d1 = abs_dist(toclust->at(i), c1);	
			float d2 = abs_dist(toclust->at(i), c2);	
			if (d1 < d2) {
				cluster1->insert(i);
				some_point_is_moving = cluster2->erase(i);
			} else {
				cluster2->insert(i);
				some_point_is_moving = cluster1->erase(i);		
			}
		}
	}
	#endif
	/* Cross-check*/
	std::set<int>::iterator test, it;
	for (it = cluster1->begin(); it != cluster1->end(); it++) {
		test = cluster2->find(*it);
		assert (test == cluster2->end());
	}

}
