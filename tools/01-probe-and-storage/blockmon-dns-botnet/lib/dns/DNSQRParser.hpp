/* Copyright (c) 2012 ETH Zürich. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the names of ETH Zürich nor the names of other contributors 
 *      may be used to endorse or promote products derived from this software 
 *      without specific prior written permission.
 *
 * This software is also available under the terms of the GNU Lesser General 
 * Public License for integration with LGPL or GPL code; therefore, any 
 * contributions to the code in this file carry implicit permission of 
 * dual-licensing of the contributed patch. Contact Brian Trammell 
 * <trammell@tik.ee.ethz.ch> for questions concerning dual-licensing.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT 
 * HOLDERBE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DNSQR_PARSER_HPP_
#define _DNSQR_PARSER_HPP_

#define DNSQR_DEBUG_NAME 0
#define DNSQR_DEBUG_ERR  0
#define DNSQR_DEBUG_HDR 0
#define DNSQR_DEBUG_QD 0
#define DNSQR_DEBUG_RR 0

#include <cstdint>
#include <arpa/inet.h>

namespace dnsqr {

enum Opcode {
    kOpcodeQuery     = 0,
    kOpcodeIQuery    = 1,
    kOpcodeStatus    = 2,
};

enum RCode {
    kRCodeNoError    = 0,
    kRCodeFormErr    = 1,
    kRCodeServFail   = 2,
    kRCodeNXDomain   = 3,
    kRCodeNotImp     = 4,
    kRCodeRefused    = 5,
};

enum Section {
    kSectionAnswer = 1,
    kSectionAuthority = 2,
    kSectionAdditional = 4,
    kSectionAny = 7,
};

enum QClass {
    kDNSClassIN   = 1,
    kDNSClassAny  = 255,
};

enum RRType {
    kRRTypeA     = 1,
    kRRTypeNS    = 2,
    kRRTypeCNAME = 5,
    kRRTypeSOA   = 6,
    kRRTypePTR   = 12,
    kRRTypeHINFO = 13,
    kRRTypeMX    = 15,
    kRRTypeTXT   = 16,
    kRRTypeAAAA  = 28,
    kRRTypeSTAR  = 255,
};

struct wire_dns_hdr {
   uint16_t    id;
   uint16_t    codes;
   uint16_t    qdcount;
   uint16_t    ancount;
   uint16_t    nscount;
   uint16_t    arcount;
};

class Decode {
public:
    static unsigned opcode(uint16_t codes) {
        return (codes & 0x7800) >> 11;
    }

    static unsigned rcode(uint16_t codes) {
        return codes & 0x000f;
    }

    static bool qr(uint16_t codes) {
        return codes & 0x8000;
    }

    static bool aa(uint16_t codes) {
        return codes & 0x0400;
    }

    static bool tc(uint16_t codes) {
        return codes & 0x0200;
    }

    static bool rd(uint16_t codes) {
        return codes & 0x0100;
    }

    static bool ra(uint16_t codes) {
        return codes & 0x0080;
    }
};

class Printer {
public:
    static std::string opcodestr(uint16_t codes) {
        static std::map<Opcode, std::string> ocmap =
        { { kOpcodeQuery  , std::string("Query") }, 
          { kOpcodeIQuery , std::string("IQuery") }, 
          { kOpcodeStatus , std::string("Status") } };
        return ocmap[static_cast<Opcode>(Decode::opcode(codes))];
    }
    
    static std::string rcodestr(uint16_t codes) {
        static std::map<RCode, std::string> rcmap =
        { { kRCodeNoError  , std::string("NoError" ) },
          { kRCodeFormErr  , std::string("FormErr" ) },
          { kRCodeServFail , std::string("ServFail") },
          { kRCodeNXDomain , std::string("NXDomain") },
          { kRCodeNotImp   , std::string("NotImp"  ) },
          { kRCodeRefused  , std::string("Refused" ) } };
      return rcmap[static_cast<RCode>(Decode::rcode(codes))];
    }

    static std::string secstr(Section sec) {
        static std::map<Section, std::string> secmap =
        { { kSectionAnswer     , std::string("answer") },
          { kSectionAuthority  , std::string("authority") },
          { kSectionAdditional , std::string("additional") },
          { kSectionAny        , std::string("any_section") } };
      return secmap[sec];
    }

    static std::string classstr(uint16_t dnsclass) {
        switch (dnsclass) {
            case kDNSClassIN:
            return std::string("IN");
            case kDNSClassAny:
            return std::string("ANY");
            default:
            return std::string("?");
        }
    }
    
    static std::string typestr(uint16_t dnstype) {
        static std::map<RRType, std::string> tsmap =
            { { kRRTypeA     , std::string("A"    ) },
              { kRRTypeNS    , std::string("NS"   ) },
              { kRRTypeCNAME , std::string("CNAME") },
              { kRRTypeSOA   , std::string("SOA"  ) },
              { kRRTypePTR   , std::string("PTR"  ) },
              { kRRTypeHINFO , std::string("HINFO") },
              { kRRTypeMX    , std::string("MX"   ) },
              { kRRTypeTXT   , std::string("TXT"  ) },
              { kRRTypeAAAA  , std::string("AAAA" ) },
              { kRRTypeSTAR  , std::string("*"    ) } };
        return tsmap[static_cast<RRType>(dnstype)];
    }    
};

template <typename Handler>
class Parser {

protected: 
    const uint8_t*  m_pbase;
    size_t          m_plen;
    
    uint16_t m_id;
    uint16_t m_codes;
    
    uint16_t m_qdcount;
    uint16_t m_ancount;
    uint16_t m_nscount;
    uint16_t m_arcount;
    
    Handler& h;

    static const size_t  kDNSHdrLen           = 12;
    static const size_t  kDNSNameMaxRecursion = 16;

    // FIXME nonportable but should work on ia32, amd64
    const uint8_t* parse_dns_val(uint16_t& val, const uint8_t* cp) {
        if (remaining(cp) < sizeof(val)) {
#if DNSQR_DEBUG_ERR
            std::cerr << "dnsqr: parse_dns_val(): overrun (need " << 
                         sizeof(val) << ", have " << remaining(cp) << ")" << 
                         std::endl;
#endif
            return NULL;
        }
        val = ntohs(*reinterpret_cast<const uint16_t*>(cp));
        return cp + sizeof(val);
    }

    // FIXME nonportable but should work on ia32, amd64
    const uint8_t* parse_dns_val(uint32_t& val, const uint8_t* cp) {
        if (remaining(cp) < sizeof(val)) {
#if DNSQR_DEBUG_ERR
            std::cerr << "dnsqr: parse_dns_val(): overrun (need " << 
                         sizeof(val) << ", have " << remaining(cp) << ")" << 
                         std::endl;
#endif
            return NULL;
        }
        val = ntohl(*reinterpret_cast<const uint32_t*>(cp));
        return cp + sizeof(val);
    }

    const uint8_t* parse_dns_name(std::string& name, const uint8_t* cp, unsigned level = 0) {    
        size_t clen;

        while (in_bounds(cp)) {
            clen = *cp++;
#if DNSQR_DEBUG_NAME
            std::cerr << "    in parse_dns_name(" << level << "): clen " << clen << std::endl;
#endif
            if (clen == 0) {
#if DNSQR_DEBUG_NAME
                std::cerr << "        terminating." << std::endl;
#endif
                return cp;
            } else if ((clen & 0xc0) == 0) {
                // normal component, check bounds
                if (clen > remaining(cp)) {
#if DNSQR_DEBUG_ERR
                    std::cerr << "dnsqr: parse_dns_name(" << level << 
                                 ") overrun (need " << clen << 
                                 ", have " << remaining(cp) << ")" << 
                                 std::endl;
#endif
                    return NULL;
                }
                // append string
                std::string part = std::string(reinterpret_cast<const char *>(cp), clen);
#if DNSQR_DEBUG_NAME
                std::cerr << "        got part " << part << std::endl;
#endif
                name.append(part);
                name.append(".");
                cp += clen;
            } else if ((clen & 0xc0) == 0xc0) {
                // message compression, recurse and return
                if (level > kDNSNameMaxRecursion) {
#if DNSQR_DEBUG_ERR
                    std::cerr << "dnsqr: parse_dns_name(" << level << 
                                 ") compression too recursive " << std::endl;
#endif
                    return NULL;
                }
                cp--;
                uint16_t off = 0;
                if (!(cp = parse_dns_val(off, cp))) return NULL;
                off &= 0x3fff; // mask out two high bits
#if DNSQR_DEBUG_NAME
                std::cerr << "        compression (offset " << off << ")" << std::endl;
#endif
                return parse_dns_name(name, m_pbase + off, level + 1) ? cp : NULL;
            } else {
                // reserved component type, fail
#if DNSQR_DEBUG_ERR
                std::cerr << "dnsqr: parse_dns_name(" << level << 
                             ") illegal coomponent length " << clen << 
                             std::endl;
#endif
                return NULL;
            }
        }

        // we fell out of the bounds loop, so we failed to parse.
        return NULL;
    }

    const uint8_t* parse_qd(const uint8_t *cp) {
        std::string qname;
        uint16_t    qtype = 0, qclass = 0;

        if (!(cp = parse_dns_name(qname, cp))) return NULL;
        if (!(cp = parse_dns_val(qtype, cp))) return NULL;
        if (!(cp = parse_dns_val(qclass, cp))) return NULL;

#if DNSQR_DEBUG_QD
        std::cerr << "dnsqr: question: " << qname << " ";
        std::cerr << classstr(qclass) << " ";
        std::cerr << typestr(qtype) << " " << std::endl;
#endif

        if ((qclass == kDNSClassIN) || (qclass = kDNSClassAny)) {
            h.dns_qd(qname, static_cast<RRType>(qtype));
        }

        return cp;
    }

    const uint8_t* parse_rr_a(const std::string& name, 
                                            unsigned ttl, 
                                            size_t rdlen, 
                                            const uint8_t *cp, 
                                            const Section sec) 
    {
        if ((rdlen != sizeof(uint32_t)) || remaining(cp) < rdlen) {
#if DNSQR_DEBUG_ERR
            std::cerr << "dnsqr: parse_rr_a() overrun (need " << rdlen << 
                         ", have " << remaining(cp) << ")" << std::endl;
#endif
            return NULL;
        }

        uint32_t a;
        if (!(cp = parse_dns_val(a, cp))) return NULL;

#if DNSQR_DEBUG_RR
        std::cerr << "dnsqr:  "<< secstr(sec) << ": ";
        std::cerr << name << " ";
        std::cerr.width(8);
        std::cerr << ttl;
        std::cerr << " IN A ";
        std::cerr << ((a & 0xFF000000) >> 24) << "."
                  << ((a & 0x00FF0000) >> 16) << "."
                  << ((a & 0x0000FF00) >> 8) << "."
                  << (a & 0x000000FF) << std::endl;
#endif

        h.dns_rr_a(sec, name, ttl, a);

        return cp;
    }

    const uint8_t* parse_rr_cname(const std::string& name, 
                                  unsigned ttl, 
                                  size_t rdlen, 
                                  const uint8_t *cp, 
                                  const Section sec) 
    {
        if (remaining(cp) < rdlen) {
#if DNSQR_DEBUG_ERR
            std::cerr << "dnsqr: parse_rr_cname() overrun (need " << rdlen << 
                         ", have " << remaining(cp) << ")" << std::endl;
#endif
            return NULL;
        }

        std::string cname;
        if (!(cp = parse_dns_name(cname, cp))) return NULL;

#if DNSQR_DEBUG_RR
        std::cerr << "dnsqr:  "<< secstr(sec) << ": ";
        std::cerr << name << " ";
        std::cerr.width(8);
        std::cerr << ttl;
        std::cerr << " IN CNAME " << cname << std::endl;
#endif

        h.dns_rr_cname(sec, name, ttl, cname);

        return cp;
    }

    const uint8_t* parse_rr(const uint8_t *cp, const Section sec) {
        std::string name;
        uint16_t dnstype = 0;
        uint16_t dnsclass = 0;
        uint32_t ttl = 0;
        uint16_t rdlength = 0;

        if (!(cp = parse_dns_name(name, cp))) return NULL;
        if (!(cp = parse_dns_val(dnstype, cp))) return NULL;
        if (!(cp = parse_dns_val(dnsclass, cp))) return NULL;
        if (!(cp = parse_dns_val(ttl, cp))) return NULL;        
        if (!(cp = parse_dns_val(rdlength, cp))) return NULL;

        if (dnsclass == kDNSClassIN) {
            switch(dnstype) {
                case kRRTypeA:
                    return parse_rr_a(name, ttl, rdlength, cp, sec);
                case kRRTypeCNAME:
                    return parse_rr_cname(name, ttl, rdlength, cp, sec);
                default: 
#if DNSQR_DEBUG_RR
                    std::cerr << "dnsqr:  "<< secstr(sec) << ": ";
                    std::cerr << name << " ";
                    std::cerr.width(8);
                    std::cerr << ttl << " ";
                    std::cerr << classstr(dnsclass) << " ";
                    std::cerr << typestr(dnstype) << " ";
                    std::cerr << " (" << rdlength << " octets)" << std::endl;
#endif
                    cp += rdlength;
            }
        } else {
            // non-Internet record; skip
            cp += rdlength;
        }

        return cp;
    }

    bool parse_dns_payload_inner() { 
        const uint8_t* cp = m_pbase;

        // parse the header
        if (m_plen < kDNSHdrLen) return false;
        auto hdr = reinterpret_cast<const wire_dns_hdr *>(cp);
        cp += kDNSHdrLen;

        uint16_t id = ntohs(hdr->id);
        uint16_t codes = ntohs(hdr->codes);

        uint16_t qdcount = ntohs(hdr->qdcount);
        uint16_t ancount = ntohs(hdr->ancount);
        uint16_t nscount = ntohs(hdr->nscount);
        uint16_t arcount = ntohs(hdr->arcount);

#if DNSQR_DEBUG_HDR
        std::cerr << "dnsqr: header: id " << id << " " << opcodestr(codes);
        std::cerr << "/" << rcodestr(codes);
        if (qr(codes)) { std::cerr << " QR"; }
        if (aa(codes)) { std::cerr << " AA"; }
        if (tc(codes)) { std::cerr << " TC"; }
        if (rd(codes)) { std::cerr << " RD"; }
        if (ra(codes)) { std::cerr << " RA"; }
        std::cerr << std::endl << "       " << qdcount << " questions, ";
        std::cerr << ancount << " answer RRs, ";
        std::cerr << nscount << " authority RRs, ";
        std::cerr << arcount << " additional RRs" << std::endl;
#endif

        // call handler, allow it to veto based on the header
        if (!h.dns_header(id, codes, qdcount, ancount, nscount, arcount)) {
            return false;
        }

        for (unsigned i = 0; i < qdcount; i++) {
            if (!(cp = parse_qd(cp))) return false;
        }

        for (unsigned i = 0; i < ancount; i++) {
            if (!(cp = parse_rr(cp, kSectionAnswer))) return false;
        }

        for (unsigned i = 0; i < nscount; i++) {
            if (!(cp = parse_rr(cp, kSectionAuthority))) return false;
        }

        for (unsigned i = 0; i < arcount; i++) {
            if (!(cp = parse_rr(cp, kSectionAdditional))) return false;
        }
        
        return true;
    }

public:
    
    Parser(Handler& hc): h(hc) {};

    bool in_bounds(const uint8_t* cp) {
        if (m_pbase && cp >= m_pbase) {
            return static_cast<ssize_t>(m_plen) >= cp - m_pbase;
        } else {
            return false;
        }
    }

    size_t remaining(const uint8_t* cp) {
        return m_pbase ? (m_plen - (cp - m_pbase)) : 0;
    }
    

    bool parse_dns_payload(const uint8_t *base, size_t len) {
        // stash the base pointer and length, call inner
        m_pbase = base;
        m_plen = len;
        bool rv = parse_dns_payload_inner();
        m_pbase = NULL;
        m_plen = 0;
        h.dns_end(rv);
        return rv;
    }
};

}

#endif