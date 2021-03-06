#include "types.h"
#include "defs.h"
#include "netutils.h"

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

#include <net/if_arp.h>

// string fmt helpers
char str1[64];

// for ether_aton_r
static ether_addr eth1, eth2;

static bool is_my_nbr(const in_addr_t nbr, const uint8_t tunId)
{
   return inet_addr(fmt_str(fauxIPfmt, str1, sizeof(str1), tunId)) == nbr;
}


const char * fmt_str(const char  * fmt, 
                     char * const  str, 
                     const size_t  strlen, 
                     const uint8_t val)
{
    memset(str, 0x0, strlen);
    snprintf(str, strlen - 1, fmt, val);

    return str;
}

const char * fmt_str(const char  * fmt, 
                     char * const  str, 
                     const size_t  strlen, 
                     const uint8_t val1,
                     const uint8_t val2,
                     const uint8_t val3)
{
    memset(str, 0x0, strlen);
    snprintf(str, strlen - 1, fmt, val1, val2, val3);

    return str;
}


void print_hex(const char * buff, size_t const buff_len, const Colors & colors)
{
    const size_t lineLen = 16;

    size_t linenum = 0;
    size_t pos = 0;

    while(pos < buff_len)
    {
        struct Str {
          size_t pos;
          char   buf[128];
          Str() : pos(0), buf{0} { } 
        }strHex, strTxt; // 1 hex string and 1 text string

        for(size_t idx = 0; idx < lineLen; ++idx, ++pos)
        {
            if((idx != 0) && (idx % (lineLen / 2) == 0))
            {
                strHex.pos += snprintf(strHex.buf + strHex.pos, 
                                       sizeof(strHex.buf) - strHex.pos, " ");

                strTxt.pos += snprintf(strTxt.buf + strTxt.pos, 
                                       sizeof(strTxt.buf) - strTxt.pos, " ");
            }

            if(pos < buff_len)
            {
                const char val = buff[pos];

                strHex.pos += snprintf(strHex.buf + strHex.pos, 
                                       sizeof(strHex.buf) - strHex.pos, "%s%02hhx ", 
                                       colors[pos].c_, (uint8_t) val);

                strTxt.pos += snprintf(strTxt.buf + strTxt.pos, 
                                       sizeof(strTxt.buf) - strTxt.pos, "%c", 
                                       isalnum(val) ? val : '.');
            }
            else
            {
                // pad the last line
                strHex.pos += snprintf(strHex.buf + strHex.pos, 
                                       sizeof(strHex.buf) - strHex.pos, "   ");

                strTxt.pos += snprintf(strTxt.buf + strTxt.pos,
                                       sizeof(strTxt.buf) - strTxt.pos, " ");
            }
        }
        printf("%03zu  %s    %s\n", linenum * lineLen, strTxt.buf, strHex.buf);

        ++linenum;
    }

   printf("%s\n", COLOR_NRM);
}


uint16_t csum16(const void *buff, uint16_t len, const uint16_t carry)
{
  uint32_t sum = carry;

  uint16_t const * p = (uint16_t const *) buff;

  while(len > 1) {
     sum += *p++;
     len -= 2;
   }

  if(len > 0) {
     sum += *((uint8_t *) p);
   }

  while(sum >> 16) {
     sum = (sum & 0xFFFF) + (sum >> 16);
   }

  return(sum);
}


uint16_t csum16v(const iovec * iov, const size_t iovn)
{
  uint16_t sum = 0;

  for(size_t n = 0; n < iovn; ++n)
   {
     sum = csum16(iov[n].iov_base, iov[n].iov_len, sum);
   }

  return sum;
}


void set_eth_hdr(ether_header * eth,
                 const ether_addr * src,
                 const ether_addr * dst,
                 const uint16_t   type)
{
   memcpy(&eth->ether_dhost, dst, ETH_ALEN);
   memcpy(&eth->ether_shost, src, ETH_ALEN);
   eth->ether_type = htons(type);
}


void set_ipv4_hdr(iphdr * ip, 
                  const uint8_t tos,
                  const uint8_t ttl,
                  const uint16_t id,
                  const uint16_t plen,
                  const uint8_t  proto,
                  const in_addr_t src,
                  const in_addr_t dst,
                  const uint32_t * opts,
                  const size_t numopts)
 {
   // set ip hdr
   ip->version  = 4;
   ip->ihl      = 5 + numopts;
   ip->tos      = tos;
   ip->tot_len  = htons((ip->ihl << 2) + plen);
   ip->id       = htons(id);
   ip->frag_off = htons(0);
   ip->ttl      = ttl;
   ip->protocol = proto;
   ip->check    = 0;
   ip->saddr    = src; 
   ip->daddr    = dst;

   // set ip csum ip and opts if any
   const iovec chkv[2] = {{(void*)ip,   sizeof(*ip)}, 
                          {(void*)opts, numopts * 4}};

   ip->check = ~csum16v(chkv, 2);
}


void set_udp_hdr(udphdr * udp,
                 const uint16_t src, 
                 const uint16_t dst, 
                 const iphdr * ip,
                 const void * data,
                 const uint16_t dlen)
{
   // set udp hdr
   udp->source = htons(src);
   udp->dest   = htons(dst);
   udp->len    = htons(sizeof(*udp) + dlen);
   udp->check  = 0;

   // udp pseudo sum
   struct {
     uint32_t src, dst;
     uint8_t  mbz, proto;
     uint16_t len;
   } __attribute__((packed)) psum = {ip->saddr,
                                     ip->daddr,
                                     0,
                                     ip->protocol,
                                     udp->len};

   const iovec chkv[3] = {{(void*)&psum, sizeof(psum)}, 
                          {(void*)udp,   sizeof(*udp)},
                          {(void*)data,  dlen}};

   // set udp csum
   udp->check = ~csum16v(chkv, 3);
}


void set_igmp_hdr(igmp * igmp,
                 const uint8_t type, 
                 const uint8_t code, 
                 const in_addr_t grp)
{
   // set igmp hdr
   igmp->igmp_type         = type;
   igmp->igmp_code         = code;
   igmp->igmp_group.s_addr = grp;
   igmp->igmp_cksum        = 0;

   // set igmp csum
   igmp->igmp_cksum  = ~csum16(igmp, sizeof(*igmp));
}



size_t build_rip_frame(char * buff, const size_t buff_len, const uint8_t tunId)
{
   Colors colors(buff_len, Color(COLOR_NRM));

   memset(buff, 0x0, buff_len);

   static uint8_t ripcnt = 0;

   const size_t eth_offset  = 0;
   const size_t ip_offset   = eth_offset + sizeof(ether_header);
   const size_t udp_offset  = ip_offset  + sizeof(iphdr); // no ip options
   const size_t data_offset = udp_offset + sizeof(udphdr);

   auto eth  = (ether_header *) (buff + eth_offset);
   auto ip   = (iphdr *)        (buff + ip_offset);
   auto udp  = (udphdr *)       (buff + udp_offset);
   auto data = (uint8_t *)      (buff + data_offset);

   // payload len
   uint16_t data_len = 0;

   // first msg is rip request
   if(ripcnt++ == 0)
    {
      ripreqmsg_t ripmsg;

      // copy riphdr into buff
      memcpy(data + data_len, &ripmsg, sizeof(ripmsg));

      data_len += sizeof(ripmsg);
    }
   else
    {
      // rip respnse
      riphdr_t riphdr(2);

      // copy riphdr into buff
      memcpy(data + data_len, &riphdr, sizeof(riphdr));

      data_len += sizeof(riphdr);

      // construct for generating N rip entries
      // these could be 'fetched' from some neighbor manager service and
      // populated into the rip msg here
      const ripentry_t ripentry {fmt_str(rmtNWfmt, str1, sizeof(str1), tunId, 1, 0), // net
                                 rmtNMfmt,                                           // mask
                                 10};                                                // metric

      // copy ripentry into buff
      memcpy(data + data_len, &ripentry, sizeof(ripentry));
          
      data_len += sizeof(ripentry_t);
    }

   // set eth hdr
   set_eth_hdr(eth,
               ether_aton_r(fmt_str(fauxHWfmt, str1, sizeof(str1), tunId), &eth1), // faux nbr
               ether_aton_r(ripHWstr, &eth2),                                      // ripv2
               ETHERTYPE_IP);                                                      // ipv4

   // color eth porto
   colors[12].c_ = COLOR_YEL;
   colors[13].c_ = COLOR_YEL;

   set_ipv4_hdr(ip,
                TOS_NC,                                                     // tos
                1,                                                          // ttl
                0,                                                          // id
                sizeof(udphdr) + data_len,                                  // udp total len
                IPPROTO_UDP,                                                // proto
                inet_addr(fmt_str(fauxIPfmt, str1, sizeof(str1), tunId)),   // faux nbr ip
                inet_addr(ripIPstr),                                        // ripv2
                nullptr,                                                    // options
                0);                                                         // num options

   // ip type and proto
   colors[ip_offset].c_     = COLOR_GRN;
   colors[ip_offset + 9].c_ = COLOR_GRN;
 
   set_udp_hdr(udp,
               ripPortNum, // rip port
               ripPortNum, // rip port
               ip,         // ip hdr
               data,       // data
               data_len);  // data len

   print_hex(buff, data_offset + data_len, colors);

   return data_offset + data_len;
}


void set_igmp_query(ether_header * eth, 
                    iphdr        * ip, 
                    uint32_t     * ipop, 
                    igmp         * igmp,
                    uint8_t       tunId)
{
   memset(eth,  0x0, sizeof(*eth));
   memset(ip,   0x0, sizeof(*ip));
   memset(ipop, 0x0, sizeof(*ipop));
   memset(igmp, 0x0, sizeof(*igmp));

   set_eth_hdr(eth,
               ether_aton_r(fmt_str(fauxHWfmt, str1, sizeof(str1), tunId), &eth1), // faux nbr
               ether_aton_r(ahHWstr, &eth2),                                       // all hosts
               ETHERTYPE_IP);                                                      // ipv4

   // igmp uses the router alert option
   *ipop = htonl(ROUTER_ALERT);

   set_ipv4_hdr(ip,
                TOS_NC,                                                     // tos
                1,                                                          // ttl
                getpid(),                                                   // id
                sizeof(*igmp),                                              // igmp payload
                IPPROTO_IGMP,                                               // proto
                inet_addr(fmt_str(fauxIPfmt, str1, sizeof(str1), tunId)),   // faux nbr ip
                inet_addr(ahIPstr),                                         // all hosts
                ipop,                                                       // options
                1);                                                         // num options

   set_igmp_hdr(igmp,
                IGMP_MEMBERSHIP_QUERY, // query
                0x64,                  // 10 sec response time
                inet_addr(anyIPstr));  // any grp

}

int parse_frame(char *buff, const size_t buff_len, const size_t msg_len, const uint8_t tunId)
{
    Colors colors(msg_len, Color(COLOR_NRM));

    printf("%s tunId %hhu\n", __func__, tunId);

    int bounce_len = 0;

    if(msg_len > sizeof(ether_header))
    {
        ether_header * eth = (ether_header *) buff;

        const uint16_t ether_type = htons(eth->ether_type);

        // sanity check ethhdr + arphdr + 2(eth/ipv4) and ether_type_arp
        if((msg_len == sizeof(ether_header) + sizeof(arphdr) + (20)) && (ether_type == ETHERTYPE_ARP))
        {
            arphdr * arp = (arphdr*) (eth + 1);

            // color eth proto 
            colors[12].c_ = COLOR_YEL;
            colors[13].c_ = COLOR_YEL;
      
            print_hex(buff, msg_len, colors);

            if((ntohs(arp->ar_op)  == ARPOP_REQUEST) &&
               (ntohs(arp->ar_hrd) == ARPHRD_ETHER)  &&
               (ntohs(arp->ar_pro) == ETHERTYPE_IP)  &&
               (arp->ar_hln        == ETH_ALEN)      &&
               (arp->ar_pln        == 4))
            {
                struct arp_ipv4_req_ {
                    ether_addr src_hw;
                    in_addr           src_ip;

                    ether_addr tar_hw;
                    in_addr           tar_ip;
                } __attribute__((packed)) * arp_req = (arp_ipv4_req_ *) (arp + 1);
#ifdef DEBUG
                printf(COLOR_YEL "in  ETH ARP:");
                printf("t_hw [%s]",   ether_ntoa(&arp_req->tar_hw));
                printf(", s_hw [%s]", ether_ntoa(&arp_req->src_hw));

                printf(", s_ip [%s]", inet_ntoa(arp_req->src_ip));
                printf(", t_ip [%s]", inet_ntoa(arp_req->tar_ip));
                printf("\n" COLOR_NRM);
#endif

                // check ip target
                // again some neighbor manager service could be consulted to avoid sending an arp over the air
                if(is_my_nbr(arp_req->tar_ip.s_addr, tunId))
                  {
                    // swap src/target ip addrs
                    const in_addr tmp_ip = arp_req->tar_ip;
                    arp_req->tar_ip = arp_req->src_ip;
                    arp_req->src_ip = tmp_ip;

                    // swap src/target hw addrs
                    memcpy(&arp_req->tar_hw, &arp_req->src_hw,  ETH_ALEN);
                    memcpy(&arp_req->src_hw, ether_aton_r(fmt_str(fauxHWfmt, str1, sizeof(str1), tunId), &eth1), ETH_ALEN); // faux nbr
            
                    // set as reply   
                    arp->ar_op = htons(ARPOP_REPLY);

#ifdef DEBUG
                    printf(COLOR_YEL "out ETH ARP:");
                    printf("t_hw [%s]",   ether_ntoa(&arp_req->tar_hw));
                    printf(", s_hw [%s]", ether_ntoa(&arp_req->src_hw));

                    printf(", s_ip [%s]", inet_ntoa(arp_req->src_ip));
                    printf(", t_ip [%s]", inet_ntoa(arp_req->tar_ip));
                    printf("\n" COLOR_NRM);
#endif
                    // return complete arp reply
                    bounce_len = msg_len;
                 }
             }
        }
        // sanity check for eth/ipv4
        else if((msg_len > sizeof(iphdr)) && (ether_type == ETHERTYPE_IP))
        {
            iphdr * ip = (iphdr*) (eth + 1);

            const size_t iphl = ip->ihl << 2;       // iphdr len may vary
            const size_t iptl = ntohs(ip->tot_len);

            // ip type and proto
            colors[14].c_ = COLOR_GRN;
            colors[23].c_ = COLOR_GRN;

            print_hex(buff, msg_len, colors);
 
            if(csum16(ip, iphl) == 0xffff)
             {
                switch(ip->protocol)
                 {
                    case IPPROTO_ICMP:
                     {
                       icmphdr * icmp = (icmphdr *) (buff + sizeof(ether_header) + iphl);

                       const size_t icmplen = iptl - iphl;

                       if(csum16(icmp, icmplen) == 0xffff)
                        {
                           if(icmp->type == ICMP_ECHO)
                             {
#ifdef DEBUG
                               if(icmplen >= (sizeof(icmphdr) + sizeof(timeval)))
                                {
                                  // see man ping for timestamp position
                                  struct ts_ {
                                    timeval tv;
                                  } __attribute__((packed))* ts = (ts_*) (icmp + 1);
                                  printf("ETH IPv4 ICMP ECHO_REQ seq %hu, ts %ld:%06ld\n", 
                                         ntohs(icmp->un.echo.sequence),
                                         htole64(ts->tv.tv_sec), htole64(ts->tv.tv_usec));
                                }
#endif
                               // again check ip dst is our faux/known nbr, just for fun, normally let these go ota
                               if(is_my_nbr(ip->daddr, tunId))
                                {
                                  // turn into echo reply
                                  icmp->type = ICMP_ECHOREPLY;

                                  // icmp checksum
                                  icmp->checksum = 0;
                                  icmp->checksum = ~csum16(icmp, icmplen);

                                  // swap ip srd/dst
                                  const in_addr_t tmp_ip = ip->saddr;
                                  ip->saddr = ip->daddr;
                                  ip->daddr = tmp_ip;
 
                                  // ip checksum
                                  ip->check = 0;
                                  ip->check = ~csum16(ip, iphl);

                                  bounce_len = msg_len;
                               }
                            }
                        }
                       else
                        {
                           printf(COLOR_RED "ETH IPv4 ICMP: bad chksum\n" COLOR_NRM);
                        }
                     }
                    break;

                    case IPPROTO_UDP:
                     {
                        auto udp = (udphdr *) (buff + sizeof(ether_header) + iphl);

                        // XXX TODO check for actual rip header, this should do for now
                        if((htons(udp->source) == ripPortNum) && 
                           (htons(udp->dest)   == ripPortNum))
                         {
                           // forged frame using existing buffer
                           return build_rip_frame(buff, buff_len, tunId);
                         }
                     }
                    break;
                 }
             }
            else
             {
               printf(COLOR_RED "ETH IPv4: bad chksum\n" COLOR_NRM);
             }
        }

      // something to send back
      if(bounce_len > 0)
       {
         // must swap eth src/dst
         memcpy(&eth->ether_dhost, &eth->ether_shost, ETH_ALEN);
         memcpy(&eth->ether_shost, ether_aton_r(fmt_str(fauxHWfmt, str1, sizeof(str1), tunId), &eth1), ETH_ALEN); // faux nbr
       }

    }

   return bounce_len;
}
