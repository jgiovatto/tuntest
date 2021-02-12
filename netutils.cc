
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

#include <net/if_arp.h>

#include "types.h"
#include "defs.h"
#include "netutils.h"

// string fmt helper
char str1[64];

static bool is_my_nbr(const in_addr_t nbr, const uint8_t tunId)
{
   return inet_addr(fmt_str(fauxIPfmt, str1, sizeof(str1), tunId)) == nbr;
}


const char * fmt_str(const char * fmt, 
                     char * const str, 
                     const size_t strlen, 
                     const uint8_t val)
{
    memset(str, 0x0, strlen);
    snprintf(str, strlen - 1, fmt, val);

    return str;
}

const char * fmt_str2(const char * fmt, 
                      char * const str, 
                      const size_t strlen, 
                      const uint8_t val1,
                      const uint8_t val2)
{
    memset(str, 0x0, strlen);
    snprintf(str, strlen - 1, fmt, val1, val2);

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


uint16_t csum16(const void *buff, uint16_t len, uint16_t carry)
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


uint16_t csum16v(const struct iovec * iov, const size_t iovn)
{
  uint16_t sum = 0;

  for(size_t n = 0; n < iovn; ++n)
   {
     sum = csum16(iov[n].iov_base, iov[n].iov_len, sum);
   }

  return sum;
}



size_t build_rip_frame(char * buff, size_t buff_len, uint8_t tunId)
{
   Colors colors(buff_len, Color(COLOR_NRM));

   memset(buff, 0x0, buff_len);

   static uint8_t ripcnt = 0;

   const size_t eth_offset = 0;
   const size_t ip_offset  = eth_offset + sizeof(ether_header);
   const size_t udp_offset = ip_offset  + sizeof(iphdr);

   auto eth = (struct ether_header *) (buff + eth_offset);
   auto ip  = (struct iphdr *)        (buff + ip_offset);
   auto udp = (struct udphdr *)       (buff + udp_offset);

   // rip starts after udp header
   uint16_t udplen = sizeof(*udp);

   // first msg is rip request
   if(ripcnt++ == 0)
    {
      ripreqmsg_t ripmsg;

      // copy riphdr into buff offset ((eth + ip) + udplen)
      memcpy(buff + udp_offset + udplen, &ripmsg, sizeof(ripmsg));

      udplen += sizeof(ripmsg);
    }
   else
    {
      // rip respnse
      riphdr_t riphdr(2);

      // copy riphdr into buff offset ((eth + ip) + udplen)
      memcpy(buff + udp_offset + udplen, &riphdr, sizeof(riphdr));

      udplen += sizeof(riphdr);

      // construct for generating N rip entries
      // these could be 'fetched' from some neighbor manager service and
      // populated into the rip msg here
      for(uint8_t idx = 1; idx <= 5; ++idx)
       {
          const ripentry_t ripentry {fmt_str2(rmtNWfmt, str1, sizeof(str1), tunId, idx), // net
                                     rmtNMfmt,                                           // mask
                                     10};                                                // metric

          // copy ripentry into buff offset ((eth + ip) + udplen)
          memcpy(buff + udp_offset + udplen, &ripentry, sizeof(ripentry));
          
          udplen += sizeof(ripentry_t);
       }
    }

   // set eth hdr
   memcpy(&eth->ether_dhost, ether_aton(ripHWstr), ETH_ALEN);                                      // ripv2
   memcpy(&eth->ether_shost, ether_aton(fmt_str(fauxHWfmt, str1, sizeof(str1), tunId)), ETH_ALEN); // faux nbr
   eth->ether_type = htons(ETHERTYPE_IP);

   // color eth porto
   colors[12].c_ = COLOR_YEL;
   colors[13].c_ = COLOR_YEL;

   // set ip hdr
   ip->version  = 4;
   ip->ihl      = 5;
   ip->tos      = 0;
   ip->tot_len  = htons((ip->ihl << 2) + udplen);
   ip->id       = htons(0);
   ip->frag_off = htons(0);
   ip->ttl      = 1;
   ip->protocol = IPPROTO_UDP;
   ip->check    = htons(0);
   ip->saddr    = inet_addr(fmt_str(fauxIPfmt, str1, sizeof(str1), tunId));  // faux nbr ip
   ip->daddr    = inet_addr(ripIPstr);                                       // ripv2
   // set ip csum
   ip->check = ~csum16(ip, ip->ihl << 2);

   // ip type and proto
   colors[ip_offset].c_     = COLOR_GRN;
   colors[ip_offset + 9].c_ = COLOR_GRN;
 
   // set udp hdr
   udp->source = htons(ripPortNum); // rip port
   udp->dest   = htons(ripPortNum); // rip port
   udp->len    = htons(udplen);
   udp->check  = 0;

   // udp pseudo sum
   struct {
     uint32_t src, dst;
     uint8_t  res, proto;
     uint16_t len;
   } __attribute__((packed)) psum = {ip->saddr,
                                     ip->daddr,
                                     0,
                                     ip->protocol,
                                     htons(udplen)};

   const struct iovec chkv[2] = {{(void*)&psum,  sizeof(psum)}, 
                                 {(void*)udp,    udplen}};

   // set udp csum
   udp->check = ~csum16v(chkv, 2);

   const size_t result = udp_offset + udplen;

   print_hex(buff, result, colors);

   return result;
}



int parse_frame(char *buff, size_t buff_len, size_t msg_len, uint8_t tunId)
{
    Colors colors(msg_len, Color(COLOR_NRM));

    printf("%s tunId %hhu\n", __func__, tunId);

    int bounce_len = 0;

    if(msg_len > sizeof(ether_header))
    {
        struct ether_header * eth = (struct ether_header *) buff;

        const uint16_t ether_type = htons(eth->ether_type);

        // sanity check ethhdr + arphdr + 2(eth/ipv4) and ether_type_arp
        if((msg_len == sizeof(struct ether_header) + sizeof(struct arphdr) + (20)) && (ether_type == ETHERTYPE_ARP))
        {
            struct arphdr * arp = (struct arphdr*) (eth + 1);

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
                    struct ether_addr src_hw;
                    in_addr           src_ip;

                    struct ether_addr tar_hw;
                    in_addr           tar_ip;
                } __attribute__((packed)) * arp_req = (struct arp_ipv4_req_ *) (arp + 1);
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
                    memcpy(&arp_req->src_hw, ether_aton(fmt_str(fauxHWfmt, str1, sizeof(str1), tunId)), ETH_ALEN); // faux nbr
            
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
        else if((msg_len > sizeof(struct iphdr)) && (ether_type == ETHERTYPE_IP))
        {
            struct iphdr * ip = (struct iphdr*) (eth + 1);

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
                       struct icmphdr * icmp = (struct icmphdr *) (buff + sizeof(ether_header) + iphl);

                       const size_t icmplen = iptl - iphl;

                       if(csum16(icmp, icmplen) == 0xffff)
                        {
                           if(icmp->type == ICMP_ECHO)
                             {
#ifdef DEBUG
                               if(icmplen >= (sizeof(icmphdr) + sizeof(struct timeval)))
                                {
                                  // see man ping for timestamp position
                                  struct ts_ {
                                    struct timeval tv;
                                  } __attribute__((packed))* ts = (struct ts_*) (icmp + 1);
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
                        auto udp = (struct udphdr *) (buff + sizeof(ether_header) + iphl);

                        // XXX TODO check for actual rip header, this should do for now
                        if((htons(udp->source) == ripPortNum) && 
                           (htons(udp->dest)   == ripPortNum))
                         {
                           // forged frame all ready send it now
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
         memcpy(&eth->ether_shost, ether_aton(fmt_str(fauxHWfmt, str1, sizeof(str1), tunId)), ETH_ALEN); // faux nbr
       }

    }

   return bounce_len;
}
