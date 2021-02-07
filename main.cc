// jgiovatto@adjacentlink.com
// Jan 29, 2021
// tuntest tool to play with ip/arp frames

// try arping 172.16.1.99 and ping 172.16.1.99

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/time.h>

#include <linux/if_tun.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

#include <net/ethernet.h>
#include <net/if_arp.h>

#include "tuntap.h"

#define COLOR_NRM "\033[0m"
#define COLOR_BLE "\033[0;34m"
#define COLOR_GRN "\033[0;32m"
#define COLOR_CYN "\033[0;36m"
#define COLOR_RED "\033[0;31m"
#define COLOR_YEL "\033[1;33m"

#define PROTO_ETH COLOR_BLU

#include <vector>

struct Color {
  Color(const char * c) : c_(c) { }

  const char * c_;
};

using Colors = std::vector<Color>;


bool bRunning = true;

void bye(const char *msg)
{
    perror(msg);
    exit(0);
}


void print_hex(const char * buff, size_t bufflen, const Colors & colors)
{
    const  size_t lineLen = 16;

    size_t linenum = 0;
    size_t pos = 0;

    while(pos < bufflen)
    {
        struct Str {
          size_t pos;
          char   buf[128];
          Str() : pos(0), buf{0} { } 
        }s1, s2;

        for(size_t idx = 0; idx < lineLen; ++idx, ++pos)
        {
            if((idx != 0) && (idx % (lineLen / 2) == 0))
            {
                s1.pos += snprintf(s1.buf + s1.pos, sizeof(s1.buf) - s1.pos, " ");
                s2.pos += snprintf(s2.buf + s2.pos, sizeof(s2.buf) - s2.pos, " ");
            }

            // have value
            if(pos < bufflen)
            {
                const char val = buff[pos];

                // as hex
                s1.pos += snprintf(s1.buf + s1.pos, sizeof(s1.buf) - s1.pos, "%s%02hhx ", colors[pos].c_, (uint8_t) val);

                // as printable
                s2.pos += snprintf(s2.buf + s2.pos, sizeof(s2.buf) - s2.pos, "%c", isprint(val) ? val : '.');
            }
            else
            {
                // fill the last line
                s2.pos += snprintf(s2.buf + s2.pos, sizeof(s2.buf) - s2.pos, " ");
            }
        }
        printf("%03zu  %s    %s\n", linenum * lineLen, s2.buf, s1.buf);

        ++linenum;
    }

   printf("\n");
}

uint16_t csum16(const void *buff, uint16_t len)
{
  uint32_t sum = 0;

  uint16_t const * p = (uint16_t const *) buff;

  while(len > 1)
   {
     sum += *p++;
     len -= 2;
   }

  if(len > 0)
   {
     sum += *((uint8_t *) p);
   }

  while(sum >> 16)
   {
     sum = (sum & 0xFFFF) + (sum >> 16);
   }

  return(sum);
}



int bounce_frame(char *buff, size_t len)
{
    int result = 0;

    Colors colors(len, Color(COLOR_NRM));

    if(len > sizeof(ether_header))
    {
        // make up nbr
        ether_addr faux_nbr;

        memcpy(&faux_nbr, ether_aton("02:02:00:00:00:99"), ETH_ALEN);

        struct ether_header * eth = (struct ether_header *) buff;

        const uint16_t ether_type = htons(eth->ether_type);

        colors[12].c_ = COLOR_YEL;
        colors[13].c_ = COLOR_YEL;

        // sanity check for eth arp
        if((len == sizeof(struct ether_header) + sizeof(struct arphdr) + (2 * (ETH_ALEN + 4))) && 
           (ether_type == ETHERTYPE_ARP))
        {
            size_t offset = sizeof(ether_header);

            struct arphdr * arp = (struct arphdr*) (buff + offset);
       
            if((ntohs(arp->ar_op)  == ARPOP_REQUEST) &&
               (ntohs(arp->ar_hrd) == ARPHRD_ETHER)  &&
               (ntohs(arp->ar_pro) == ETHERTYPE_IP)  &&
               (arp->ar_hln        == ETH_ALEN)      &&
               (arp->ar_pln        == 4))
            {
                // eth hdr [[ff ff ff ff ff ff]
                //          [ee 66 e3 bc 9c b7]
                //          [08 06]]
                //
                // arp hdr [[00 01]
                //          [08 00]
                //          [06]
                //          [04]
                //          [00 01]
                //          [02 02 00 00 00 01]  [ac 10 01 01]
                //          [00 00 00 00 00 00]  [ac 10 01 02]]

                struct arp_ipv4_req_
                {
                    struct ether_addr src_hw;
                    in_addr           src_ip;

                    struct ether_addr tar_hw;
                    in_addr           tar_ip;
                } __attribute__((packed)) * arp_req = (struct arp_ipv4_req_ *) (arp + 1);

                printf(COLOR_YEL "in  ETH ARP:");
                printf("t_hw [%s]", ether_ntoa(&arp_req->tar_hw));
                printf(", s_hw [%s]", ether_ntoa(&arp_req->src_hw));
                printf(", s_ip [%s]", inet_ntoa(arp_req->src_ip));
                printf(", t_ip [%s]", inet_ntoa(arp_req->tar_ip));
                printf("\n" COLOR_NRM);

                // swap src/target ip addrs
                const in_addr tmp_ip = arp_req->tar_ip;
                arp_req->tar_ip = arp_req->src_ip;
                arp_req->src_ip = tmp_ip;

                // swap src/target hw addrs
                memcpy(&arp_req->tar_hw, &arp_req->src_hw, ETH_ALEN);
                memcpy(&arp_req->src_hw, &faux_nbr, ETH_ALEN);
            
                // set as reply   
                arp->ar_op = htons(ARPOP_REPLY);

                printf(COLOR_YEL "out ETH ARP:");
                printf("t_hw [%s]", ether_ntoa(&arp_req->tar_hw));
                printf(", s_hw [%s]", ether_ntoa(&arp_req->src_hw));
                printf(", s_ip [%s]", inet_ntoa(arp_req->src_ip));
                printf(", t_ip [%s]", inet_ntoa(arp_req->tar_ip));
                printf("\n" COLOR_NRM);

                // return complete arp reply
                result = len;
            }
        }
        // sanity check for eth ipv4
        else if((len > sizeof(struct iphdr)) && (ether_type == ETHERTYPE_IP))
        {
            size_t offset = sizeof(ether_header);

            struct iphdr * ip = (struct iphdr*) (buff + offset);

            colors[14].c_ = COLOR_GRN;
            colors[23].c_ = COLOR_GRN;
 
            if(csum16(ip, ip->ihl << 2) == 0xffff)
             {
                switch(ip->protocol)
                 {
                    case IPPROTO_ICMP:
                     {
                       offset += (ip->ihl << 2);

                       struct icmphdr * icmp = (struct icmphdr *)(buff + offset);

                       const size_t icmplen = ntohs(ip->tot_len) - (ip->ihl << 2);

                       if(csum16(icmp, icmplen) == 0xffff)
                        {
                           if(icmp->type == ICMP_ECHO)
                             {
                               printf("ETH IPv4 ICMP ECHO_REQ seq %hu\n", ntohs(icmp->un.echo.sequence));

                               // turn into echo reply
                               icmp->type = ICMP_ECHOREPLY;
                               icmp->checksum = 0;
                               icmp->checksum = ~csum16(icmp, icmplen);

                               // swap ip srd/dst
                               const in_addr_t tmp_ip = ip->saddr;
                               ip->saddr = ip->daddr;
                               ip->daddr = tmp_ip;


                               struct
                                {
                                 uint32_t otime;
                                 uint32_t rtime;
                                 uint32_t ttime;
                                } id_ts;


                               ip->check = 0;
                               ip->check = ~csum16(ip, ip->ihl << 2);

                               // XXX TODO check len and timestamps
                               result = len;
                            }
                        }
                       else
                        {
                           printf(COLOR_RED "ETH IPv4 ICMP: bad chksum\n" COLOR_NRM);
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
      if(result > 0)
       {
         // must swap eth src/dst
         memcpy(&eth->ether_dhost, &eth->ether_shost, ETH_ALEN);
         memcpy(&eth->ether_shost, &faux_nbr, ETH_ALEN);
       }

       print_hex(buff, len, colors);
    }


   return result;
}



int main(int, char *[])
{
    // create tun tap object
    TunTap tunTap;

    // open
    if(tunTap.open("/dev/net/tun", "tuntap0", IFF_TAP | IFF_NO_PI) < 0)
    {
        bye("tun open");
    }

    // set ip addr
    if(tunTap.set_ip_address(inet_addr("172.16.1.1"), 24) < 0)
    {
        bye("tun set ip");
    }

    // set hw addr
    if(tunTap.set_hw_address(ether_aton("02:02:00:00:00:01")) < 0)
    {
        bye("tun set ip");
    }

    // set up, arp on
    if(tunTap.activate(true, true) < 0)
    {
        bye("tun activate");
    }

    // set read blocking
    if(tunTap.set_blocking(true) < 0)
    {
        bye("tun setblocking");
    }

    while(bRunning)
    {
        char buff[2048] = {0};

        const int num_read = tunTap.read(buff, sizeof(buff));

        if(num_read < 0)
        {
            bye("tun read");
        }
        else
        {
            const int num_write = bounce_frame(buff, num_read);

            if(num_write > 0)
             {
               tunTap.write(buff, num_write);
             }
        }
    }

    printf("bye \n" COLOR_NRM);

    return (0);
}


