// jgiovatto@adjacentlink.com
// Jan 29, 2021
// tuntest tool to play with ip/arp frames

// try arping 172.16.1.99 and ping 172.16.1.99

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/time.h>

#include <linux/if_tun.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#include <net/ethernet.h>
#include <net/if_arp.h>

#include "tuntap.h"

#define COLOR_NRM "\033[0m"
#define COLOR_BLE "\033[0;34m"
#define COLOR_GRN "\033[0;32m"
#define COLOR_CYN "\033[0;36m"
#define COLOR_RED "\033[0;31m"
#define COLOR_YEL "\033[1;33m"

bool bRunning = true;

void die(const char *msg)
{
    perror(msg);
    exit(0);
}

void signal_handler(int sig_num)
{
    switch (sig_num)
    {
    case SIGQUIT:
    case SIGTERM:
    case SIGINT:
        bRunning = false;
        sleep(1);
        printf("\n" COLOR_NRM);
        pthread_cancel(0);
        break;
    }
}


void print_hex(const char * buff, size_t bufflen)
{
    size_t linenum = 0;
    int     numrem = bufflen;

    while(numrem > 0)
    {
        char str1[128] = {0};
        char str2[128] = {0};

        size_t pos1 = 0, pos2 = 0;
        for(size_t i = 0; i < 16; ++i)
        {
            // space every 8
            if(i != 0 && i % 8 == 0)
            {
                pos1 += snprintf(str1 + pos1, sizeof(str1) - pos1, "  ");
            }

            // have value
            if(numrem > 0)
            {
                const char val = buff[linenum * 16 + i];

                // as hex
                pos1 += snprintf(str1 + pos1, sizeof(str1) - pos1, "%02hhx ", (uint8_t) val);

                // as printable
                pos2 += snprintf(str2 + pos2, sizeof(str2) - pos2, "%c", isprint(val) ? val : '.');
            }
            else
            {
                // fill the last line
                pos2 += snprintf(str2 + pos2, sizeof(str2) - pos2, " ");
            }

            --numrem;
        }
        printf("%03zu  %s    %s\n", linenum, str2, str1);

        ++linenum;
    }
}


int bounce_frame(char *buff, size_t len)
{
    int result = 0;

    if(len > sizeof(ether_header))
    {
        // make up nbr
        ether_addr faux_nbr;

        memcpy(&faux_nbr, ether_aton("02:02:00:00:00:99"), ETH_ALEN);

        struct ether_header * eth = (struct ether_header *) buff;

        const uint16_t ether_type = htons(eth->ether_type);

        // sanity check for eth arp
        if((len == sizeof(struct ether_header) + sizeof(struct arphdr) + (2 * (ETH_ALEN + 4))) && (ether_type == ETHERTYPE_ARP))
        {
            struct arphdr * arp = (struct arphdr*) (eth + 1);
            
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

                printf(COLOR_YEL "in  eth_type ARP:");
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

                printf(COLOR_YEL "out eth_type ARP:");
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
            struct iphdr * ip = (struct iphdr*) (eth + 1);

            printf(COLOR_GRN "len %zu, eth_type IPv4, proto 0x%hhx\n" COLOR_NRM, len, ip->protocol);

            // XXX TODO reply to icmp
            print_hex(buff, len);
        }


      // something to send back
      if(result > 0)
       {
         // must swap eth src/dst
         memcpy(&eth->ether_dhost, &eth->ether_shost, ETH_ALEN);
         memcpy(&eth->ether_shost, &faux_nbr, ETH_ALEN);
       }
    }

   return result;
}



int main(int, char *[])
{
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    // create tun tap object
    TunTap tunTap;

    // open
    if(tunTap.open("/dev/net/tun", "tuntap0", IFF_TAP | IFF_NO_PI) < 0)
    {
        die("tun open");
    }

    // set ip addr
    if(tunTap.set_ip_address(inet_addr("172.16.1.1"), 24) < 0)
    {
        die("tun set ip");
    }

    // set hw addr
    if(tunTap.set_hw_address(ether_aton("02:02:00:00:00:01")) < 0)
    {
        die("tun set ip");
    }

    // set up, arp on
    if(tunTap.activate(true, true) < 0)
    {
        die("tun activate");
    }

    // set read blocking
    if(tunTap.set_blocking(true) < 0)
    {
        die("tun setblocking");
    }

    while(bRunning)
    {
        char buff[2048] = {0};

        const int num_read = tunTap.read(buff, sizeof(buff));

        if(num_read < 0)
        {
            die("tun read");
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

    return (0);
}


