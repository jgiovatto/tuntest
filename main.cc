// jgiovatto@adjacentlink.com
// Jan 29, 2021
// tuntest tool to play with ip/arp frames


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


void parse_frame(char *buff, size_t len)
{
    if(len > sizeof(ether_header))
    {
        struct ether_header * eth = (struct ether_header *) buff;

        const uint16_t ether_type = htons(eth->ether_type);

        if(ether_type == ETHERTYPE_ARP)
        {

            struct arphdr * arp = (struct arphdr*) (eth + 1);

            if((ntohs(arp->ar_hrd) == ARPHRD_ETHER) &&
                    (ntohs(arp->ar_pro) == ETHERTYPE_IP) &&
                    (arp->ar_hln        == ETH_ALEN)     &&
                    (arp->ar_pln        == 4)            &&
                    (len                == sizeof(struct ether_header) +
                     sizeof(struct arphdr)       +
                     (2 * (ETH_ALEN + 4))))

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
                //          [ee 11 22 33 44 55]  [ac 10 01 01]
                //          [00 00 00 00 00 00]  [ac 10 01 02]]

                struct arp_ipv4_req_
                {
                    struct ether_addr sha;
                    in_addr           sip;
                    struct ether_addr tha;
                    in_addr           tip;
                } __attribute__((packed)) * arpr = (struct arp_ipv4_req_ *) (arp + 1);

                printf(COLOR_YEL "eth_type ARP:");
                printf(", thw [%s]", ether_ntoa(&arpr->tha));
                printf(", shw [%s]", ether_ntoa(&arpr->sha));
                printf(", sip [%s]", inet_ntoa(arpr->sip));
                printf(", tip [%s]", inet_ntoa(arpr->tip));
                printf("\n" COLOR_NRM);
            }
        }
        else if(ether_type == ETHERTYPE_IP)
        {
            printf(COLOR_GRN "len %zu, eth_type IPv4\n" COLOR_NRM, len);

            print_hex(buff, len);
        }

    }
}



int main(int, char *[])
{
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    const int mode = IFF_TAP | IFF_NO_PI;

    TunTap tunTap;

    // create tun tap
    const auto fd = tunTap.open("/dev/net/tun", "tuntap0", mode);

    // open
    if(fd < 0)
    {
        die("tun open");
    }

    // set ip addr
    if(tunTap.set_ip_address(inet_addr("172.16.1.1"), 24) < 0)
    {
        die("tun set ip");
    }

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

        const int result = tunTap.read(buff, sizeof(buff));

        if(result < 0)
        {
            die("tun read");
        }
        else
        {
            parse_frame(buff, result);
        }
    }

    return (0);
}


