// jgiovatto@adjacentlink.com
// Jan 29, 2021
//
// purpose to spoof rip/icmp/arp frames for radio networks that do
// their own neighbor discovery
//
// this application will proxy for a faux neighbor number 99
// ping/arping 172.16.2.99 or 172.16.2.99
//
// PING 172.16.2.99 (172.16.2.99) 56(84) bytes of data.
// 64 bytes from 172.16.2.99: icmp_seq=1 ttl=64 time=1.16 ms
// 64 bytes from 172.16.2.99: icmp_seq=2 ttl=64 time=0.785 ms
// 64 bytes from 172.16.2.99: icmp_seq=3 ttl=64 time=0.728 ms
// 64 bytes from 172.16.2.99: icmp_seq=4 ttl=64 time=0.803 ms
//
// ARPING 172.16.2.99 from 172.16.2.1 tuntap2
// Unicast reply from 172.16.2.99 [02:02:00:00:02:63]  1.127ms
// Unicast reply from 172.16.2.99 [02:02:00:00:02:63]  1.243ms
// Unicast reply from 172.16.2.99 [02:02:00:00:02:63]  1.224ms
// Unicast reply from 172.16.2.99 [02:02:00:00:02:63]  1.273ms
//

// running zebra/rip
// may need to pop open the new interface so zebra/rip can recv our msgs
// sudo iptables -I INPUT -i tuntap1 -j ACCEPT
// sudo iptables -I INPUT -i tuntap2 -j ACCEPT
//
//  see example config files within this project conf dir
//
//
//  |                                         | ------   local IP stack   -----  |  
//  |                                               |-----  RIPv2  ----|
//  |  faux rmt net    faux1 nbr              tuntap1            tuntap2                faux2 nbr          faux rmt net
//  |  10.1.1.0/24 --- 172.16.1.99            172.16.1.1/24      172.16.2.1/24          172.16.2.99 ------ 10.2.1.0/24
//  |                  02:02:00:00:01:63 ---- 02:02:00:00:01:01  02:02:00:00:02:01 ---- 02:02:00:00:02:63
//  |                                   
//                               
// tuntap1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
//       inet 172.16.1.1  netmask 255.255.255.0  broadcast 172.16.1.255
//       inet6 fe80::2:ff:fe00:101  prefixlen 64  scopeid 0x20<link>
//       ether 02:02:00:00:01:01  txqueuelen 1000  (Ethernet)
//
// tuntap2: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
//        inet 172.16.2.1  netmask 255.255.255.0  broadcast 172.16.2.255
//        inet6 fe80::2:ff:fe00:201  prefixlen 64  scopeid 0x20<link>
//        ether 02:02:00:00:02:01  txqueuelen 1000  (Ethernet)
//
// Kernel IP routing table after running zebra/rip
// Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
// 10.1.1.0        172.16.1.99     255.255.255.0   UG    20     0        0 tuntap1
// 10.2.1.0        172.16.2.99     255.255.255.0   UG    20     0        0 tuntap2
// 172.16.1.0	   0.0.0.0         255.255.255.0   U     0      0        0 tuntap1
// 172.16.2.0  	   0.0.0.0         255.255.255.0   U     0      0        0 tuntap2
//


#include "tuntap.h"
#include "netutils.h"
#include "types.h"
#include "dvmrp.h"

#include <stdio.h>
#include <errno.h>
#include <signal.h>

#include <sys/select.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/igmp.h>


volatile bool bRunning = true;

static void bye(const char *msg)
{
    perror(msg);
    exit(0);
}

static void sig_handle(int sig)
{
  if(sig == SIGINT || sig == SIGTERM)
    {
      printf("caught term signal\n");

      bRunning = false;
    }
}

static inline uint8_t idx_to_tunid(size_t idx)
 {
    return idx + 1;
 }

int main(int, char *[])
{
    signal(SIGINT,  sig_handle);
    signal(SIGTERM, sig_handle);

    bool bIgmpQuery   = false;
    bool bDvmrpReport = true;

    // try 2, though 1 would do
    const size_t NUM_TUN_TAP = 2;

    TunTap tunTap[NUM_TUN_TAP];

    int fd_max = -1;

    fd_set read_fds;

    FD_ZERO(&read_fds);

    for(uint8_t idx = 0; idx < NUM_TUN_TAP; ++idx)
     {
       const auto tunId = idx_to_tunid(idx);

       // open device
       if(tunTap[idx].open("/dev/net/tun", 
            fmt_str(tunTapfmt, str1, sizeof(str1), tunId), 
              IFF_TAP | IFF_NO_PI) < 0)
        {
           bye("tun open");
        }

       // set ip addr
       if(tunTap[idx].set_ip_address(inet_addr(
             fmt_str(localIPfmt, str1, sizeof(str1), tunId)), 24) < 0)
        {
           bye("tun set ip");
        }

       // set hw addr
       if(tunTap[idx].set_hw_address(ether_aton(
             fmt_str(localHWfmt, str1, sizeof(str1), tunId))) < 0)
        {
           bye("tun set ip");
        }

       // set up, arp on
       if(tunTap[idx].activate(true, true) < 0)
        {
           bye("tun activate");
        }

       // set blocking
       if(tunTap[idx].set_blocking(true) < 0)
        {
           bye("tun setblocking");
        }

       const int fd = tunTap[idx].get_handle();

       // add to read fd set
       FD_SET(fd, &read_fds);

       // get max fd
       fd_max = std::max(fd_max, fd);
     }

    while(bRunning)
     {
       // single threaded so one buffer for all i/o
       char buff[2048] = {0};

       // set our read fds
       fd_set rfds = read_fds;
     
       // wait for 1 sec 
       timeval tv = {1, 0};
 
       int num_ready = select(fd_max + 1, &rfds, nullptr, nullptr, &tv);

       while((num_ready > 0) && bRunning)
        {
          for(uint8_t idx = 0; idx < NUM_TUN_TAP; ++idx)
           {
              const int fd = tunTap[idx].get_handle();

              if(FD_ISSET(fd, &rfds))
               {
                 const int num_read = tunTap[idx].read(buff, sizeof(buff));

                 if(num_read > 0) 
                  {
                     const int num_write = parse_frame(buff, sizeof(buff), num_read, idx_to_tunid(idx));

                     // bounce something back
                     if(num_write > 0)
                      {
                        tunTap[idx].write(buff, num_write);
                      }
                  }
                 else
                  {
                    perror("tuntap.read");
                  }

                  --num_ready;
                  FD_CLR(fd, &rfds);
               }
           }  
        }

       // periodic timer
       if((time(NULL) % 10 == 0) && bRunning)
        {
           // alternative to using a contiguous buffer
           // scatter/gather i/o is helpful for
           // buffer boundry alignment issues
           // that may arise due to the 14 byte ether header.
 
           if(bIgmpQuery)
            {
              // the are common
              ether_header eth;
              iphdr        ip;
              uint32_t     opt;

              // build an igmp query for each interface
              for(uint8_t idx = 0; idx < NUM_TUN_TAP; ++idx)
               {
                  igmp igmp;
                  set_igmp_query(&eth, &ip, &opt, &igmp, idx + 1);

                  // order is important here
                  const iovec iov[4] = {{(void *) &eth,  sizeof(eth)},   // eth hdr
                                       {(void *)  &ip,   sizeof(ip)},    // ip hdr
                                       {(void *)  &opt,  sizeof(opt)},   // ip option
                                       {(void *)  &igmp, sizeof(igmp)}}; // igmp hdr

                  tunTap[idx].writev(iov, 4);

                 // eventually we should see some igmpv2 activity
                 //
                 // sudo tcpdump -i tuntap1 -vvv -n igmp
                 // IP (tos 0xc0, ttl 1, id 42136, offset 0, flags [none], proto IGMP (2), length 32, options (RA))
                 // 172.16.1.99 > 224.0.0.1: igmp query v2
                 //
                 // IP (tos 0xc0, ttl 1, id 0, offset 0, flags [DF], proto IGMP (2), length 32, options (RA))
                 // 172.16.1.1 > 224.0.0.251: igmp v2 report 224.0.0.251
               }
          }

          if(bDvmrpReport)
           {
             // build a dvmrp probe for each interface
             for(uint8_t idx = 0; idx < NUM_TUN_TAP; ++idx)
              {
                const auto tunId = idx_to_tunid(idx);

                 { // dvmrp probe
                   const uint32_t genid = 1;

                   dvmrpneighbors_t nbrs{dvmrpneighbor_t{inet_addr(fmt_str(rmtNWfmt,   str1, sizeof(str1), tunId, idx, 1))}, // faux rmt nbr
                                         dvmrpneighbor_t{inet_addr(fmt_str(localIPfmt, str1, sizeof(str1), tunId))}};      // lcl nbr


                   DVMRP_Probe dvmrp_probe{ether_aton(fmt_str(fauxHWfmt, str1, sizeof(str1), tunId)), // faux nbr hw
                                           inet_addr (fmt_str(fauxIPfmt, str1, sizeof(str1), tunId)), // faux nbr ip
                                           genid,                                                     // gen id
                                           nbrs};                                                     // faux rmt nbr
 
                   tunTap[idx].writev(dvmrp_probe.getIOV().first, dvmrp_probe.getIOV().second);
                 }


                 { // dvmrp report
                   dvmrproutes_t routes{ dvmrproute_t{{0xFF, 0xFF, 0X00},   // 24 bit netmask
                                                      {10, tunId, 1},       // faux rmt nbr
                                                       0x81}};              // metric

                   DVMRP_Report dvmrp_report{ether_aton(fmt_str(fauxHWfmt, str1, sizeof(str1), tunId)), // faux nbr hw
                                             inet_addr (fmt_str(fauxIPfmt, str1, sizeof(str1), tunId)), // faux nbr ip
                                             routes};                                                   // routes

                   tunTap[idx].writev(dvmrp_report.getIOV().first, dvmrp_report.getIOV().second);
                 }
            }

           // below are some tcpdum captures 
           // sudo tcpdump -i tuntap1  -vvv igmp -n
           // IP (tos 0xc0, ttl 1, id 14946, offset 0, flags [none], proto IGMP (2), length 44, options (RA))
           //     172.16.1.99 > 224.0.0.4: igmp dvmrp Probe
           // 	genid 1
           // 	neighbor 10.1.0.1
           // 	neighbor 172.16.1.1

           // IP (tos 0xc0, ttl 1, id 14946, offset 0, flags [none], proto IGMP (2), length 39, options (RA))
           //     172.16.1.99 > 224.0.0.4: igmp dvmrp Report
           // 	Mask 255.255.255.0
           // 	  10.1.1.0 metric 1

           // IP (tos 0xc0, ttl 1, id 58682, offset 0, flags [none], proto IGMP (2), length 40, options (RA))
           //     172.16.1.1 > 224.0.0.4: igmp dvmrp Probe
           // 	genid 2234647808
           // 	neighbor 172.16.1.99

           // IP (tos 0xc0, ttl 1, id 58887, offset 0, flags [none], proto IGMP (2), length 47, options (RA))
           //     172.16.1.1 > 224.0.0.4: igmp dvmrp Report
           // 	Mask 255.255.255.0
           // 	  10.1.1.0 metric 34
           // 	  10.2.1.0 metric 2
           // 	  172.16.2.0 metric 1
         }
      }
   }

   printf("bye \n" COLOR_NRM);

    return (0);
}
