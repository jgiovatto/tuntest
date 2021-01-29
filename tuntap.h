// jgiovatto@adjacentlink.com
// Jan 29, 2021
// tuntap wrapper

#ifndef __TUNTAP_H_
#define __TUNTAP_H_

#include <string>
#include <sys/uio.h>
#include <netinet/ether.h>

class TunTap
{

public:
    TunTap();

    ~TunTap();

    int open(const char *, const char *, int);

    int close();

    int set_blocking(bool b_blocking);

    int activate(bool up, bool arp);

    int read(void *, size_t);

    int readv(struct iovec *, size_t);

    int write(void *, size_t);

    int writev(const struct iovec *, size_t);

    int set_ip_address(uint32_t, size_t);

    int set_hw_address(const struct ether_addr * addr);

private:
    int i_tunfd_;

    int i_ctrl_sock_;

    std::string s_devname_;

    int set_flags_(int, int action = 0);

    int get_flags_();
};
#endif
