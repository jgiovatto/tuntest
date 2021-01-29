// jgiovatto@adjacentlink.com
// Jan 29, 2021
// tuntap wrapper



#include <arpa/inet.h>

#include <net/if.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <linux/if_tun.h>

#include "tuntap.h"


/*
 * this lookup is in host byte order
 */
unsigned long NETMASK[33] =
{
    0x00000000,
    0x80000000, 0xC0000000, 0xE0000000, 0xF0000000,
    0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000,
    0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000,
    0xFFF80000, 0xFFFC0000, 0xFFFE0000, 0xFFFF0000,
    0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
    0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00,
    0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0,
    0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF
};

/*
 * Create device node: mknod /dev/net/tun c 10 200 Add following line to
 * the /etc/modules.conf: alias char-major-10-200 tun Run: depmod -a
 * Driver will be automatically loaded when application access
 * /dev/net/tun.
 */

TunTap::TunTap() :
    i_tunfd_{-1},
    i_ctrl_sock_{-1}
{ }

TunTap::~TunTap()
{
    close();
}

int
TunTap::open(const char *path, const char *dev, int flags)
{
    if((i_ctrl_sock_ = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        return -1;
    }

    i_tunfd_ = ::open(path, O_RDWR);

    if(i_tunfd_ < 0)
    {
        perror("tun open");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_flags = flags;

    if(ioctl(i_tunfd_, TUNSETIFF, &ifr) < 0)
    {
        perror("tun ioctl");
        return -1;
    }
    else
    {
        s_devname_ = dev;
    }

    return i_tunfd_;
}


int TunTap::set_blocking(bool b_blocking)
{
    int flags = 0;

    if(fcntl(i_tunfd_, F_GETFL, &flags) < 0)
    {
        perror("fcntl");
        return -1;
    }

    if(! b_blocking)
    {
        flags |= O_NONBLOCK;

        if(fcntl(i_tunfd_, F_SETFL, flags) < 0)
        {
            perror("fcntl");
            return -1;
        }
    }
    else
    {
        flags &= ~O_NONBLOCK;

        if(fcntl(i_tunfd_, F_SETFL, flags) < 0)
        {
            perror("fcntl");
            return -1;
        }
    }

    return 0;
}



int TunTap::close()
{
    if(i_tunfd_ >= 0)
    {
        ::close(i_tunfd_);
        i_tunfd_ = -1;
    }

    if(i_ctrl_sock_ >= 0)
    {
        ::close(i_ctrl_sock_);
        i_ctrl_sock_ = -1;
    }

    return 0;
}


int TunTap::activate(bool up, bool arp)
{
    int flags = IFF_UP;

    if(! arp)
    {
        flags |= IFF_NOARP;
    }

    if(up == true)
    {
        return set_flags_(flags, 1);
    }
    else
    {
        return set_flags_(flags, -1);
    }
}


int TunTap::set_flags_(int newflags, int cmd)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, s_devname_.c_str(), IFNAMSIZ - 1);

    // add
    if(cmd > 0)
    {
        ifr.ifr_flags = (get_flags_() | newflags);
    }
    // del
    else if(cmd < 0)
    {
        ifr.ifr_flags = (get_flags_() & ~newflags);
    }
    // set
    else
    {
        ifr.ifr_flags = newflags;
    }

    if(i_ctrl_sock_ >= 0)
    {
        if(ioctl(i_ctrl_sock_, SIOCSIFFLAGS, &ifr) < 0)
        {
            perror("ioctl");
            return -1;
        }
    }
    else
    {
        return -1;
    }

    return 0;
}

int TunTap::get_flags_()
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, s_devname_.c_str(), IFNAMSIZ - 1);

    if(ioctl(i_ctrl_sock_, SIOCGIFFLAGS, &ifr) < 0)
    {
        perror("ioctl");
        return -1;
    }

    return ifr.ifr_flags;
}


int TunTap::set_ip_address(uint32_t addr, size_t masklen)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, s_devname_.c_str(), IFNAMSIZ - 1);

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = addr;

    // set address
    if(ioctl(i_ctrl_sock_, SIOCSIFADDR, &ifr) < 0)
    {
        perror("ioctl");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, s_devname_.c_str(), IFNAMSIZ - 1);

    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = masklen <= 32 ? htonl(NETMASK[masklen]) : 0;

    // set mask
    if(ioctl(i_ctrl_sock_, SIOCSIFNETMASK, &ifr) < 0)
    {
        perror("ioctl");
        return -1;
    }

    return 0;
}

int TunTap::set_hw_address(const struct ether_addr * addr)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, s_devname_.c_str(), IFNAMSIZ - 1);

    memcpy(ifr.ifr_hwaddr.sa_data, addr, 6);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

    // set address
    if(ioctl(i_ctrl_sock_, SIOCSIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        return -1;
    }

    return 0;
}


int TunTap::writev(const struct iovec *iov, size_t num)
{
    const int result = ::writev(i_tunfd_, iov, num);

    if(result < 0)
    {
        perror("writev");
    }

    return result;
}


int TunTap::write(void *buf, size_t len)
{
    const int result = ::write(i_tunfd_, buf, len);

    if(result < 0)
    {
        perror("write");
    }

    return result;
}


int TunTap::readv(struct iovec *iov, size_t num)
{
    const int result = ::read(i_tunfd_, iov, num);

    if(result < 0)
    {
        if(errno != EAGAIN)
        {
            perror("readv");
        }
    }

    return result;
}


int TunTap::read(void *buf, size_t len)
{
    const int result = ::read(i_tunfd_, buf, len);

    if(result < 0)
    {
        if(errno != EAGAIN)
        {
            perror("read");
        }
    }

    return result;
}


