// l2_bcast.cpp
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static uint16_t csum16(const void* data, size_t len) {
    uint32_t sum = 0;
    const uint16_t* p = (const uint16_t*)data;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *(const uint8_t*)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t udp_checksum(const iphdr* ip, const udphdr* udp, const uint8_t* payload, size_t payload_len) {
    // pseudo header
    struct Pseudo {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t udp_len;
    } ph{};
    ph.saddr = ip->saddr;
    ph.daddr = ip->daddr;
    ph.zero  = 0;
    ph.proto = IPPROTO_UDP;
    ph.udp_len = udp->len;

    uint32_t sum = 0;
    auto add = [&](const void* d, size_t l) {
        const uint16_t* p = (const uint16_t*)d;
        while (l > 1) { sum += *p++; l -= 2; }
        if (l == 1) sum += *(const uint8_t*)p;
    };

    add(&ph, sizeof(ph));
    add(udp, sizeof(udphdr));
    add(payload, payload_len);

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t out = (uint16_t)(~sum);
    return out ? out : 0xFFFF; // checksum 0 表示不用，這裡避免 0
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: sudo " << argv[0] << " <iface> <dst-ip> <dst-port>\n";
        return 1;
    }
    std::string iface = argv[1];
    std::string dst_ip_str = argv[2];
    int dst_port = std::stoi(argv[3]);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket(AF_PACKET)"); return 1; }

    // 取得介面 index / MAC / IP
    ifreq ifr{};
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return 1; }
    uint8_t src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { perror("SIOCGIFADDR"); return 1; }
    auto* sin = (sockaddr_in*)&ifr.ifr_addr;
    uint32_t src_ip = sin->sin_addr.s_addr;

    uint32_t dst_ip;
    if (inet_pton(AF_INET, dst_ip_str.c_str(), &dst_ip) != 1) {
        std::cerr << "Bad dst ip\n"; return 1;
    }

    // 目標 L2：broadcast MAC
    uint8_t dst_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

    // payload
    std::vector<uint8_t> payload(900, 'A');

    // frame buffer: eth + ip + udp + payload
    std::vector<uint8_t> frame(sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr) + payload.size());
    auto* eth = (ether_header*)frame.data();
    memcpy(eth->ether_dhost, dst_mac, 6);
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    auto* ip = (iphdr*)(frame.data() + sizeof(ether_header));
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(iphdr) + sizeof(udphdr) + payload.size());
    ip->id = htons(0x1234);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
    ip->check = csum16(ip, sizeof(iphdr));

    auto* udp = (udphdr*)(frame.data() + sizeof(ether_header) + sizeof(iphdr));
    udp->source = htons(1234);
    udp->dest   = htons(dst_port);
    udp->len    = htons(sizeof(udphdr) + payload.size());
    udp->check  = 0;

    uint8_t* pl = frame.data() + sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr);
    memcpy(pl, payload.data(), payload.size());
    udp->check = udp_checksum(ip, udp, pl, payload.size());

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    memcpy(addr.sll_addr, dst_mac, 6);

    int count = 0;
    while (true) {
        std::cout << "Press Enter to send L2 broadcast... ";
        std::cin.get();
        ssize_t n = sendto(fd, frame.data(), frame.size(), 0, (sockaddr*)&addr, sizeof(addr));
        if (n < 0) perror("sendto");
        else std::cout << "Sent #" << (++count) << " frame bytes=" << n << " payload=" << payload.size() << "\n";
    }

    close(fd);
    return 0;
}
