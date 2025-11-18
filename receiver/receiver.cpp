#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

// 定義UDP Payload的每個欄位結構，依照需求將每個欄位的大小設為4bytes
struct UDP_Payload {
    uint32_t version;
    uint32_t address_type;
    uint32_t agent_addr;
    uint32_t sub_agent_id;
    uint32_t sequence_number;
    uint32_t uptime;
    uint32_t samples;
    uint32_t sample_type;
    uint32_t sample_length;
    uint32_t sample_seq_num;
    uint32_t source_id;
    uint32_t sampling_rate;
    uint32_t sample_pool;
    uint32_t drops;
    uint32_t input_if;
    uint32_t output_if;
    uint32_t record_count;
    uint32_t enterprise_format;
    uint32_t flow_length;
    uint32_t pkt_length;
    uint32_t protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t src_port;
    uint32_t dst_port;
    uint32_t tcp_flags;
    uint32_t tos;
};

// 解析並顯示 UDP Payload 資料
void displayPayload(const UDP_Payload& payload) {
    std::cout << "UDP Payload Data:" << std::endl;
    std::cout << "Version: " << payload.version << std::endl;
    std::cout << "Address Type: " << payload.address_type << std::endl;
    std::cout << "Agent Addr: " << payload.agent_addr << std::endl;
    std::cout << "Sub Agent ID: " << payload.sub_agent_id << std::endl;
    std::cout << "Sequence Number: " << payload.sequence_number << std::endl;
    std::cout << "Uptime: " << payload.uptime << std::endl;
    std::cout << "Samples: " << payload.samples << std::endl;
    std::cout << "Sample Type: " << payload.sample_type << std::endl;
    std::cout << "Sample Length: " << payload.sample_length << std::endl;
    std::cout << "Sample Sequence Number: " << payload.sample_seq_num << std::endl;
    std::cout << "Source ID: " << payload.source_id << std::endl;
    std::cout << "Sampling Rate: " << payload.sampling_rate << std::endl;
    std::cout << "Sample Pool: " << payload.sample_pool << std::endl;
    std::cout << "Drops: " << payload.drops << std::endl;
    std::cout << "Input IF: " << payload.input_if << std::endl;
    std::cout << "Output IF: " << payload.output_if << std::endl;
    std::cout << "Record Count: " << payload.record_count << std::endl;
    std::cout << "Enterprise Format: " << payload.enterprise_format << std::endl;
    std::cout << "Flow Length: " << payload.flow_length << std::endl;
    std::cout << "Packet Length: " << payload.pkt_length << std::endl;
    std::cout << "Protocol: " << payload.protocol << std::endl;
    std::cout << "Source IP: " << inet_ntoa(*(struct in_addr*)&payload.src_ip) << std::endl;
    std::cout << "Destination IP: " << inet_ntoa(*(struct in_addr*)&payload.dst_ip) << std::endl;
    std::cout << "Source Port: " << ntohs(payload.src_port) << std::endl;
    std::cout << "Destination Port: " << ntohs(payload.dst_port) << std::endl;
    std::cout << "TCP Flags: " << payload.tcp_flags << std::endl;
    std::cout << "TOS: " << payload.tos << std::endl;
}

int main() {
    int sockfd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[65536]; // 用於接收封包的緩衝區

    // 創建套接字
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // 指定監聽的網路介面
    const char* interface = "enp2s0";  // 監聽網路介面
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0) {
        perror("Failed to bind to device");
        close(sockfd);
        return -1;
    }

    std::cout << "Listening on interface enp2s0..." << std::endl;

    while (true) {
        ssize_t packet_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &client_len);
        if (packet_len < 0) {
            perror("Error receiving packet");
            continue;
        }

        // 解析 IP header
        struct ip* ip_header = (struct ip*)buffer;
        int ip_header_len = ip_header->ip_hl * 4;
        struct udphdr* udp_header = (struct udphdr*)(buffer + ip_header_len);

        // 檢查是否是 UDP 端口 6343
        if (ntohs(udp_header->uh_dport) == 6343) {
            std::cout << "Received a UDP packet on port 6343" << std::endl;

            // 解析並顯示 IP 和 UDP Header
            std::cout << "\n*** IP Header ***" << std::endl;
            std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
            std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

            std::cout << "\n*** UDP Header ***" << std::endl;
            std::cout << "Source Port: " << ntohs(udp_header->uh_sport) << std::endl;
            std::cout << "Destination Port: " << ntohs(udp_header->uh_dport) << std::endl;

            // 解析並顯示 UDP payload
            UDP_Payload* payload = (UDP_Payload*)(buffer + ip_header_len + sizeof(struct udphdr));
            displayPayload(*payload);
        } else {
            // 如果是其他端口
            std::cout << "Received a packet from enp2s0 (not port 6343)" << std::endl;
        }
    }

    close(sockfd);
    return 0;
}
