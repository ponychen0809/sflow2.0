#include <iostream>
#include <fstream>
#include <string>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>   // for struct ether_header

using namespace std;

// UDP Payload 解析結構
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

// 全域計數器：sub_agent_id = 1 / 2 各自的封包數
static uint64_t g_subAgent1Count = 0;
static uint64_t g_subAgent2Count = 0;

void displayPayload(const UDP_Payload& payload) {
    cout << "UDP Payload Data:" << endl;
    cout << "Version: " << ntohl(payload.version) << endl;
    cout << "Address Type: " << ntohl(payload.address_type) << endl;

    struct in_addr agent_ip;
    agent_ip.s_addr = payload.agent_addr;      // 維持網路序，直接給 inet_ntoa
    cout << "Agent Addr: " << inet_ntoa(agent_ip) << endl;

    cout << "Sub Agent ID: " << ntohl(payload.sub_agent_id) << endl;
    cout << "Sequence Number: " << ntohl(payload.sequence_number) << endl;
    cout << "Uptime: " << ntohl(payload.uptime) << endl;
    cout << "Samples: " << ntohl(payload.samples) << endl;
    cout << "Sample Type: " << ntohl(payload.sample_type) << endl;
    cout << "Sample Length: " << ntohl(payload.sample_length) << endl;
    cout << "Sample Sequence Number: " << ntohl(payload.sample_seq_num) << endl;
    cout << "Source ID: " << ntohl(payload.source_id) << endl;
    cout << "Sampling Rate: " << ntohl(payload.sampling_rate) << endl;
    cout << "Sample Pool: " << ntohl(payload.sample_pool) << endl;
    cout << "Drops: " << ntohl(payload.drops) << endl;
    cout << "Input IF: " << ntohl(payload.input_if) << endl;
    cout << "Output IF: " << ntohl(payload.output_if) << endl;
    cout << "Record Count: " << ntohl(payload.record_count) << endl;
    cout << "Enterprise Format: " << ntohl(payload.enterprise_format) << endl;
    cout << "Flow Length: " << ntohl(payload.flow_length) << endl;
    cout << "Packet Length: " << ntohl(payload.pkt_length) << endl;
    cout << "Protocol: " << ntohl(payload.protocol) << endl;

    struct in_addr sip, dip;
    sip.s_addr = payload.src_ip;
    dip.s_addr = payload.dst_ip;
    cout << "Source IP: "      << inet_ntoa(sip) << endl;
    cout << "Destination IP: " << inet_ntoa(dip) << endl;

    cout << "Source Port: "      << ntohl(payload.src_port) << endl;
    cout << "Destination Port: " << ntohl(payload.dst_port) << endl;
    cout << "TCP Flags: "        << ntohl(payload.tcp_flags) << endl;
    cout << "TOS: "              << ntohl(payload.tos) << endl;
}

// 處理每個捕獲的封包
void packetHandler(unsigned char *userData,
                   const struct pcap_pkthdr *pkthdr,
                   const unsigned char *packet) {
    (void)userData;

    cout << "============================" << endl;

    // 1) Ethernet header
    if (pkthdr->caplen < sizeof(ether_header)) {
        cout << "Packet too short for Ethernet header" << endl;
        return;
    }

    auto* eth_hdr = (const struct ether_header*)packet;
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
        cout << "Not IPv4 (ether_type != 0x0800)" << endl;
        return;
    }

    // 2) IP header 在 Ethernet header 後面
    const unsigned char* ip_start = packet + sizeof(struct ether_header);

    if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
        cout << "Packet too short for IP header" << endl;
        return;
    }

    auto* ip_hdr = (struct ip*)ip_start;
    int ip_hdr_len = ip_hdr->ip_hl * 4;

    if (ip_hdr->ip_p != IPPROTO_UDP) {
        cout << "Not a UDP (ip_p=" << (int)ip_hdr->ip_p << ")" << endl;
        return;
    }

    // 3) UDP header 在 IP header 後面
    const unsigned char* udp_start = ip_start + ip_hdr_len;

    if (pkthdr->caplen <
        sizeof(struct ether_header) + ip_hdr_len + sizeof(struct udphdr)) {
        cout << "Packet too short for UDP header" << endl;
        return;
    }

    auto* udp_hdr = (struct udphdr*)udp_start;

    // BPF filter 已經是 udp port 6343，這裡當保險
    if (ntohs(udp_hdr->dest) != 6343) {
        cout << "Not dest port 6343, port=" << ntohs(udp_hdr->dest) << endl;
        return;
    }

    // 4) payload 在 UDP header 後面
    const unsigned char* payload_start = udp_start + sizeof(struct udphdr);

    size_t min_size =
        sizeof(struct ether_header) + ip_hdr_len +
        sizeof(struct udphdr) + sizeof(UDP_Payload);

    if (pkthdr->caplen < min_size) {
        cout << "Packet too short for UDP_Payload struct" << endl;
        return;
    }

    auto* payload = (const UDP_Payload*)payload_start;

    // 顯示 payload 詳細內容
    displayPayload(*payload);

    // ===== 根據 sub_agent_id 計數與顯示統計 =====
    uint32_t sub_id = ntohl(payload->sub_agent_id);

    if (sub_id == 1) {
        ++g_subAgent1Count;
        cout << "[From SubAgent 1] Total count for SubAgent 1 = "
             << g_subAgent1Count
             << ", SubAgent 2 = " << g_subAgent2Count << endl;
    } else if (sub_id == 2) {
        ++g_subAgent2Count;
        cout << "[From SubAgent 2] Total count for SubAgent 1 = "
             << g_subAgent1Count
             << ", SubAgent 2 = " << g_subAgent2Count << endl;
    } else {
        cout << "[From Unknown SubAgent ID = " << sub_id << "] "
             << "SubAgent 1 = " << g_subAgent1Count
             << ", SubAgent 2 = " << g_subAgent2Count << endl;
    }
    // ============================================
}

int main() {
    char errBuf[PCAP_ERRBUF_SIZE];

    // 開啟網卡 (enp2s0)
    pcap_t *handle = pcap_open_live("enp2s0", BUFSIZ, 1, 1000, errBuf);
    if (handle == nullptr) {
        cerr << "Error opening device: " << errBuf << endl;
        return 1;
    }

    // 設定過濾器，只接收 UDP 端口 6343 的封包
    struct bpf_program fp;
    const char* filter_exp = "udp port 6343";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Error compiling filter: " << pcap_geterr(handle) << endl;
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Error setting filter: " << pcap_geterr(handle) << endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&fp);

    cout << "Listening on enp2s0 for UDP port 6343..." << endl;

    // 開始捕獲封包
    if (pcap_loop(handle, 0, packetHandler, nullptr) < 0) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    return 0;
}
