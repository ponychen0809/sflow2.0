#include <iostream>
#include <fstream>
#include <string>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

using namespace std;

// UDP Payload 解析結構，這取決於您的 payload 格式
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
    cout << "UDP Payload Data:" << endl;
    cout << "Version: " << payload.version << endl;
    cout << "Address Type: " << payload.address_type << endl;
    cout << "Agent Addr: " << payload.agent_addr << endl;
    cout << "Sub Agent ID: " << payload.sub_agent_id << endl;
    cout << "Sequence Number: " << payload.sequence_number << endl;
    cout << "Uptime: " << payload.uptime << endl;
    cout << "Samples: " << payload.samples << endl;
    cout << "Sample Type: " << payload.sample_type << endl;
    cout << "Sample Length: " << payload.sample_length << endl;
    cout << "Sample Sequence Number: " << payload.sample_seq_num << endl;
    cout << "Source ID: " << payload.source_id << endl;
    cout << "Sampling Rate: " << payload.sampling_rate << endl;
    cout << "Sample Pool: " << payload.sample_pool << endl;
    cout << "Drops: " << payload.drops << endl;
    cout << "Input IF: " << payload.input_if << endl;
    cout << "Output IF: " << payload.output_if << endl;
    cout << "Record Count: " << payload.record_count << endl;
    cout << "Enterprise Format: " << payload.enterprise_format << endl;
    cout << "Flow Length: " << payload.flow_length << endl;
    cout << "Packet Length: " << payload.pkt_length << endl;
    cout << "Protocol: " << payload.protocol << endl;
    cout << "Source IP: " << inet_ntoa(*(struct in_addr*)&payload.src_ip) << endl;
    cout << "Destination IP: " << inet_ntoa(*(struct in_addr*)&payload.dst_ip) << endl;
    cout << "Source Port: " << ntohs(payload.src_port) << endl;
    cout << "Destination Port: " << ntohs(payload.dst_port) << endl;
    cout << "TCP Flags: " << payload.tcp_flags << endl;
    cout << "TOS: " << payload.tos << endl;
}

// 處理每個捕獲的封包
void packetHandler(unsigned char *userData, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // 解析 IP header
    auto* ip_hdr = (struct ip*)packet;
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    std::cout << "============================" << std::endl;
    // 檢查是否是 UDP 封包
    if (ip_hdr->ip_p != IPPROTO_UDP) {
        return;
    }

    // 解析 UDP header
    auto* udp_hdr = (struct udphdr*)(packet + ip_hdr_len);
    if (ntohs(udp_hdr->dest) != 6343) {
        return;
    }

    // 計算 payload 偏移
    auto* payload = (UDP_Payload*)(packet + ip_hdr_len + sizeof(struct udphdr));

    // 顯示解析的 UDP Payload
    displayPayload(*payload);
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
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Error setting filter: " << pcap_geterr(handle) << endl;
        return 1;
    }

    cout << "Listening on enp2s0 for UDP port 6343..." << endl;

    // 開始捕獲封包
    if (pcap_loop(handle, 0, packetHandler, nullptr) < 0) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
        return 1;
    }

    // 關閉抓包介面
    pcap_close(handle);
    return 0;
}
