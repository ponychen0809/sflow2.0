#include <iostream>
#include <pcap.h>

using namespace std;

void packetHandler(unsigned char *userData, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // 顯示收到封包的訊息
    cout << "Received packet: " << pkthdr->len << " bytes" << endl;
}

int main() {
    char errBuf[PCAP_ERRBUF_SIZE];
    
    // 開啟網卡 (enp2s0)
    pcap_t *handle = pcap_open_live("enp2s0", BUFSIZ, 1, 1000, errBuf);
    if (handle == nullptr) {
        cerr << "Error opening device: " << errBuf << endl;
        return 1;
    }

    cout << "Listening on enp2s0..." << endl;

    // 開始監聽封包
    if (pcap_loop(handle, 0, packetHandler, nullptr) < 0) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
        return 1;
    }

    // 關閉抓包介面
    pcap_close(handle);

    return 0;
}
