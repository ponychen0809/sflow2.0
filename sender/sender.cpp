#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

using namespace std;

int main() {
    // 設定目標 IP 和端口
    string target_ip = "10.10.3.3";  // 目標 IP
    int target_port = 12345;         // 目標端口

    // 創建 UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // 設定目標地址結構
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr) <= 0) {
        perror("Invalid address");
        return -1;
    }

    // 輸入介面名稱
    string interface_name;
    cout << "Enter the network interface name (e.g., eth0, wlan0): ";
    cin >> interface_name;

    // 取得並設置介面 IP 地址
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Failed to get interface address");
        close(sockfd);
        return -1;
    }

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    string interface_ip = inet_ntoa(ipaddr->sin_addr);

    // 將該接口 IP 設置為發送源 IP
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface_name.c_str(), interface_name.size()) < 0) {
        perror("Failed to bind socket to interface");
        close(sockfd);
        return -1;
    }

    // 發送封包
    string message = "Hello, UDP!";
    int packet_count = 0; // 記錄發送的封包數量

    while (true) {
        cout << "Press Enter to send a packet... ";
        cin.get();     // 等待按下 Enter 鍵

        if (sendto(sockfd, message.c_str(), message.length(), 0, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            perror("Send failed");
        } else {
            packet_count++;  // 每發送一次封包，計數器加一
            cout << "Packet " << packet_count << " sent to " << target_ip << ":" << target_port << " from " << interface_ip << endl;
        }
    }

    // 關閉 socket
    close(sockfd);
    return 0;
}
