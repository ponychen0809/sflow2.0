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
    string target_ip = "10.10.3.2";
    int target_port = 12345;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr) <= 0) {
        perror("Invalid address");
        return -1;
    }

    string interface_name;
    cout << "Enter the network interface name (e.g., eth0, wlan0): ";
    cin >> interface_name;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Failed to get interface address");
        close(sockfd);
        return -1;
    }

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    string interface_ip = inet_ntoa(ipaddr->sin_addr);

    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                   interface_name.c_str(), interface_name.size()) < 0) {
        perror("Failed to bind socket to interface");
        close(sockfd);
        return -1;
    }

    // ======================================
    // 產生 >800 bytes 的 payload (900 bytes)
    // ======================================
    string message(900, 'A');  // 產生 900 個 'A'
    cout << "Payload size = " << message.size() << " bytes\n";
    // 實際封包大小 = 20 (IP) + 8 (UDP) + payload
    cout << "Estimated IP packet size = " << (20 + 8 + message.size()) << " bytes\n\n";

    int packet_count = 0;
    cin.ignore(); // 清空 buffer

    while (true) {
        cout << "Press Enter to send a packet... ";
        cin.get();

        if (sendto(sockfd, message.c_str(), message.length(), 0,
                   (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            perror("Send failed");
        } else {
            packet_count++;
            cout << "Packet " << packet_count << " sent! Size = "
                 << message.size() << " bytes payload." << endl;
        }
    }

    close(sockfd);
    return 0;
}
