#include <pcap.h>
#include <string>
#include <iostream>
#include <sstream>
#include <winsock2.h>

uint16_t checksum (uint16_t *addr, int len) {

    int count = len;
    uint32_t sum = 0;
    uint16_t answer = 0;

    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    if (count > 0) {
        sum += *(uint8_t *) addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    answer = ~sum;

    return (answer);

}

int main([[maybe_unused]] int argc, [[maybe_unused]] char **argv) {

    // L1 - Physical Interface
    const std::string interfaceName = "\\Device\\NPF_{A4C97E65-B72C-4687-B214-51E15B3C8D1C}";

    // L2 - MAC Addresses
    const std::string source_mac = "e4:5d:51:94:d0:40";
    const std::string destination_mac = "04:7c:16:d9:5b:76";

    // L3 - IP Addresses
    const std::string source_ip = "192.168.1.1";
    const std::string destination_ip = "192.168.1.250";

    // L4 - Ports, Protocol & Payload (Data)
    const char payload[] = "abcdefghijklmnopqurstvwxyzabcdef";
    const int payload_length = sizeof(payload) - 1;

    /*
     * Craft Packet - Ethernet Type 2 Frame
     */
    // 14=ethernet header, 20=ip header, 8=icmp header
    int packet_len = 14 + 20 + 8 + payload_length;
    auto* packet = new u_char[packet_len];
    int packetByte = 0;

    // Clear packet entirely
    memset(packet, 0, packet_len);

    /*
     * MAC Header
     * https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
     */

    // Destination Mac Address
    // Byte 0-5 (len=6)
    std::stringstream ssDstMac(destination_mac);
    std::string partDstMac;
    while (std::getline(ssDstMac, partDstMac, ':') && packetByte < 6) {

        packet[packetByte++] = static_cast<u_char>(std::stoi(partDstMac, nullptr, 16));

    }

    // Source Mac Address
    // Byte 6-11 (len=6)
    std::stringstream ssSrcMac(source_mac);
    std::string partSrcMac;
    while (std::getline(ssSrcMac, partSrcMac, ':') && packetByte >= 6 && packetByte < 12) {

        packet[packetByte++] = static_cast<u_char>(std::stoi(partSrcMac, nullptr, 16));

    }

    // EtherType (IPv4)
    // Byte 12-13 (len=2)
    packet[12] = 0x08;
    packet[13] = 0x00;

    // MAC Header done! (len=14)

    /*
     * IPv4 Header
     * https://en.wikipedia.org/wiki/IPv4#Header
     */

    // Version & IHL
    packet[14] = 0x45;

    // DSCP (Differentiated Services Code Point) (ToS = Type Of Service) [Off]
    packet[15] = 0x00;

    // Length | Remove Ethernet Header length
    uint16_t ipv4_len = htons(packet_len - 14);
    packet[16] = ipv4_len & 0xFF;        // Low byte
    packet[17] = (ipv4_len >> 8) & 0xFF; // High byte

    // Identification
    packet[18] = 0x12;
    packet[19] = 0x34;

    // Flags and Fragment Offset (0x4000 indicates "Don't Fragment")
    packet[20] = 0x40; // Flag: DF (Don't Fragment)
    packet[21] = 0x00; // Fragment offset

    // TTL
    packet[22] = 0x80;

    // Protocol (ICMP)
    packet[23] = 0x01;

    // Select next byte to prepare for source/destination IP entries
    packetByte = 26;

    // Source IP Address
    // Byte 26-29 (len=4)
    std::stringstream ssSrcIp(source_ip);
    std::string partSrcIp;
    while (std::getline(ssSrcIp, partSrcIp, '.') && packetByte >= 26 && packetByte < 30) {
        packet[packetByte++] = static_cast<u_char>(std::stoi(partSrcIp, nullptr, 10));  // Base 10 for IP address octets
    }

    // Destination IP Address
    // Byte 30-33 (len=4)
    std::stringstream ssDstIp(destination_ip);
    std::string partDstIp;
    while (std::getline(ssDstIp, partDstIp, '.') && packetByte >= 30 && packetByte < 34) {
        packet[packetByte++] = static_cast<u_char>(std::stoi(partDstIp, nullptr, 10));  // Base 10 for IP address octets
    }

    // IPv4 Header done! (len=20)

    /*
     * ICMP Header
     * https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
     */

    // Type
    packet[34] = 8; // Echo Request

    // Code
    packet[35] = 0; // Echo Request

    // Checksum (calculated later)
    packet[36] = 0;
    packet[37] = 0;

    // Identifier
    uint16_t identifier = htons(1);
    packet[38] = identifier & 0xFF;        // Low byte
    packet[39] = (identifier >> 8) & 0xFF; // High byte

    // Sequence Number
    uint16_t sequence_number = htons(1);
    packet[40] = sequence_number & 0xFF;        // Low byte
    packet[41] = (sequence_number >> 8) & 0xFF; // High byte

    // Payload
    for (size_t i = 0; i < payload_length; ++i) {
        packet[42 + i] = payload[i];
    }

    // Checksum
    uint16_t icmp_checksum = checksum((uint16_t *) (packet + 34), 8 + payload_length);
    packet[36] = icmp_checksum & 0xFF;        // Low byte
    packet[37] = (icmp_checksum >> 8) & 0xFF; // High byte

    // ICMP Header done! (len=8)

    // IPv4 checksum
    uint16_t ipv4_cksum = checksum((uint16_t *)(packet + 14), 20);
    *(uint16_t*)(packet + 24) = ipv4_cksum;

    // Packet crafting done!

    // Init Npcap & Interface
    pcap_t *pcap = nullptr;
    char errorBuffer[PCAP_ERRBUF_SIZE];

    if ((pcap = pcap_open_live(interfaceName.c_str(), 0, 0, 1000, errorBuffer)) == nullptr) {

        std::cerr << "Interface couldn't be opened (pcap_open_live)" << std::endl;

        pcap_close(pcap);
        delete[] packet;

        return -1;

    }

    // Send crafted packet
    if (pcap_sendpacket(pcap, packet, packet_len) != 0) {

        std::cerr << "Packet failed to send (pcap_sendpacket)" << std::endl;

        pcap_close(pcap);
        delete[] packet;

        return -1;

    } else {

        std::cout << "SUCCESS! Packet sent!" << std::endl;

    }

    pcap_close(pcap);
    delete[] packet;

    return 0;

}