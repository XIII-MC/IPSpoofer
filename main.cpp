#include <pcap.h>
#include <string>
#include <iostream>
#include <sstream>
#include <winsock2.h>

int main([[maybe_unused]] int argc, [[maybe_unused]] char **argv) {

    // L1 - Physical Interface
    const std::string interfaceName = "\\Device\\NPF_{A4C97E65-B72C-4687-B214-51E15B3C8D1C}";

    // L2 - MAC Addresses
    const std::string source_mac = "F4:01:E8:AD:42:45";
    const std::string destination_mac = "AE:33:37:8D:DF:AA";

    // L3 - IP Addresses
    const std::string source_ip = "1.1.1.1";
    const std::string destination_ip = "192.168.1.250";

    // L4 - Ports, Protocol & Payload (Data)
    const uint16_t source_port = htons(54321);
    const uint16_t destination_port = htons(12345);
    const char payload[] = "This is a test string";
    const int payload_length = sizeof(payload) - 1;

    /*
     * Craft Packet - Ethernet Type 2 Frame
     */
    // 14=ethernet header, 20=ip header, 8=udp header
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
    packet[22] = 0x64;

    // Protocol (UDP)
    packet[23] = 0x11;

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
     * UDP Header
     * https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure
     */

    // Source Port
    packet[34] = source_port & 0xFF;        // Low byte
    packet[35] = (source_port >> 8) & 0xFF; // High byte

    // Source Port
    packet[36] = destination_port & 0xFF;        // Low byte
    packet[37] = (destination_port >> 8) & 0xFF; // High byte

    // UDP Length
    uint16_t udp_length = htons(8 + payload_length);
    packet[38] = udp_length & 0xFF;        // Low byte
    packet[39] = (udp_length >> 8) & 0xFF; // High byte

    // Payload
    for (size_t i = 0; i < payload_length; ++i) {
        packet[42 + i] = payload[i];
    }

    // Calculate IPv4 checksum
    uint32_t cksum = 0;
    for (int i = 14; i < 34; i += 2) {
        cksum += *(uint16_t*)(packet + i);
    }

    while (cksum >> 16) {
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    }

    cksum = ~cksum;
    *(uint16_t*)(packet + 24) = cksum;

    // UDP Header done! (len=8)

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