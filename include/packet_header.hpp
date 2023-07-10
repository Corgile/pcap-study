//
// Created by xhl on 2023/7/9.
//

#ifndef PCAP_STUDY_PACKET_HEADER_HPP
#define PCAP_STUDY_PACKET_HEADER_HPP

#include <cstdint>

/* 4 bytes IP address */
typedef struct ip_v4_address ip_v4_address;

/* 16 bytes IP address */
typedef struct ip_v6_address ip_v6_address;

/*8 bytes MAC addresss*/
typedef struct mac_address mac_address;

/*Ethernet common*/
typedef struct ethernet_header ethernet_header;

/* IPv4 common */
typedef struct ip_v4_header ip_v4_header;

/*IPv6 common*/
typedef struct ip_v6_header ip_v6_header;

/*arp common*/
typedef struct arp_header arp_header;

/*TCP common*/
typedef struct tcp_header tcp_header;

/* UDP common*/
typedef struct udp_header udp_header;

/*ICMP common*/
typedef struct icmp_header icmp_header;
/*common structure*/
struct ip_v4_address {
  uint8_t byte1;
  uint8_t byte2;
  uint8_t byte3;
  uint8_t byte4;
};

struct ip_v6_address {
  uint16_t part1;
  uint16_t part2;
  uint16_t part3;
  uint16_t part4;
  uint16_t part5;
  uint16_t part6;
  uint16_t part7;
  uint16_t part8;
};

struct mac_address {
  uint8_t byte1;
  uint8_t byte2;
  uint8_t byte3;
  uint8_t byte4;
  uint8_t byte5;
  uint8_t byte6;
};

struct ethernet_header {
  mac_address des_mac_addr;
  mac_address src_mac_addr;
  uint16_t type;
};

struct ip_v4_header {
  uint8_t ver_ihl;        // Version (4 bits) + Internet common length (4 bits)
  uint8_t tos;            // Type of service
  uint16_t tlen;            // Total length
  uint16_t identification; // Identification
  uint16_t flags_fo;        // Flags (3 bits) + Fragment offset (13 bits)
  uint8_t ttl;            // Time to live
  uint8_t proto;            // Protocol
  uint16_t checksum;            // Header checksum
  ip_v4_address src_ip_addr;        // Source address
  ip_v4_address des_ip_addr;        // Destination address
  uint32_t op_pad;            // Option + Padding
};

struct ip_v6_header {
  uint32_t ver_trafficclass_flowlabel;
  uint16_t payload_len;
  uint8_t next_head;
  uint8_t ttl;
  ip_v6_address src_ip_addr;
  ip_v6_address dst_ip_addr;
};

struct arp_header {
  uint16_t hardware_type;
  uint16_t protocol_type;
  uint8_t hardware_length;
  uint8_t protocol_length;
  uint16_t operation_code;
  mac_address source_mac_addr;
  ip_v4_address source_ip_addr;
  mac_address des_mac_addr;
  ip_v4_address des_ip_addr;
};

struct tcp_header {
  uint16_t sport;
  uint16_t dport;
  uint32_t sequence;
  uint32_t acknowledgement;
  uint8_t offset;
  uint8_t flags;
  uint16_t windows;
  uint16_t checksum;
  uint16_t urgent_pointer;
};

struct udp_header {
  uint16_t sport;            // Source port
  uint16_t dport;            // Destination port
  uint16_t len;            // Datagram length
  uint16_t checksum;            // Checksum
};

struct icmp_header {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;
  uint16_t sequence;
};

#endif //PCAP_STUDY_PACKET_HEADER_HPP
