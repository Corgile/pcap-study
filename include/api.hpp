//
// Created by xhl on 2023/7/9.
//

#ifndef PCAP_STUDY_API_HPP
#define PCAP_STUDY_API_HPP

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */

#define _CRT_SECURE_NO_WARNINGS
#endif

/*set the environment head files*/
#ifndef WIN32
#define WIN32
#endif
#pragma comment (lib, "ws2_32.lib")  //load ws2_32.dll

/*set the C++ head files*/
#include <iostream>
#include <cstdio>
#include <map>
#include <string>
#include <iomanip>
#include <sstream>

/*set the wpcap head files*/
#include <pcap/pcap.h>

#ifdef WIN32
//#include <WinSock2.h>
#endif

#include "packet_header.hpp"

#define DIVISION ("--------------------")
#define B_DIVISION ("===================")


/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the Ethernet packet*/
void ethernet_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the IPv4 packet*/
void ip_v4_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the IPv6 packet*/
void ip_v6_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the arp packet*/
void arp_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the udp packet*/
void udp_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the tcp packet*/
void tcp_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*analysis the icmp packet*/
void icmp_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*count the package with c++ std::map*/
void add_to_map(std::map<std::string, int> &_counter, ip_v4_address ip);

void add_to_map(std::map<std::string, int> &_counter, ip_v6_address ip);

/*print the map info*/
void print_map(std::map<std::string, int> _counter);

#endif //PCAP_STUDY_API_HPP
