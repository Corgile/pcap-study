//
// Created by xhl on 2023/7/9.
//
#include "api.hpp"

std::map<std::string, int> counts;

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  struct tm *ltime;
  char timestr[16];
  time_t local_tv_sec;

  /* convert the timestamp to readable format */
  local_tv_sec = header->ts.tv_sec;
  ltime = localtime(&local_tv_sec);
  strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
  std::cout << B_DIVISION << "time:" << timestr << ","
            << header->ts.tv_usec << "  len:" << header->len << B_DIVISION << std::endl;
  ethernet_package_handler(param, header, pkt_data);
}

void ethernet_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  auto *eh = (ethernet_header *) pkt_data;
  std::cout << DIVISION << "以太网协议分析结构" << DIVISION << std::endl;
  u_short type = ntohs(eh->type);
  std::cout << "类型：0x" << std::hex << type;
  std::cout << std::setbase(10);
  switch (type) {
    case 0x0800:
      std::cout << " (IPv4)" << std::endl;
      break;
    case 0x86DD:
      std::cout << "(IPv6)" << std::endl;
      break;
    case 0x0806:
      std::cout << " (ARP)" << std::endl;
      break;
    case 0x0835:
      std::cout << " (RARP)" << std::endl;
    default:
      break;
  }
  std::cout << "目的地址：" << int(eh->des_mac_addr.byte1) << ":"
            << int(eh->des_mac_addr.byte2) << ":"
            << int(eh->des_mac_addr.byte3) << ":"
            << int(eh->des_mac_addr.byte4) << ":"
            << int(eh->des_mac_addr.byte5) << ":"
            << int(eh->des_mac_addr.byte6) << std::endl;
  std::cout << "源地址：" << int(eh->src_mac_addr.byte1) << ":"
            << int(eh->src_mac_addr.byte2) << ":"
            << int(eh->src_mac_addr.byte3) << ":"
            << int(eh->src_mac_addr.byte4) << ":"
            << int(eh->src_mac_addr.byte5) << ":"
            << int(eh->src_mac_addr.byte6) << std::endl;
  switch (type) {
    case 0x0800:
      ip_v4_package_handler(param, header, pkt_data);
      break;
    case 0x0806:
      arp_package_handler(param, header, pkt_data);
      break;
    case 0x86DD:
      ip_v6_package_handler(param, header, pkt_data);
      break;
    default:
      break;
  }
  std::cout << std::endl << std::endl;
}

void arp_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  arp_header *ah;
  ah = (arp_header *) (pkt_data + 14);
  std::cout << DIVISION << "ARP协议分析结构" << DIVISION << std::endl;
  u_short operation_code = ntohs(ah->operation_code);
  std::cout << "硬件类型：" << ntohs(ah->hardware_type) << std::endl;
  std::cout << "协议类型：0x" << std::hex << ntohs(ah->protocol_type) << std::endl;
  std::cout << std::setbase(10);
  std::cout << "硬件地址长度：" << int(ah->hardware_length) << std::endl;
  std::cout << "协议地址长度：" << int(ah->protocol_length) << std::endl;
  switch (operation_code) {
    case 1:
      std::cout << "ARP请求协议" << std::endl;
      break;
    case 2:
      std::cout << "ARP应答协议" << std::endl;
      break;
    case 3:
      std::cout << "ARP请求协议" << std::endl;
      break;
    case 4:
      std::cout << "RARP应答协议" << std::endl;
      break;
    default:
      break;
  }
  std::cout << "源IP地址："
            << int(ah->source_ip_addr.byte1) << "."
            << int(ah->source_ip_addr.byte2) << "."
            << int(ah->source_ip_addr.byte3) << "."
            << int(ah->source_ip_addr.byte4) << std::endl;

  std::cout << "目的IP地址："
            << int(ah->des_ip_addr.byte1) << "."
            << int(ah->des_ip_addr.byte2) << "."
            << int(ah->des_ip_addr.byte3) << "."
            << int(ah->des_ip_addr.byte4) << std::endl;

  add_to_map(counts, ah->source_ip_addr);
  print_map(counts);
}

void ip_v4_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  ip_v4_header *ih;
  ih = (ip_v4_header *) (pkt_data + 14); //14 measn the length of Ethernet common
  std::cout << DIVISION << "IPv4协议分析结构" << DIVISION << std::endl;
  std::cout << "版本号：" << ((ih->ver_ihl & 0xf0) >> 4) << std::endl;
  std::cout << "首部长度：" << (ih->ver_ihl & 0xf) << "("
            << ((ih->ver_ihl & 0xf) << 2) << "B)" << std::endl;
  std::cout << "区别服务：" << int(ih->tos) << std::endl;
  std::cout << "总长度：" << ntohs(ih->tlen) << std::endl;
  std::cout << "标识：" << ntohs(ih->identification) << std::endl;
  std::cout << "标志：" << ((ih->flags_fo & 0xE000) >> 12) << std::endl;
  std::cout << "片偏移：" << (ih->flags_fo & 0x1FFF) << "("
            << ((ih->flags_fo & 0x1FFF) << 3) << "B)" << std::endl;
  std::cout << "生命周期：" << int(ih->ttl) << std::endl;
  std::cout << "协议：";
  switch (ih->proto) {
    case 6:
      std::cout << "TCP" << std::endl;
      break;
    case 17:
      std::cout << "UDP" << std::endl;
      break;
    case 1:
      std::cout << "ICMP" << std::endl;
      break;
    default:
      std::cout << std::endl;
      break;
  }
  std::cout << "校验和：" << ntohs(ih->checksum) << std::endl;
  std::cout << "源IP地址："
            << int(ih->src_ip_addr.byte1) << "."
            << int(ih->src_ip_addr.byte2) << "."
            << int(ih->src_ip_addr.byte3) << "."
            << int(ih->src_ip_addr.byte4) << std::endl;

  std::cout << "目的IP地址："
            << int(ih->des_ip_addr.byte1) << "."
            << int(ih->des_ip_addr.byte2) << "."
            << int(ih->des_ip_addr.byte3) << "."
            << int(ih->des_ip_addr.byte4) << std::endl;
  switch (ih->proto) {
    case 6:
      tcp_package_handler(param, header, pkt_data);
      break;
    case 17:
      udp_package_handler(param, header, pkt_data);
      break;
    case 1:
      icmp_package_handler(param, header, pkt_data);
      break;
    default:
      break;
  }
  add_to_map(counts, ih->src_ip_addr);
  print_map(counts);
}

void ip_v6_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  auto *ih = (ip_v6_header *) (pkt_data + 14); //14 measn the length of Ethernet common
  auto version = (ih->ver_trafficclass_flowlabel & 0xf0000000) >> 28;
  int traffic_class = ntohs((ih->ver_trafficclass_flowlabel & 0x0ff00000) >> 20);
  auto flow_label = ih->ver_trafficclass_flowlabel & 0x000fffff;
  std::cout << "版本号：" << version << std::endl;
  std::cout << "通信量类：" << traffic_class << std::endl;
  std::cout << "流标号：" << flow_label << std::endl;
  std::cout << "有效载荷：" << ntohs(ih->payload_len) << std::endl;
  std::cout << "下一个首部：" << int(ih->next_head) << std::endl;
  std::cout << "跳数限制：" << int(ih->ttl) << std::endl;
  std::cout << "源IP地址："
            << int(ih->src_ip_addr.part1) << ":"
            << int(ih->src_ip_addr.part2) << ":"
            << int(ih->src_ip_addr.part3) << ":"
            << int(ih->src_ip_addr.part4) << ":"
            << int(ih->src_ip_addr.part5) << ":"
            << int(ih->src_ip_addr.part6) << ":"
            << int(ih->src_ip_addr.part7) << ":"
            << int(ih->src_ip_addr.part8) << std::endl;
  std::cout << "目的IP地址："
            << int(ih->dst_ip_addr.part1) << ":"
            << int(ih->dst_ip_addr.part2) << ":"
            << int(ih->dst_ip_addr.part3) << ":"
            << int(ih->dst_ip_addr.part4) << ":"
            << int(ih->dst_ip_addr.part5) << ":"
            << int(ih->dst_ip_addr.part6) << ":"
            << int(ih->dst_ip_addr.part7) << ":"
            << int(ih->dst_ip_addr.part8) << std::endl;
  switch (ih->next_head) {
    case 6:
      tcp_package_handler(param, header, pkt_data);
      break;
    case 17:
      udp_package_handler(param, header, pkt_data);
      break;
    case 58:
      icmp_package_handler(param, header, pkt_data);
      break;
    default:
      break;
  }
  add_to_map(counts, ih->src_ip_addr);
  print_map(counts);
}

void udp_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  udp_header *uh;
  uh = (udp_header *) (pkt_data + 20 + 14);
  std::cout << DIVISION << "UDP协议分析结构" << DIVISION << std::endl;
  std::cout << "源端口：" << ntohs(uh->sport) << std::endl;
  std::cout << "目的端口：" << ntohs(uh->dport) << std::endl;
  std::cout << "长度：" << ntohs(uh->len) << std::endl;
  std::cout << "检验和：" << ntohs(uh->checksum) << std::endl;
}

void tcp_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  tcp_header *th;
  th = (tcp_header *) (pkt_data + 14 + 20);
  std::cout << DIVISION << "TCP协议分析结构" << DIVISION << std::endl;
  std::cout << "源端口：" << ntohs(th->sport) << std::endl;
  std::cout << "目的端口：" << ntohs(th->dport) << std::endl;
  std::cout << "序号：" << ntohl(th->sequence) << std::endl;
  std::cout << "确认号：" << ntohl(th->acknowledgement) << std::endl;
  std::cout << "数据偏移：" << ((th->offset & 0xf0) >> 4) << "("
            << ((th->offset & 0xf0) >> 2) << "B)" << std::endl;
  std::cout << "标志：";
  if (th->flags & 0x01) {
    std::cout << "FIN ";
  }
  if (th->flags & 0x02) {
    std::cout << "SYN ";
  }
  if (th->flags & 0x04) {
    std::cout << "RST ";
  }
  if (th->flags & 0x08) {
    std::cout << "PSH ";
  }
  if (th->flags & 0x10) {
    std::cout << "ACK ";
  }
  if (th->flags & 0x20) {
    std::cout << "URG ";
  }
  std::cout << std::endl;
  std::cout << "窗口：" << ntohs(th->windows) << std::endl;
  std::cout << "检验和：" << ntohs(th->checksum) << std::endl;
  std::cout << "紧急指针：" << ntohs(th->urgent_pointer) << std::endl;
}

void icmp_package_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  icmp_header *ih;
  ih = (icmp_header *) (pkt_data + 14 + 20);
  std::cout << DIVISION << "ICMP协议分析结构" << DIVISION << std::endl;
  std::cout << "ICMP类型：" << ih->type;
  switch (ih->type) {
    case 8:
      std::cout << "ICMP回显请求协议" << std::endl;
      break;
    case 0:
      std::cout << "ICMP回显应答协议" << std::endl;
      break;
    default:
      break;
  }
  std::cout << "ICMP代码：" << ih->code << std::endl;
  std::cout << "标识符：" << ih->id << std::endl;
  std::cout << "序列码：" << ih->sequence << std::endl;
  std::cout << "ICMP校验和：" << ntohs(ih->checksum) << std::endl;
}

void add_to_map(std::map<std::string, int> &_counter, ip_v4_address ip) {
  std::string ip_string;
  int amount = 0;
  std::map<std::string, int>::iterator iter;
  ip_string = std::to_string(ip.byte1) + "."
              + std::to_string(ip.byte2) + "."
              + std::to_string(ip.byte3) + "."
              + std::to_string(ip.byte4);
  iter = _counter.find(ip_string);
  if (iter != _counter.end()) {
    amount = iter->second;
  }
  _counter.insert_or_assign(ip_string, ++amount);
}

void add_to_map(std::map<std::string, int> &_counter, ip_v6_address ip) {
  std::string ip_string;
  int amount = 0;
  std::map<std::string, int>::iterator iter;
  ip_string = std::to_string(ip.part1) + ":"
              + std::to_string(ip.part2) + ":"
              + std::to_string(ip.part3) + ":"
              + std::to_string(ip.part4) + ":"
              + std::to_string(ip.part5) + ":"
              + std::to_string(ip.part6) + ":"
              + std::to_string(ip.part7) + ":"
              + std::to_string(ip.part8);
  iter = _counter.find(ip_string);
  if (iter != _counter.end()) {
    amount = iter->second;
  }
  _counter.insert_or_assign(ip_string, ++amount);
}

void print_map(std::map<std::string, int> _counter) {
  std::map<std::string, int>::iterator iter;
  std::cout << DIVISION << "流量统计" << DIVISION << std::endl;
  std::cout << "IP" << std::setfill(' ') << std::setw(45) << "流量" << std::endl;
  for (iter = _counter.begin(); iter != _counter.end(); iter++) {
    std::cout << iter->first
              << std::setfill('.')
              << std::setw(int(45 - iter->first.length()))
              << iter->second
              << std::endl;
  }
}
