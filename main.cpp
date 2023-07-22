#include <iostream>
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"

/**
 * A struct for collecting packet statistics
 */
struct PacketStats {
  int ethPacketCount;
  int ipv4PacketCount;
  int ipv6PacketCount;
  int tcpPacketCount;
  int udpPacketCount;
  int dnsPacketCount;
  int httpPacketCount;
  int sslPacketCount;


  /**
   * Clear all stats
   */
  void clear() {
    ethPacketCount = 0;
    ipv4PacketCount = 0;
    ipv6PacketCount = 0;
    tcpPacketCount = 0;
    udpPacketCount = 0;
    tcpPacketCount = 0;
    dnsPacketCount = 0;
    httpPacketCount = 0;
    sslPacketCount = 0;
  }

  /**
   * C'tor
   */
  PacketStats() { clear(); }

  /**
   * Collect stats from a packet
   */
  void consumePacket(pcpp::Packet &packet) {
    if (packet.isPacketOfType(pcpp::Ethernet))
      ethPacketCount++;
    if (packet.isPacketOfType(pcpp::IPv4))
      ipv4PacketCount++;
    if (packet.isPacketOfType(pcpp::IPv6))
      ipv6PacketCount++;
    if (packet.isPacketOfType(pcpp::TCP))
      tcpPacketCount++;
    if (packet.isPacketOfType(pcpp::UDP))
      udpPacketCount++;
    if (packet.isPacketOfType(pcpp::DNS))
      dnsPacketCount++;
    if (packet.isPacketOfType(pcpp::HTTP))
      httpPacketCount++;
    if (packet.isPacketOfType(pcpp::SSL))
      sslPacketCount++;
  }

  /**
   * Print stats to console
   */
  void printToConsole() const {
    std::cout
        << "Ethernet packet count: " << ethPacketCount << std::endl
        << "IPv4 packet count:     " << ipv4PacketCount << std::endl
        << "IPv6 packet count:     " << ipv6PacketCount << std::endl
        << "TCP packet count:      " << tcpPacketCount << std::endl
        << "UDP packet count:      " << udpPacketCount << std::endl
        << "DNS packet count:      " << dnsPacketCount << std::endl
        << "HTTP packet count:     " << httpPacketCount << std::endl
        << "SSL packet count:      " << sslPacketCount << std::endl;
  }
};


/**
 * A callback function for the async capture which is called each time a packet is captured
 */
static void callback(pcpp::RawPacket *packet, [[maybe_unused]] pcpp::PcapLiveDevice *dev, void *cookie) {
  // extract the stats object form the cookie
  auto *stats = (PacketStats *) cookie;

  // parsed the raw packet
  pcpp::Packet parsedPacket(packet);

  // collect stats from packet
  stats->consumePacket(parsedPacket);
}

/**
 * main method of the application
 */
int main([[maybe_unused]] int argc, [[maybe_unused]] char *argv[]) {
  // IPv4 address of the interface we want to sniff
  std::string interfaceIPAddr = "192.168.2.29";

  // find the interface by IP address
  pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
  if (dev == nullptr) {
    std::cerr << "Cannot find interface with IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
    return 1;
  }

  // Get device info
  // ~~~~~~~~~~~~~~~

  // before capturing packets let's print some info about this interface
  std::cout
      << "Interface info:" << std::endl
      << "   Interface name:        " << dev->getName() << std::endl // get interface name
      << "   Interface description: " << dev->getDesc() << std::endl // get interface description
      << "   MAC address:           " << dev->getMacAddress() << std::endl // get interface MAC address
      << "   Default gateway:       " << dev->getDefaultGateway() << std::endl // get default gateway
      << "   Interface MTU:         " << dev->getMtu() << std::endl; // get interface MTU

  if (!pcpp::PcapLiveDevice::getDnsServers().empty())
    std::cout << "   DNS server:            " << pcpp::PcapLiveDevice::getDnsServers().at(0) << std::endl;

  // open the device before start capturing/sending packets
  if (!dev->open()) {
    std::cerr << "Cannot open device" << std::endl;
    return 1;
  }

  // create the stats object
  PacketStats stats;

#define ASYNC
#ifdef ASYNC
  // Async packet capture with a callback function
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  std::cout << std::endl << "开始异步抓包..." << std::endl;

  // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
  dev->startCapture(callback, &stats);

  // sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
  pcpp::multiPlatformSleep(10);

  // stop capturing packets
  dev->stopCapture();

  // print results
  std::cout << "Results:" << std::endl;
  stats.printToConsole();

  // clear stats
  stats.clear();
#endif
#ifdef CAPTURE_VECTOR
  // Capturing packets in a packet vector
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  std::cout << std::endl << "Starting capture with packet vector..." << std::endl;

  // create an empty packet vector object
  pcpp::RawPacketVector packetVec;

  // start capturing packets. All packets will be added to the packet vector
  dev->startCapture(packetVec);

  // sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
  pcpp::multiPlatformSleep(10);

  // stop capturing packets
  dev->stopCapture();

  // go over the packet vector and feed all packets to the stats object
  for (auto iter: packetVec) {
    // parse raw packet
    pcpp::Packet parsedPacket(iter);

    // feed packet to the stats object
    stats.consumePacket(parsedPacket);
  }

  // print results
  std::cout << "Results:" << std::endl;
  stats.printToConsole();

  // clear stats
  stats.clear();
#endif

#ifdef Using_filters
  // ~~~~~~~~~~~~~

  // create a filter instance to capture only traffic on port 80
  pcpp::PortFilter portFilter(443, pcpp::SRC_OR_DST);

  // create a filter instance to capture only TCP traffic
  pcpp::ProtoFilter protocolFilter(pcpp::TCP);

  // create an AND filter to combine both filters - capture only TCP traffic on port 80
  pcpp::AndFilter andFilter;
  andFilter.addFilter(&portFilter);
  andFilter.addFilter(&protocolFilter);

  // set the filter on the device
  dev->setFilter(andFilter);

  std::cout << std::endl << "使用适当的过滤器开始数据包捕获" << std::endl;

  // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
  dev->startCapture(onPacketArrives, &stats);

  // sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
  pcpp::multiPlatformSleep(10);

  // stop capturing packets
  dev->stopCapture();

  // print results - should capture only packets which match the filter (which is TCP port 80)
  std::cout << "Results:" << std::endl;
  stats.printToConsole();


  // close the device before application ends
  dev->close();
#endif
}
