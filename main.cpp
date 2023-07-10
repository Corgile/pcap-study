#include "api.hpp"


int main() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int inum;
  int i = 0;
  int pktnum;
  pcap_t *adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];
  u_int netmask = 0xffffff;
  struct bpf_program fcode{};

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }


  for (d = alldevs; d; d = d->next) {
    std::cout << ++i << "." << d->name;
    if (d->description)
      std::cout << d->description << std::endl;
    else
      std::cout << " (No description available)" << std::endl;
  }

  if (i == 0) {
    std::cout << "\nNo interfaces found! Make sure WinPcap is installed." << std::endl;
    return -1;
  }

  std::cout << "Enter the interface number (1-" << i << "): ";
  std::cin >> inum;

  if (inum < 1 || inum > i) {
    std::cout << "\nInterface number out of range." << std::endl;
    pcap_freealldevs(alldevs);
    return -1;
  }


  for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

  if ((adhandle = pcap_open_live(d->name,    // name of the device
                                 65536,            // portion of the packet to capture.
      // 65536 grants that the whole packet will be captured on all the MACs.
                                 1,                // promiscuous mode (nonzero means promiscuous)
                                 1000,            // read timeout
                                 errbuf            // error buffer
  )) == nullptr) {
    fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
    pcap_freealldevs(alldevs);
    return -1;
  }

  std::cout << "listening on " << d->description << "...." << std::endl;

  pcap_freealldevs(alldevs);

  if (pcap_compile(adhandle, &fcode, "ip or arp", 1, netmask) < 0) {
    fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
    pcap_close(adhandle);
    return -1;
  }

  if (pcap_setfilter(adhandle, &fcode) < 0) {
    fprintf(stderr, "\nError setting the filter.\n");
    pcap_close(adhandle);
    return -1;
  }

  std::cout << "please input the num of packets you want to catch(0 for keeping catching): ";
  std::cin >> pktnum;
  std::cout << std::endl;
  pcap_loop(adhandle, pktnum, packet_handler, nullptr);
  pcap_close(adhandle);

  getchar();
  return 0;
}

