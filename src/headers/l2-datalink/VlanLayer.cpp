#define LOG_MODULE PacketLogModuleVlanLayer

#include "osi/l2-datalink/VlanLayer.h"
#include "osi/l3-network/IPv4Layer.h"
#include "osi/l3-network/IPv6Layer.h"
#include "osi/l7-application/PayloadLayer.h"
#include "osi/l3-network/ArpLayer.h"
#include "osi/l2-datalink/PPPoELayer.h"
#include "osi/l3-network/MplsLayer.h"
#include "osi/l2-datalink/LLCLayer.h"
#include <string.h>
#include <sstream>
#include "EndianPortable.h"

namespace pcpp {

  VlanLayer::VlanLayer(const uint16_t vlanID, bool cfi, uint8_t priority, uint16_t etherType) {
    const size_t headerLen = sizeof(vlan_header);
    m_DataLen = headerLen;
    m_Data = new uint8_t[headerLen];
    memset(m_Data, 0, headerLen);
    m_Protocol = VLAN;

    vlan_header *vlanHeader = getVlanHeader();
    setVlanID(vlanID);
    setCFI(cfi);
    setPriority(priority);
    vlanHeader->etherType = htobe16(etherType);
  }

  uint16_t VlanLayer::getVlanID() const {
    return be16toh(getVlanHeader()->vlan) & 0xFFF;
  }

  uint8_t VlanLayer::getCFI() const {
    return ((be16toh(getVlanHeader()->vlan) >> 12) & 1);
  }

  uint8_t VlanLayer::getPriority() const {
    return (be16toh(getVlanHeader()->vlan) >> 13) & 7;
  }

  void VlanLayer::setVlanID(uint16_t id) {
    getVlanHeader()->vlan = htobe16((be16toh(getVlanHeader()->vlan) & (~0xFFF)) | (id & 0xFFF));
  }

  void VlanLayer::setCFI(bool cfi) {
    getVlanHeader()->vlan = htobe16((be16toh(getVlanHeader()->vlan) & (~(1 << 12))) | ((cfi & 1) << 12));
  }

  void VlanLayer::setPriority(uint8_t priority) {
    getVlanHeader()->vlan = htobe16((be16toh(getVlanHeader()->vlan) & (~(7 << 13))) | ((priority & 7) << 13));
  }

  void VlanLayer::parseNextLayer() {
    if (m_DataLen <= sizeof(vlan_header))
      return;

    uint8_t *payload = m_Data + sizeof(vlan_header);
    size_t payloadLen = m_DataLen - sizeof(vlan_header);

    vlan_header *hdr = getVlanHeader();
    switch (be16toh(hdr->etherType)) {
      case PCPP_ETHERTYPE_IP:
        m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
                      ? static_cast<AbstractLayer *>(new IPv4Layer(payload, payloadLen, this, m_Packet))
                      : static_cast<AbstractLayer *>(new PayloadLayer(payload, payloadLen, this, m_Packet));
        break;
      case PCPP_ETHERTYPE_IPV6:
        m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
                      ? static_cast<AbstractLayer *>(new IPv6Layer(payload, payloadLen, this, m_Packet))
                      : static_cast<AbstractLayer *>(new PayloadLayer(payload, payloadLen, this, m_Packet));
        break;
      case PCPP_ETHERTYPE_ARP:
        m_NextLayer = new ArpLayer(payload, payloadLen, this, m_Packet);
        break;
      case PCPP_ETHERTYPE_VLAN:
      case PCPP_ETHERTYPE_IEEE_802_1AD:
        m_NextLayer = new VlanLayer(payload, payloadLen, this, m_Packet);
        break;
      case PCPP_ETHERTYPE_PPPOES:
        m_NextLayer = PPPoESessionLayer::isDataValid(payload, payloadLen)
                      ? static_cast<AbstractLayer *>(new PPPoESessionLayer(payload, payloadLen, this, m_Packet))
                      : static_cast<AbstractLayer *>(new PayloadLayer(payload, payloadLen, this, m_Packet));
        break;
      case PCPP_ETHERTYPE_PPPOED:
        m_NextLayer = PPPoEDiscoveryLayer::isDataValid(payload, payloadLen)
                      ? static_cast<AbstractLayer *>(new PPPoEDiscoveryLayer(payload, payloadLen, this, m_Packet))
                      : static_cast<AbstractLayer *>(new PayloadLayer(payload, payloadLen, this, m_Packet));
        break;
      case PCPP_ETHERTYPE_MPLS:
        m_NextLayer = new MplsLayer(payload, payloadLen, this, m_Packet);
        break;
      default:
        m_NextLayer = (be16toh(hdr->etherType) < 1500 && LLCLayer::isDataValid(payload, payloadLen))
                      ? static_cast<AbstractLayer *>(new LLCLayer(payload, payloadLen, this, m_Packet))
                      : static_cast<AbstractLayer *>(new PayloadLayer(payload, payloadLen, this, m_Packet));
    }
  }

  void VlanLayer::computeCalculateFields() {
    if (m_NextLayer == nullptr)
      return;

    switch (m_NextLayer->getProtocol()) {
      case IPv4:
        getVlanHeader()->etherType = htobe16(PCPP_ETHERTYPE_IP);
        break;
      case IPv6:
        getVlanHeader()->etherType = htobe16(PCPP_ETHERTYPE_IPV6);
        break;
      case ARP:
        getVlanHeader()->etherType = htobe16(PCPP_ETHERTYPE_ARP);
        break;
      case VLAN:
        getVlanHeader()->etherType = htobe16(PCPP_ETHERTYPE_VLAN);
        break;
      default:
        return;
    }
  }

  std::string VlanLayer::toString() const {
    std::ostringstream cfiStream;
    cfiStream << (int) getCFI();
    std::ostringstream priStream;
    priStream << (int) getPriority();
    std::ostringstream idStream;
    idStream << getVlanID();

    return "VLAN AbstractLayer, Priority: " + priStream.str() + ", Vlan ID: " + idStream.str() + ", CFI: " + cfiStream.str();
  }

} // namespace pcpp