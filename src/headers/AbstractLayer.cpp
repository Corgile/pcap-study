#define LOG_MODULE PacketLogModuleLayer

#include "osi/AbstractLayer.h"
#include <string.h>
#include "Logger.h"
#include "Packet.h"

namespace pcpp {

  AbstractLayer::~AbstractLayer() {
    if (!isAllocatedToPacket())
      delete[] m_Data;
  }

  AbstractLayer::AbstractLayer(const AbstractLayer &other) : m_Packet(nullptr), m_Protocol(other.m_Protocol), m_NextLayer(nullptr),
                                                             m_PrevLayer(nullptr), m_IsAllocatedInPacket(false) {
    m_DataLen = other.getHeaderLen();
    m_Data = new uint8_t[other.m_DataLen];
    memcpy(m_Data, other.m_Data, other.m_DataLen);
  }

  AbstractLayer &AbstractLayer::operator=(const AbstractLayer &other) {
    if (this == &other)
      return *this;

    if (m_Data != nullptr)
      delete[] m_Data;

    m_DataLen = other.getHeaderLen();
    m_Packet = nullptr;
    m_Protocol = other.m_Protocol;
    m_NextLayer = nullptr;
    m_PrevLayer = nullptr;
    m_Data = new uint8_t[other.m_DataLen];
    m_IsAllocatedInPacket = false;
    memcpy(m_Data, other.m_Data, other.m_DataLen);

    return *this;
  }

  void AbstractLayer::copyData(uint8_t *toArr) const {
    memcpy(toArr, m_Data, m_DataLen);
  }

  bool AbstractLayer::extendLayer(int offsetInLayer, size_t numOfBytesToExtend) {
    if (m_Data == nullptr) {
      PCPP_LOG_ERROR("AbstractLayer's data is NULL");
      return false;
    }

    if (m_Packet == nullptr) {
      if ((size_t) offsetInLayer > m_DataLen) {
        PCPP_LOG_ERROR("Requested offset is larger than data length");
        return false;
      }

      uint8_t *newData = new uint8_t[m_DataLen + numOfBytesToExtend];
      memcpy(newData, m_Data, offsetInLayer);
      memcpy(newData + offsetInLayer + numOfBytesToExtend, m_Data + offsetInLayer, m_DataLen - offsetInLayer);
      delete[] m_Data;
      m_Data = newData;
      m_DataLen += numOfBytesToExtend;
      return true;
    }

    return m_Packet->extendLayer(this, offsetInLayer, numOfBytesToExtend);
  }

  bool AbstractLayer::shortenLayer(int offsetInLayer, size_t numOfBytesToShorten) {
    if (m_Data == nullptr) {
      PCPP_LOG_ERROR("AbstractLayer's data is NULL");
      return false;
    }

    if (m_Packet == nullptr) {
      if ((size_t) offsetInLayer >= m_DataLen) {
        PCPP_LOG_ERROR("Requested offset is larger than data length");
        return false;
      }

      uint8_t *newData = new uint8_t[m_DataLen - numOfBytesToShorten];
      memcpy(newData, m_Data, offsetInLayer);
      memcpy(newData + offsetInLayer, m_Data + offsetInLayer + numOfBytesToShorten,
             m_DataLen - offsetInLayer - numOfBytesToShorten);
      delete[] m_Data;
      m_Data = newData;
      m_DataLen -= numOfBytesToShorten;
      return true;
    }

    return m_Packet->shortenLayer(this, offsetInLayer, numOfBytesToShorten);
  }

} // namespace pcpp
