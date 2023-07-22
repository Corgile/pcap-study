#ifndef PACKETPP_ETH_DOT3_LAYER
#define PACKETPP_ETH_DOT3_LAYER

#include "osi/AbstractLayer.h"
#include "MacAddress.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp {

  /**
   * @struct ether_dot3_header
   * Represents an IEEE 802.3 Ethernet common
   */
#pragma pack(push, 1)
  struct ether_dot3_header {
    /** Destination MAC */
    uint8_t dstMac[6];
    /** Source MAC */
    uint8_t srcMac[6];
    /** EtherType */
    uint16_t length;
  };
#pragma pack(pop)

  /**
   * @class EthDot3Layer
   * Represents an IEEE 802.3 Ethernet protocol layer
   */
  class EthDot3Layer : public AbstractLayer {
  public:

    /**
     * A constructor that creates the layer from an existing packet raw data
     * @param[in] data A pointer to the raw data (will be casted to ether_dot3_header)
     * @param[in] dataLen Size of the data in bytes
     * @param[in] packet A pointer to the Packet instance where layer will be stored in
     */
    EthDot3Layer(uint8_t *data, size_t dataLen, Packet *packet) :
    AbstractLayer(data, dataLen, nullptr, packet) { m_Protocol = EthernetDot3; }

    /**
     * A constructor that creates the layer from an existing packet raw data
     * @param[in] data A pointer to the raw data (will be casted to ether_header)
     * @param[in] dataLen Size of the data in bytes
     * @param[in] prevLayer A pointer to the previous layer
     * @param[in] packet A pointer to the Packet instance where layer will be stored in
     */
    EthDot3Layer(uint8_t *data, size_t dataLen, AbstractLayer *prevLayer, Packet *packet) : AbstractLayer(data, dataLen, prevLayer,
                                                                                                          packet) { m_Protocol = EthernetDot3; }

    /**
     * A constructor that creates a new IEEE 802.3 Ethernet common and allocates the data
     * @param[in] sourceMac The source MAC address
     * @param[in] destMac The destination MAC address
     * @param[in] length The frame length
     */
    EthDot3Layer(const MacAddress &sourceMac, const MacAddress &destMac, uint16_t length);

    ~EthDot3Layer() override = default;

    /**
     * Get a pointer to the Ethernet common. Notice this points directly to the data, so every change will change the actual packet data
     * @return A pointer to the ether_header
     */
    ether_dot3_header *getEthHeader() const { return (ether_dot3_header *) m_Data; }

    /**
     * Get the source MAC address
     * @return The source MAC address
     */
    MacAddress getSourceMac() const { return {getEthHeader()->srcMac}; }

    /**
     * Set source MAC address
     * @param sourceMac Source MAC to set
     */
    void setSourceMac(const MacAddress &sourceMac) const { sourceMac.copyTo(getEthHeader()->srcMac); }

    /**
     * Get the destination MAC address
     * @return The destination MAC address
     */
    MacAddress getDestMac() const { return {getEthHeader()->dstMac}; }

    /**
     * Set destination MAC address
     * @param destMac Destination MAC to set
     */
    void setDestMac(const MacAddress &destMac) const { destMac.copyTo(getEthHeader()->dstMac); }

    // implement abstract methods

    /**
     * Parses next layer
     */
    void parseNextLayer() override;

    /**
     * @return Size of ether_dot3_header
     */
    size_t getHeaderLen() const override { return sizeof(ether_dot3_header); }

    /**
     * Does nothing for this layer
     */
    void computeCalculateFields() override {}

    std::string toString() const override;

    OsiModelLayer getOsiModelLayer() const override { return OsiModelDataLinkLayer; }

    /**
     * A static method that validates the input data
     * @param[in] data The pointer to the beginning of a byte stream of an IEEE 802.3 Eth packet
     * @param[in] dataLen The length of the byte stream
     * @return True if the data is valid and can represent an IEEE 802.3 Eth packet
     */
    static bool isDataValid(const uint8_t *data, size_t dataLen);
  };

} // namespace pcpp

#endif // PACKETPP_ETH_DOT3_LAYER
