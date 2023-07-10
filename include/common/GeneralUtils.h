#ifndef PCAPPP_GENERAL_UTILS
#define PCAPPP_GENERAL_UTILS

#include <string>
#include <stdint.h>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp {
  /**
   * 将字节数组转换成十六进制字符串. 比如对于数组: {0xaa, 0x2b, 0x10} 转换后字符串为 "aa2b10"
   * @param[in] byteArr 字节数组
   * @param[in] byteArrSize 数组的字节大小 [in bytes]
   * @param[in] stringSizeLimit 一个可选参数，允许限制返回的字符串大小。
   * 如果设置为正整数值，返回的字符串大小将等于或小于该值。如果整个数组
   * 的字符串表示长度超过这个长度，那么只有数组的一部分会被读取。
   * 默认值为-1，表示没有字符串大小限制
   * @return 表示字节数组的十六进制字符串
   */
  std::string byteArrayToHexString(const uint8_t *byteArr, size_t byteArrSize, int stringSizeLimit = -1);

  /**
   * 将十六进制字符串转换为字节数组。例如:“aa2b10 ” -> { 0xaa, 0x2b, 0x10 }
   *
   * @param[in] hexString 一串十六进制字符
   * @param[out] resultByteArr buffer 数组
   * @param[in] resultByteArrSize buffer 数组的字节大小
   * @return The size of the result array. If the string represents an array that is longer than the pre-allocated size
   * (resultByteArrSize) then the result array will contain only the part of the string that managed to fit into the
   * array, and the returned size will be resultByteArrSize. However if the string represents an array that is shorter
   * than the pre-allocated size then some of the cells will remain empty and contain zeros, and the returned size will
   * be the part of the array that contain data. If the input is an illegal hex string 0 will be returned.
   * Illegal hex string means odd number of characters or a string that contains non-hex characters
   */
  size_t hexStringToByteArray(const std::string &hexString, uint8_t *resultByteArr, size_t resultByteArrSize);

  /**
   * This is a cross platform version of memmem (https://man7.org/linux/man-pages/man3/memmem.3.html) which is not supported
   * on all platforms.
   * @param[in] haystack A pointer to the buffer to be searched
   * @param[in] haystackLen Length of the haystack buffer
   * @param[in] needle A pointer to a buffer that will be searched for
   * @param[in] needleLen Length of the needle buffer
   * @return A pointer to the beginning of the substring, or NULL if the substring is not found
   */
  char *cross_platform_memmem(const char *haystack, size_t haystackLen, const char *needle, size_t needleLen);
}

#endif // PCAPPP_GENERAL_UTILS
