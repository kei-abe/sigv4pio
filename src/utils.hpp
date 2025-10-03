/**
 * @file utils.hpp
 * @author K.Abe
 * @brief utils
 */
#pragma once

#include <array>
#include <string>

inline std::string hex_dump(const std::array<uint8_t, 32>& arr) {
  static const char hex_chars[] = "0123456789abcdef";

  // fixed size buffer
  std::string result;
  result.reserve(64);

  // convert to hex
  for (const auto& byte : arr) {
    result += hex_chars[(byte >> 4) & 0x0F];
    result += hex_chars[byte & 0x0F];
  }

  return result;
}
