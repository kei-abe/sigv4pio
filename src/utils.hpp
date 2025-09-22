/**
 * @file utils.hpp
 * @author K.Abe
 * @brief utils
 */
#pragma once

#include <iomanip>
#include <sstream>
#include <string>

inline std::string hex_dump(const std::array<uint8_t, 32>& arr) {
  std::ostringstream oss;
  for (const auto& c : arr) {
    oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
  }
  return oss.str();
}
