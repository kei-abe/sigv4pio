/**
 * @file signer.hpp
 * @author K.Abe
 * @brief signer
 */
#pragma once

#include <mbedtls/md.h>

#include <array>
#include <string>

#include "../constants.hpp"
#include "StringToSign.hpp"

class Signer {
 private:
  std::array<uint8_t, 32> signing_key;

  std::array<uint8_t, 32> hamc_sha256(const uint8_t* key, const size_t key_len, const uint8_t* value, size_t value_len) {
    std::array<uint8_t, 32> signature;
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, key_len, value, value_len, signature.data());
    return signature;
  }

  std::array<uint8_t, 32> hamc_sha256(const std::string& key, const std::string& value) { return hamc_sha256((uint8_t*)key.data(), key.size(), (uint8_t*)value.data(), value.size()); }

  std::array<uint8_t, 32> hamc_sha256(const std::array<uint8_t, 32>& key, const std::string& value) { return hamc_sha256(key.data(), key.size(), (uint8_t*)value.data(), value.size()); }

 public:
  Signer(const std::string& secret_access_key, const std::string& amz_date, const std::string& aws_region, const std::string& aws_service) {
    // Efficient concatenation using constexpr constants
    std::string AWS4;
    AWS4.reserve(sigv4pio::AWS4_PREFIX_SIZE + secret_access_key.size());
    AWS4 = sigv4pio::AWS4_PREFIX;
    AWS4 += secret_access_key;

    auto DateKey = hamc_sha256(AWS4, amz_date);
    auto DateRegionKey = hamc_sha256(DateKey, aws_region);
    auto DateRegionServiceKey = hamc_sha256(DateRegionKey, aws_service);
    signing_key = hamc_sha256(DateRegionServiceKey, sigv4pio::AWS4_REQUEST);
  }
  std::array<uint8_t, 32> sign(const StringToSign& string_to_sign) { return hamc_sha256(signing_key, string_to_sign); };

  std::array<uint8_t, 32> get_signing_key() { return signing_key; }
};