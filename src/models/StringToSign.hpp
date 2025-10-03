/**
 * @file StringToSign.hpp
 * @author K.Abe
 * @brief string to sign
 */
#pragma once

#include <string>

#include "utils.hpp"

struct CredentialScope {
  std::string credential_scope;

  CredentialScope(const std::string& date, const std::string& aws_region, const std::string& aws_service) {
    // 事前サイズ計算して効率的な連結
    size_t total_size = date.size() + 1 + aws_region.size() + 1 + aws_service.size() + 13;  // "/aws4_request"
    credential_scope.reserve(total_size);

    credential_scope = date;
    credential_scope += "/";
    credential_scope += aws_region;
    credential_scope += "/";
    credential_scope += aws_service;
    credential_scope += "/aws4_request";
  }

  operator std::string() const { return credential_scope; }
};

/**
 * @brief String to sign
 * @see https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html#create-string-to-sign
 *
 */
class StringToSign {
 private:
  std::string string_to_sign;

 public:
  StringToSign(const std::string& algorithm, const std::string& request_datetime, const CredentialScope& credential_scope, const std::array<uint8_t, 32>& hashed_canonical_request) {
    std::string hash_string = hex_dump(hashed_canonical_request);
    std::string credential_str = credential_scope;

    size_t total_size = algorithm.size() + 1 + request_datetime.size() + 1 + credential_str.size() + 1 + hash_string.size();

    string_to_sign.reserve(total_size);

    string_to_sign = algorithm;
    string_to_sign += "\n";
    string_to_sign += request_datetime;
    string_to_sign += "\n";
    string_to_sign += credential_str;
    string_to_sign += "\n";
    string_to_sign += hash_string;
  }

  operator std::string() const { return string_to_sign; }

  bool operator==(const StringToSign& other) const { return string_to_sign == other.string_to_sign; }
};