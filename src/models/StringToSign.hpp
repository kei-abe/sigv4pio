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

  CredentialScope(const std::string& date, const std::string& aws_region, const std::string& aws_service) : credential_scope(date + "/" + aws_region + "/" + aws_service + "/aws4_request") {}

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

    string_to_sign = algorithm + "\n" + request_datetime + "\n" + std::string(credential_scope) + "\n" + hash_string;
  }

  operator std::string() const { return string_to_sign; }

  bool operator==(const StringToSign& other) const { return string_to_sign == other.string_to_sign; }
};