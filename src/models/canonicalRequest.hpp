/**
 * @file canonicalRequest.hpp
 * @author K.Abe
 * @brief canonical request
 */
#pragma once

#include <mbedtls/md.h>

#include <array>
#include <string>

struct CanonicalQueryString {
  std::string query_string;

  std::string aws_sigV4_url_encode(const std::string& str) {
    // SigV4 requires uppercase hex
    static const char hex[] = "0123456789ABCDEF";

    // Step 1: calculate the actual size needed
    size_t encoded_size = 0;
    for (const auto& c : str) {
      if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
        encoded_size += 1;
      } else if (c == ' ') {
        encoded_size += 1;
      } else {
        encoded_size += 3;
      }
    }

    // Step 2: allocate the buffer with the exact size
    std::string buf;
    buf.reserve(encoded_size);

    // Step 3: encode the string
    for (const auto& c : str) {
      if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
        buf += c;
      } else if (c == ' ') {
        buf += '+';
      } else {
        buf += '%';
        buf += hex[(c >> 4) & 15];
        buf += hex[c & 0x0F];
      }
    }

    return buf;
  }

  CanonicalQueryString(const std::string& access_key, const std::string& amz_datetime, const std::string& aws_region, const std::string& aws_service, const std::string& x_amz_expires,
                       const std::string& x_amz_signed_headers, const std::string& x_amz_security_token) {
    // Step 1: prepare the necessary strings
    size_t date_index = amz_datetime.find("T");
    std::string amz_date = amz_datetime.substr(0, date_index);

    std::string aws4_request = access_key + "/" + amz_date + "/" + aws_region + "/" + aws_service + "/aws4_request";
    std::string credential = aws_sigV4_url_encode(aws4_request);
    std::string URL_security_token = x_amz_security_token.empty() ? "" : aws_sigV4_url_encode(x_amz_security_token);

    // Step 2: calculate the total size and allocate the buffer
    size_t total_size = 25 +                               // "X-Amz-Algorithm=AWS4-HMAC-SHA256"
                        17 + credential.size() +           // "&X-Amz-Credential=" + credential
                        12 + amz_datetime.size() +         // "&X-Amz-Date=" + amz_datetime
                        14 + x_amz_expires.size() +        // "&X-Amz-Expires=" + x_amz_expires
                        21 + URL_security_token.size() +   // "&X-Amz-Security-Token=" + URL_security_token
                        20 + x_amz_signed_headers.size();  // "&X-Amz-SignedHeaders=" + x_amz_signed_headers

    query_string.reserve(total_size);

    // Step 3: create the query string
    query_string = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=" + credential + "&X-Amz-Date=" + amz_datetime + "&X-Amz-Expires=" + x_amz_expires +
                   "&X-Amz-Security-Token=" + URL_security_token + "&X-Amz-SignedHeaders=" + x_amz_signed_headers;
  }
};

struct CanonicalHeaders {
  std::string canonical_headers;
  CanonicalHeaders(const std::string& host, const std::string& x_amz_content_sha256, const std::string& x_amz_date, const std::string& x_amz_security_token) {
    // Step 1: calculate the total size and allocate the buffer
    size_t total_size = 5 + host.size() + 1;  // "host:" + host + "\n"

    if (!x_amz_content_sha256.empty()) {
      total_size += 22 + x_amz_content_sha256.size() + 1;  // "x-amz-content-sha256:" + value + "\n"
    }
    if (!x_amz_date.empty()) {
      total_size += 12 + x_amz_date.size() + 1;  // "x-amz-date:" + value + "\n"
    }
    if (!x_amz_security_token.empty()) {
      total_size += 21 + x_amz_security_token.size() + 1;  // "x-amz-security-token:" + value + "\n"
    }

    canonical_headers.reserve(total_size);

    // Step 2: create the canonical headers
    canonical_headers = "host:" + host + "\n";

    if (!x_amz_content_sha256.empty()) {
      canonical_headers += "x-amz-content-sha256:" + x_amz_content_sha256 + "\n";
    }
    if (!x_amz_date.empty()) {
      canonical_headers += "x-amz-date:" + x_amz_date + "\n";
    }
    if (!x_amz_security_token.empty()) {
      canonical_headers += "x-amz-security-token:" + x_amz_security_token + "\n";
    }
  }
};

/**
 * @brief Canonical request
 * @see https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html#create-canonical-request
 *
 */
class CanonicalRequest {
 private:
  std::string query_string;
  std::string canonical_request;
  std::array<uint8_t, 32> canonical_request_hash;

 public:
  CanonicalRequest(const std::string& method, const std::string& canonical_uri, const CanonicalQueryString& canonical_query_string, const CanonicalHeaders& canonical_headers,
                   const std::string& signed_headers, const std::string& hashed_payload) {
    size_t total_size = method.size() + 1 + canonical_uri.size() + 1 + canonical_query_string.query_string.size() + 1 + canonical_headers.canonical_headers.size() + 1 + signed_headers.size() + 1 +
                        hashed_payload.size();
    canonical_request.reserve(total_size);

    canonical_request = method;
    canonical_request += "\n" + canonical_uri;
    canonical_request += "\n" + canonical_query_string.query_string;
    canonical_request += "\n" + canonical_headers.canonical_headers;
    canonical_request += "\n" + signed_headers;
    canonical_request += "\n" + hashed_payload;

    query_string = canonical_query_string.query_string;

    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (unsigned char*)canonical_request.data(), canonical_request.size(), (unsigned char*)canonical_request_hash.data());
  }

  std::string get_canonical_request() { return canonical_request; }

  std::array<uint8_t, 32> hash() { return canonical_request_hash; }

  std::string get_query_string() { return query_string; }
};