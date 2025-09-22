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
    static char hex[] = "0123456789ABCDEF";
    std::string buf;
    buf.resize(str.size() * 3 + 1);
    size_t i = 0;
    for (const auto& c : str) {
      if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        buf[i++] = c;
      else if (c == ' ')
        buf[i++] = '+';
      else
        buf[i++] = '%', buf[i++] = hex[(c >> 4) & 15], buf[i++] = hex[(c & 15) & 15];
    }
    buf[i] = '\0';
    buf.resize(i);
    return buf;
  }

  CanonicalQueryString(const std::string& access_key, const std::string& amz_datetime, const std::string& aws_region, const std::string& aws_service, const std::string& x_amz_expires,
                       const std::string& x_amz_signed_headers, const std::string& x_amz_security_token) {
    query_string = "X-Amz-Algorithm=AWS4-HMAC-SHA256";

    size_t date_index = amz_datetime.find("T");
    std::string amz_date = amz_datetime.substr(0, date_index);

    std::string aws4_request = access_key + "/" + amz_date + "/" + aws_region + "/" + aws_service + "/aws4_request";
    std::string credential = aws_sigV4_url_encode(aws4_request);

    query_string += "&X-Amz-Credential=" + credential;
    query_string += "&X-Amz-Date=" + amz_datetime;
    query_string += "&X-Amz-Expires=" + x_amz_expires;

    std::string URL_security_token = "";
    if (x_amz_security_token != "") {
      URL_security_token = aws_sigV4_url_encode(x_amz_security_token);
    }
    query_string += "&X-Amz-Security-Token=" + URL_security_token;
    query_string += "&X-Amz-SignedHeaders=" + x_amz_signed_headers;
  }
};

struct CanonicalHeaders {
  std::string canonical_headers;
  CanonicalHeaders(const std::string& host, const std::string& x_amz_content_sha256, const std::string& x_amz_date, const std::string& x_amz_security_token) {
    canonical_headers = "host:" + host + "\n";
    if (x_amz_content_sha256 != "") {
      canonical_headers += "x-amz-content-sha256:" + x_amz_content_sha256 + "\n";
    }
    if (x_amz_date != "") {
      canonical_headers += "x-amz-date:" + x_amz_date + "\n";
    }
    if (x_amz_security_token != "") {
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