/**
 * @file constants.hpp
 * @author K.Abe
 * @brief Compile-time constants for sigv4pio
 */
#pragma once

namespace sigv4pio {
// AWS SigV4 constants
constexpr const char* ALGORITHM = "AWS4-HMAC-SHA256";
constexpr const char* AWS4_REQUEST = "aws4_request";
constexpr const char* AWS4_PREFIX = "AWS4";
constexpr const char* S3_DOMAIN_SUFFIX = ".s3.amazonaws.com";
constexpr const char* HTTPS_PREFIX = "https://";
constexpr const char* UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
constexpr const char* HTTP_METHOD_GET = "GET";
constexpr const char* SIGNED_HEADERS_HOST = "host";
constexpr const char* S3_SERVICE = "s3";

// Query parameter names
constexpr const char* X_AMZ_ALGORITHM = "X-Amz-Algorithm=AWS4-HMAC-SHA256";
constexpr const char* X_AMZ_CREDENTIAL = "&X-Amz-Credential=";
constexpr const char* X_AMZ_DATE = "&X-Amz-Date=";
constexpr const char* X_AMZ_EXPIRES = "&X-Amz-Expires=";
constexpr const char* X_AMZ_SECURITY_TOKEN = "&X-Amz-Security-Token=";
constexpr const char* X_AMZ_SIGNED_HEADERS = "&X-Amz-SignedHeaders=";
constexpr const char* X_AMZ_SIGNATURE = "&X-Amz-Signature=";

// Header names
constexpr const char* HEADER_HOST = "host:";
constexpr const char* HEADER_X_AMZ_CONTENT_SHA256 = "x-amz-content-sha256:";
constexpr const char* HEADER_X_AMZ_DATE = "x-amz-date:";
constexpr const char* HEADER_X_AMZ_SECURITY_TOKEN = "x-amz-security-token:";

// Size constants
constexpr size_t AWS4_PREFIX_SIZE = 4;
constexpr size_t AWS4_REQUEST_SIZE = 13;      // "/aws4_request"
constexpr size_t S3_DOMAIN_SUFFIX_SIZE = 17;  // ".s3.amazonaws.com"
constexpr size_t HTTPS_PREFIX_SIZE = 8;       // "https://"
constexpr size_t HEX_HASH_SIZE = 64;          // 32 bytes * 2 chars
}  // namespace sigv4pio
