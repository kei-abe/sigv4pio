/**
 * @file test_canonical_request.cpp
 * @author K.Abe
 * @brief test canonical request
 */
#include <gtest/gtest.h>

#include <string>

#include "../src/models/canonicalRequest.hpp"

class CanonicalRequestTest : public ::testing::Test {
 protected:
  void SetUp() override {}
};

TEST_F(CanonicalRequestTest, create_canonical_query_string) {
  CanonicalQueryString canonical_query_string("access_key", "20250101T010000Z", "us-east-1", "s3", "10", "host", "security_token");
  ASSERT_EQ(canonical_query_string.query_string,
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&"
            "X-Amz-Credential=access_key%2F20250101%2Fus-east-1%2Fs3%2Faws4_request&"
            "X-Amz-Date=20250101T010000Z&"
            "X-Amz-Expires=10&X-Amz-Security-Token=security_token&"
            "X-Amz-SignedHeaders=host");
}

TEST_F(CanonicalRequestTest, create_canonical_headers_string) {
  auto canonical_headers_string = CanonicalHeaders("example.com", "1234567890", "20250101", "1234567890");

  ASSERT_EQ(canonical_headers_string.canonical_headers, "host:example.com\nx-amz-content-sha256:1234567890\nx-amz-date:20250101\nx-amz-security-token:1234567890\n");
}

TEST_F(CanonicalRequestTest, create_canonical_request) {
  CanonicalQueryString canonical_query_string("access_key", "20250101T010000Z", "us-east-1", "s3", "10", "host", "security_token");
  CanonicalHeaders canonical_headers("example.com", "1234567890", "20250101", "1234567890");
  auto canonical_request = CanonicalRequest("GET", "object", canonical_query_string, canonical_headers, "host", "UNSIGNED-PAYLOAD");

  std::array<uint8_t, 32> reference_canonical_request = {0x5F, 0xD3, 0x37, 0x70, 0xB5, 0x99, 0xE1, 0x3C, 0x4E, 0xFB, 0x9F, 0x14, 0xC3, 0xAE, 0xC3, 0xD6,
                                                         0x6E, 0x86, 0xD8, 0xD4, 0x54, 0x4D, 0x00, 0x88, 0xFE, 0xD8, 0x95, 0x51, 0xF2, 0x12, 0x0F, 0xCB};

  auto hash = canonical_request.hash();
  ASSERT_EQ(hash, reference_canonical_request);
}