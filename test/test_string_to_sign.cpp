/**
 * @file test_string_to_sign.cpp
 * @author K.Abe
 * @brief test string to sign
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/models/StringToSign.hpp"

class StringToSignTest : public ::testing::Test {
 protected:
  void SetUp() override {}

  void TearDown() override {}
};

TEST_F(StringToSignTest, create_string_to_sign) {
  std::array<uint8_t, 32> hashed_canonical_request = {0x12, 0x34, 0x56, 0x78, 0x90};
  std::string date = "20250101";
  std::string datetime = date + "T010000Z";
  auto string_to_sign = StringToSign({
      "AWS4-HMAC-SHA256",
      datetime,
      CredentialScope(date, "us-east-1", "s3"),
      hashed_canonical_request,
  });

  ASSERT_EQ(std::string(string_to_sign), "AWS4-HMAC-SHA256\n20250101T010000Z\n20250101/us-east-1/s3/aws4_request\n1234567890000000000000000000000000000000000000000000000000000000");
}