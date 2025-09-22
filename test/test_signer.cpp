/**
 * @file test_signer.cpp
 * @author K.Abe
 * @brief test signer
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/models/signer.hpp"

class SignerTest : public ::testing::Test {
 protected:
  void SetUp() override {}

  void TearDown() override {}
};

TEST_F(SignerTest, create_signing_key) {
  auto signing_key = Signer("1234567890", "20250101", "us-east-1", "s3").get_signing_key();

  // This time, the key should be the same as following.
  std::array<uint8_t, 32> reference_key = {0x9f, 0x7d, 0x7c, 0x69, 0x61, 0xb7, 0xbd, 0x25, 0xc8, 0xa7, 0xa5, 0x89, 0xbf, 0xe4, 0xec, 0x52,
                                           0xf6, 0x46, 0x3e, 0xd3, 0x2e, 0x76, 0x90, 0x47, 0xc5, 0x34, 0x8a, 0x03, 0x68, 0x8a, 0x5d, 0xcf};

  ASSERT_EQ(signing_key, reference_key);
}

TEST_F(SignerTest, sign) {
  StringToSign string_to_sign("AWS4-HMAC-SHA256", "20250101T010000Z", CredentialScope("20250101", "us-east-1", "s3"), {0x12, 0x34, 0x56, 0x78, 0x90});
  auto signer = Signer("1234567890", "20250101", "us-east-1", "s3");
  auto signature_hex = signer.sign(string_to_sign);

  printf("signature_hex: %s\n", hex_dump(signature_hex).c_str());

  // This time, the signature should be the same as following.
  std::array<uint8_t, 32> reference_signature = {0x4b, 0xfa, 0x2a, 0xf0, 0x19, 0xd7, 0x52, 0xd3, 0xef, 0x72, 0x09, 0x26, 0x97, 0xc9, 0x8b, 0xa8,
                                                 0xc4, 0x55, 0x48, 0x5c, 0xe6, 0xd1, 0x57, 0x66, 0x9b, 0x8e, 0x9f, 0x06, 0x3a, 0x39, 0xb2, 0x2a};

  ASSERT_EQ(signature_hex, reference_signature);
}