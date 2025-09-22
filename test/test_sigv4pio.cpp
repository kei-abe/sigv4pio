/**
 * @file test_sigv4pio.cpp
 * @author K.Abe
 * @brief test sigv4pio
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "../include/sigv4pio.hpp"

class Sigv4ForPioTest : public ::testing::Test {
 protected:
  void SetUp() override {}

  void TearDown() override {}
};

TEST_F(Sigv4ForPioTest, presign_url) {
  std::string access_key = "ACCESS_KEY";
  std::string secret_access_key = "SECRET_ACCESS_KEY";
  std::string security_token =
      "sample_security_token//////////sample_a/sample_b"
      "sample_c/sample_d/sample_e/sample_f/sample_g/sample_h/sample_i/sample_j";
  std::string bucket = "BUCKET";
  std::string path = "/PATH";
  std::string region = "ap-northeast-1";
  std::string amzTime = "20250101T0100Z";

  std::string presigned_url = sigv4pio::presign_url(access_key, secret_access_key, security_token, bucket, path, region, amzTime, "1000");

  ASSERT_EQ(presigned_url,
            "https://BUCKET.s3.amazonaws.com/"
            "PATH?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ACCESS_KEY%2F20250101%2Fap-northeast-1%2Fs3%2Faws4_request&X-Amz-Date=20250101T0100Z&X-Amz-Expires=1000&X-Amz-Security-Token="
            "sample_security_token%2F%2F%2F%2F%2F%2F%2F%2F%2F%2Fsample_a%2Fsample_bsample_c%2Fsample_d%2Fsample_e%2Fsample_f%2Fsample_g%2Fsample_h%2Fsample_i%2Fsample_j&X-Amz-SignedHeaders=host&X-"
            "Amz-Signature=083464ac22f98133993c1ef8f08549f21629708168ea59405afcb959e882e151");
}