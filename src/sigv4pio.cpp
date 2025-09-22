#include "sigv4pio.hpp"

#include "models/StringToSign.hpp"
#include "models/canonicalRequest.hpp"
#include "models/signer.hpp"
#include "utils.hpp"

namespace sigv4pio {
std::string presign_url(const std::string& access_key, const std::string& secret_access_key, const std::string& x_amz_security_token, const std::string& bucket, const std::string& object,
                        const std::string& aws_region, const std::string& x_amz_datetime, const std::string& x_amz_expires) {
  size_t date_index = x_amz_datetime.find("T");
  std::string date = x_amz_datetime.substr(0, date_index);

  std::string host = bucket + ".s3.amazonaws.com";

  // 1. Creating a canonical request based on the request details.
  CanonicalRequest canonical_request({
      "GET",
      object,
      CanonicalQueryString(access_key, x_amz_datetime, aws_region, "s3", x_amz_expires, "host", x_amz_security_token),
      CanonicalHeaders(bucket + ".s3.amazonaws.com", "", "", ""),
      "host",
      "UNSIGNED-PAYLOAD",
  });

  StringToSign string_to_sign({
      "AWS4-HMAC-SHA256",
      x_amz_datetime,
      CredentialScope(date, aws_region, "s3"),
      canonical_request.hash(),
  });

  // 2. Calculating a signature using your AWS credentials.
  Signer signer(secret_access_key, date, aws_region, "s3");

  std::array<uint8_t, 32> signature = signer.sign(string_to_sign);

  // 3. Adding this signature to the request as an Authorization header.
  std::string presigned_url = "https://" + host + object + "?" + canonical_request.get_query_string() + "&X-Amz-Signature=" + hex_dump(signature);

  return presigned_url;
}
}  // namespace sigv4pio