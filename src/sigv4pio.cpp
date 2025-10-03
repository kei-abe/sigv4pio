#include "sigv4pio.hpp"

#include "constants.hpp"
#include "models/StringToSign.hpp"
#include "models/canonicalRequest.hpp"
#include "models/signer.hpp"
#include "utils.hpp"

namespace sigv4pio {
std::string presign_url(const std::string& access_key, const std::string& secret_access_key, const std::string& x_amz_security_token, const std::string& bucket, const std::string& object,
                        const std::string& aws_region, const std::string& x_amz_datetime, const std::string& x_amz_expires) {
  size_t date_index = x_amz_datetime.find("T");
  std::string date = x_amz_datetime.substr(0, date_index);

  // constexpr定数を使用してコンパイル時最適化
  std::string host = bucket + S3_DOMAIN_SUFFIX;

  // 1. Creating a canonical request based on the request details.
  CanonicalRequest canonical_request({
      HTTP_METHOD_GET,
      object,
      CanonicalQueryString(access_key, x_amz_datetime, aws_region, S3_SERVICE, x_amz_expires, SIGNED_HEADERS_HOST, x_amz_security_token),
      CanonicalHeaders(host, "", "", ""),
      SIGNED_HEADERS_HOST,
      UNSIGNED_PAYLOAD,
  });

  StringToSign string_to_sign({
      ALGORITHM,
      x_amz_datetime,
      CredentialScope(date, aws_region, S3_SERVICE),
      canonical_request.hash(),
  });

  // 2. Calculating a signature using your AWS credentials.
  Signer signer(secret_access_key, date, aws_region, S3_SERVICE);

  std::array<uint8_t, 32> signature = signer.sign(string_to_sign);

  // 3. Create a presigned url
  std::string query_string = canonical_request.get_query_string();
  std::string signature_hex = hex_dump(signature);

  // constexpr定数を使用した効率的な連結
  size_t url_size = HTTPS_PREFIX_SIZE + host.size() + object.size() + 1 + query_string.size() + 17 + signature_hex.size();

  std::string presigned_url;
  presigned_url.reserve(url_size);
  presigned_url = HTTPS_PREFIX;
  presigned_url += host;
  presigned_url += object;
  presigned_url += "?";
  presigned_url += query_string;
  presigned_url += X_AMZ_SIGNATURE;
  presigned_url += signature_hex;

  return presigned_url;
}
}  // namespace sigv4pio