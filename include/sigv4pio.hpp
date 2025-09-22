/**
 * @file sigv4pio.hpp
 * @author K.Abe
 * @brief simple interface for sigv4 presigned url to get access to AWS S3 items
 * @see https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
 */
#pragma once

#include <string>

namespace sigv4pio {
std::string presign_url(const std::string& access_key, const std::string& secret_access_key, const std::string& x_amz_security_token, const std::string& bucket, const std::string& object,
                        const std::string& aws_region, const std::string& x_amz_datetime, const std::string& x_amz_expires);
}  // namespace sigv4pio