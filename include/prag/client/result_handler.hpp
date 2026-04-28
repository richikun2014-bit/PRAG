#pragma once

#include <string>
#include <vector>

#include "prag/client/crypto_utils.hpp"
#include "prag/common/types.hpp"

namespace prag {

/** Trusted client-side result decryption and reranking helper. */
class ResultHandler {
public:
    /** Create a result handler with trusted secret key access. */
    ResultHandler(const CryptoUtils& crypto, SecretKey secret_key);

    /** Decrypt encrypted result scores. */
    std::vector<double> decryptScores(const SearchResult& result) const;

    /** Rerank identifiers using decrypted scores. */
    std::vector<std::string> rerank(const SearchResult& result) const;

private:
    const CryptoUtils& crypto_;
    SecretKey secret_key_;
};

}  // namespace prag

