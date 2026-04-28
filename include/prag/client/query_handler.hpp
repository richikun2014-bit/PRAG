#pragma once

#include <unordered_map>
#include <vector>

#include "prag/client/crypto_utils.hpp"

namespace prag {

/** Client-side query preparation helper. */
class QueryHandler {
public:
    /** Create a query handler bound to crypto utilities and a public key. */
    QueryHandler(const CryptoUtils& crypto, PublicKey public_key);

    /** Encrypt a query vector. */
    Ciphertext encryptQueryVector(const std::vector<double>& vector) const;

    /** Select aggregate clusters on the trusted client side. */
    std::vector<int> selectClusters(
        const std::vector<double>& query_vector,
        const std::unordered_map<int, std::vector<double>>& centroids,
        int cluster_probe) const;

private:
    const CryptoUtils& crypto_;
    PublicKey public_key_;
};

}  // namespace prag

