#pragma once

#include <vector>

#include "prag/common/types.hpp"

namespace prag {

/** Base interface for encrypted retrieval engines. */
class RetrievalEngine {
public:
    /** Destroy a retrieval engine through the interface pointer. */
    virtual ~RetrievalEngine() = default;

    /** Search the encrypted index and return encrypted scores. */
    virtual SearchResult search(const Ciphertext& encrypted_query, int top_k, const std::vector<int>& cluster_ids = {}) = 0;

    /** Search a single encrypted cluster. */
    virtual SearchResult searchCluster(const Ciphertext& encrypted_query, int cluster_id, int top_k) = 0;
};

}  // namespace prag

