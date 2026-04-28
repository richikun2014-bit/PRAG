#pragma once

#include "prag/client/interactive_client.hpp"
#include "prag/common/config.hpp"
#include "prag/server/encrypted_index.hpp"
#include "prag/server/homomorphic_ops.hpp"
#include "prag/server/retrieval_engine.hpp"

namespace prag {

/** PRAG-II retrieval using client-assisted encrypted score ordering. */
class RetrievalEnginePRAG2 final : public RetrievalEngine {
public:
    /** Create a PRAG-II retrieval engine over shared encrypted state. */
    RetrievalEnginePRAG2(const Config& config, EncryptedIndex& index, const HomomorphicOps& ops, InteractiveClient& client);

    /** Search encrypted candidates with bounded client assistance. */
    SearchResult search(const Ciphertext& encrypted_query, int top_k, const std::vector<int>& cluster_ids = {}) override;

    /** Search one encrypted cluster in PRAG-II mode. */
    SearchResult searchCluster(const Ciphertext& encrypted_query, int cluster_id, int top_k) override;

private:
    double estimateOee(const std::vector<Ciphertext>& scores) const;

    const Config& config_;
    EncryptedIndex& index_;
    const HomomorphicOps& ops_;
    InteractiveClient& client_;
};

}  // namespace prag

