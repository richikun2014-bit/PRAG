#pragma once

#include "prag/common/chebyshev.hpp"
#include "prag/common/config.hpp"
#include "prag/server/encrypted_index.hpp"
#include "prag/server/homomorphic_ops.hpp"
#include "prag/server/retrieval_engine.hpp"

namespace prag {

/** PRAG-I retrieval using Chebyshev-based encrypted ranking surrogates. */
class RetrievalEnginePRAG1 final : public RetrievalEngine {
public:
    /** Create a PRAG-I retrieval engine over shared encrypted state. */
    RetrievalEnginePRAG1(const Config& config, EncryptedIndex& index, const HomomorphicOps& ops);

    /** Search encrypted candidates without client interaction. */
    SearchResult search(const Ciphertext& encrypted_query, int top_k, const std::vector<int>& cluster_ids = {}) override;

    /** Search one encrypted cluster in PRAG-I mode. */
    SearchResult searchCluster(const Ciphertext& encrypted_query, int cluster_id, int top_k) override;

private:
    std::vector<std::vector<std::string>> perturbedPaths(const std::vector<std::string>& real_ids, const std::vector<std::string>& candidate_ids);
    double estimateOee(const std::vector<Ciphertext>& scores, const std::vector<std::vector<std::string>>& paths) const;

    const Config& config_;
    EncryptedIndex& index_;
    const HomomorphicOps& ops_;
    ChebyshevApprox cheby_;
};

}  // namespace prag

