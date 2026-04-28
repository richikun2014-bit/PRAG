#include "prag/server/update_prag1.hpp"

#include <algorithm>

namespace prag {

UpdateEnginePRAG1::UpdateEnginePRAG1(const Config& config, EncryptedIndex& index, const HomomorphicOps& ops)
    : config_(config),
      index_(index),
      ops_(ops),
      cheby_(config.chebyshev_degree, config.chebyshev_scale, ops.context(), ops.evaluationKey(), ops.scale()) {}

UpdateResult UpdateEnginePRAG1::insert(const EncryptedVector& encrypted_vector, int cluster_id) {
    const int layer = index_.randomLayer();
    const std::vector<std::string> candidate_ids = index_.activeIds({cluster_id});
    EncryptedNode node{encrypted_vector.identifier, encrypted_vector, cluster_id, layer, false};
    index_.insertNode(node);
    if (candidate_ids.empty()) {
        return UpdateResult{true, encrypted_vector.identifier, "insert", 0, "Inserted as entry point."};
    }
    std::vector<Ciphertext> scores;
    scores.reserve(candidate_ids.size());
    for (const std::string& identifier : candidate_ids) {
        scores.push_back(ops_.l2Score(encrypted_vector.ciphertext, index_.node(identifier).vector.ciphertext));
    }
    const std::vector<Ciphertext> encrypted_weights = cheby_.evaluateAll(scores);
    const int selected_count = std::min<int>(config_.hnsw_params.max_degree, encrypted_weights.size());
    for (int idx = 0; idx < selected_count; ++idx) {
        const std::string& target_id = candidate_ids[idx];
        const int max_layer = std::min(layer, index_.node(target_id).max_layer);
        for (int link_layer = 0; link_layer <= max_layer; ++link_layer) {
            index_.link(encrypted_vector.identifier, target_id, link_layer);
        }
    }
    return UpdateResult{true, encrypted_vector.identifier, "insert", selected_count, "Inserted with encrypted Chebyshev scores and deterministic links."};
}

UpdateResult UpdateEnginePRAG1::remove(const std::string& identifier) {
    const bool ok = index_.markDeleted(identifier);
    return UpdateResult{ok, identifier, "remove", ok ? 1 : 0, ok ? "Marked for offline sweep." : "Node not found."};
}

UpdateResult UpdateEnginePRAG1::sweep() {
    const int count = index_.sweepDeleted();
    return UpdateResult{true, "*", "sweep", count, "Swept deleted nodes."};
}

}  // namespace prag
