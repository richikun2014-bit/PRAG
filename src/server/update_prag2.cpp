#include "prag/server/update_prag2.hpp"

#include <algorithm>
#include <queue>
#include <set>

namespace prag {

UpdateEnginePRAG2::UpdateEnginePRAG2(
    const Config& config,
    EncryptedIndex& index,
    const HomomorphicOps& ops,
    InteractiveClient& client)
    : config_(config), index_(index), ops_(ops), client_(client) {}

UpdateResult UpdateEnginePRAG2::insert(const EncryptedVector& encrypted_vector, int cluster_id) {
    const int layer = index_.randomLayer();
    std::vector<std::string> candidate_ids = index_.activeIds({cluster_id});
    EncryptedNode node{encrypted_vector.identifier, encrypted_vector, cluster_id, layer, false};
    index_.insertNode(node);
    if (candidate_ids.empty()) {
        return UpdateResult{true, encrypted_vector.identifier, "insert", 0, "Inserted as entry point."};
    }

    std::string current = index_.entryPoint();
    if (current == encrypted_vector.identifier && !candidate_ids.empty()) {
        current = candidate_ids.front();
    }
    for (int search_layer = index_.maxLayer(); search_layer > layer; --search_layer) {
        bool improved = true;
        int guard = 0;
        while (improved && guard++ < config_.hnsw_params.search_depth) {
            improved = false;
            std::vector<std::string> local{current};
            std::vector<std::string> neighbors = index_.neighbors(current, search_layer);
            local.insert(local.end(), neighbors.begin(), neighbors.end());
            local.erase(
                std::remove(local.begin(), local.end(), encrypted_vector.identifier),
                local.end());
            std::vector<Ciphertext> local_scores;
            for (const std::string& identifier : local) {
                local_scores.push_back(ops_.l2Score(encrypted_vector.ciphertext, index_.node(identifier).vector.ciphertext));
            }
            const int chosen = client_.decryptAndCompare(local_scores);
            if (chosen > 0 && chosen < static_cast<int>(local.size()) && local[chosen] != current) {
                current = local[chosen];
                improved = true;
            }
        }
    }

    std::set<std::string> visited;
    std::queue<std::string> frontier;
    frontier.push(current);
    visited.insert(current);
    while (!frontier.empty() && static_cast<int>(visited.size()) < config_.hnsw_params.search_depth) {
        const std::string node_id = frontier.front();
        frontier.pop();
        for (const std::string& neighbor : index_.neighbors(node_id, 0)) {
            if (neighbor != encrypted_vector.identifier && index_.node(neighbor).cluster_id == cluster_id && visited.insert(neighbor).second) {
                frontier.push(neighbor);
            }
        }
    }
    candidate_ids.assign(visited.begin(), visited.end());

    std::vector<Ciphertext> scores;
    scores.reserve(candidate_ids.size());
    for (const std::string& identifier : candidate_ids) {
        scores.push_back(ops_.l2Score(encrypted_vector.ciphertext, index_.node(identifier).vector.ciphertext));
    }
    const std::vector<int> selected = client_.decryptAndTopK(scores, std::min<int>(config_.hnsw_params.max_degree, scores.size()));
    for (int idx : selected) {
        const std::string& target_id = candidate_ids[idx];
        const int max_layer = std::min(layer, index_.node(target_id).max_layer);
        for (int link_layer = 0; link_layer <= max_layer; ++link_layer) {
            index_.link(encrypted_vector.identifier, target_id, link_layer);
        }
    }
    return UpdateResult{true, encrypted_vector.identifier, "insert", static_cast<int>(selected.size()), "Inserted with client-assisted links."};
}

UpdateResult UpdateEnginePRAG2::remove(const std::string& identifier) {
    const bool ok = index_.markDeleted(identifier);
    return UpdateResult{ok, identifier, "remove", ok ? 1 : 0, ok ? "Marked for offline sweep." : "Node not found."};
}

UpdateResult UpdateEnginePRAG2::sweep() {
    const int count = index_.sweepDeleted();
    return UpdateResult{true, "*", "sweep", count, "Swept deleted nodes."};
}

}  // namespace prag
