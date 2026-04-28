#include "prag/server/retrieval_prag2.hpp"

#include <algorithm>
#include <set>
#include <queue>

namespace prag {

RetrievalEnginePRAG2::RetrievalEnginePRAG2(
    const Config& config,
    EncryptedIndex& index,
    const HomomorphicOps& ops,
    InteractiveClient& client)
    : config_(config), index_(index), ops_(ops), client_(client) {}

SearchResult RetrievalEnginePRAG2::search(const Ciphertext& encrypted_query, int top_k, const std::vector<int>& cluster_ids) {
    std::vector<std::string> access_path;
    std::string current = index_.entryPoint();
    if (current.empty()) {
        return SearchResult{};
    }

    for (int layer = index_.maxLayer(); layer >= 0; --layer) {
        bool improved = true;
        int guard = 0;
        while (improved && guard++ < config_.hnsw_params.search_depth) {
            improved = false;
            std::vector<std::string> candidates{current};
            std::vector<std::string> layer_neighbors = index_.neighbors(current, layer);
            candidates.insert(candidates.end(), layer_neighbors.begin(), layer_neighbors.end());
            std::vector<Ciphertext> local_scores;
            local_scores.reserve(candidates.size());
            for (const std::string& identifier : candidates) {
                local_scores.push_back(ops_.l2Score(encrypted_query, index_.node(identifier).vector.ciphertext));
            }
            const int chosen = client_.decryptAndCompare(local_scores);
            if (chosen > 0 && candidates[chosen] != current) {
                current = candidates[chosen];
                improved = true;
            }
            access_path.push_back(current);
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
            if (cluster_ids.empty() || std::find(cluster_ids.begin(), cluster_ids.end(), index_.node(neighbor).cluster_id) != cluster_ids.end()) {
                if (visited.insert(neighbor).second) {
                    frontier.push(neighbor);
                }
            }
        }
    }

    std::vector<std::string> candidate_ids(visited.begin(), visited.end());
    std::vector<Ciphertext> scores;
    scores.reserve(candidate_ids.size());
    for (const std::string& identifier : candidate_ids) {
        scores.push_back(ops_.l2Score(encrypted_query, index_.node(identifier).vector.ciphertext));
    }
    const std::vector<int> order = client_.decryptAndTopK(scores, std::min<int>(top_k, scores.size()));
    SearchResult result;
    result.mode = modeName(PRAGMode::PRAG_II);
    for (const Ciphertext& score : scores) {
        result.communication_bytes += score.byteSize();
    }
    for (int idx : order) {
        result.identifiers.push_back(candidate_ids[idx]);
        result.encrypted_scores.push_back(scores[idx]);
        result.access_paths.push_back(access_path);
        result.communication_bytes += scores[idx].byteSize();
    }
    result.oee_bound = estimateOee(result.encrypted_scores);
    index_.nextQueryCounter();
    return result;
}

SearchResult RetrievalEnginePRAG2::searchCluster(const Ciphertext& encrypted_query, int cluster_id, int top_k) {
    return search(encrypted_query, top_k, {cluster_id});
}

double RetrievalEnginePRAG2::estimateOee(const std::vector<Ciphertext>& scores) const {
    double max_noise = 0.0;
    for (const Ciphertext& score : scores) {
        max_noise = std::max(max_noise, score.noise());
    }
    return max_noise;
}

}  // namespace prag
