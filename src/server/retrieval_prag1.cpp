#include "prag/server/retrieval_prag1.hpp"

#include <algorithm>
#include <cstdint>
#include <set>
#include <random>

namespace prag {

RetrievalEnginePRAG1::RetrievalEnginePRAG1(const Config& config, EncryptedIndex& index, const HomomorphicOps& ops)
    : config_(config),
      index_(index),
      ops_(ops),
      cheby_(config.chebyshev_degree, config.chebyshev_scale, ops.context(), ops.evaluationKey(), ops.scale()) {}

SearchResult RetrievalEnginePRAG1::search(const Ciphertext& encrypted_query, int top_k, const std::vector<int>& cluster_ids) {
    std::vector<std::string> frontier;
    if (!index_.entryPoint().empty()) {
        frontier.push_back(index_.entryPoint());
    }
    const int beam_width = std::max(1, config_.hnsw_params.max_degree);
    std::vector<std::vector<std::string>> observed_paths;

    for (int layer = index_.maxLayer(); layer >= 0; --layer) {
        std::set<std::string> expanded(frontier.begin(), frontier.end());
        for (const std::string& identifier : frontier) {
            for (const std::string& neighbor : index_.neighbors(identifier, layer)) {
                if (cluster_ids.empty() || std::find(cluster_ids.begin(), cluster_ids.end(), index_.node(neighbor).cluster_id) != cluster_ids.end()) {
                    expanded.insert(neighbor);
                }
            }
        }
        std::vector<std::string> candidates(expanded.begin(), expanded.end());
        if (candidates.empty()) {
            candidates = index_.activeIds(cluster_ids);
        }
        std::vector<Ciphertext> layer_scores;
        layer_scores.reserve(candidates.size());
        for (const std::string& identifier : candidates) {
            layer_scores.push_back(ops_.l2Score(encrypted_query, index_.node(identifier).vector.ciphertext));
        }
        const std::vector<Ciphertext> encrypted_weights = cheby_.evaluateAll(layer_scores);
        (void)encrypted_weights;

        observed_paths.push_back(candidates);
        frontier.clear();
        for (int i = 0; i < std::min<int>(beam_width, candidates.size()); ++i) {
            frontier.push_back(candidates[i]);
        }
    }

    std::vector<std::string> candidate_ids = frontier.empty() ? index_.activeIds(cluster_ids) : frontier;
    std::vector<Ciphertext> scores;
    scores.reserve(candidate_ids.size());
    for (const std::string& identifier : candidate_ids) {
        scores.push_back(ops_.l2Score(encrypted_query, index_.node(identifier).vector.ciphertext));
    }
    const std::vector<Ciphertext> cheby_scores = cheby_.evaluateAll(scores);
    SearchResult result;
    result.mode = modeName(PRAGMode::PRAG_I);
    const int count = std::min<int>(top_k, cheby_scores.size());
    for (int idx = 0; idx < count; ++idx) {
        result.identifiers.push_back(candidate_ids[idx]);
        result.encrypted_scores.push_back(cheby_scores[idx]);
        result.communication_bytes += cheby_scores[idx].byteSize();
    }
    result.access_paths = observed_paths;
    const std::vector<std::vector<std::string>> dummy_paths = perturbedPaths(result.identifiers, candidate_ids);
    result.access_paths.insert(result.access_paths.end(), dummy_paths.begin(), dummy_paths.end());
    result.oee_bound = estimateOee(result.encrypted_scores, result.access_paths);
    index_.nextQueryCounter();
    return result;
}

SearchResult RetrievalEnginePRAG1::searchCluster(const Ciphertext& encrypted_query, int cluster_id, int top_k) {
    return search(encrypted_query, top_k, {cluster_id});
}

std::vector<std::vector<std::string>> RetrievalEnginePRAG1::perturbedPaths(
    const std::vector<std::string>& real_ids,
    const std::vector<std::string>& candidate_ids) {
    std::vector<std::vector<std::string>> paths;
    if (candidate_ids.empty()) {
        return paths;
    }
    std::mt19937 rng(config_.system_params.random_seed + static_cast<std::uint32_t>(index_.nextQueryCounter()));
    std::uniform_int_distribution<std::size_t> pick(0, candidate_ids.size() - 1);
    for (const std::string& identifier : real_ids) {
        std::vector<std::string> path{identifier};
        while (static_cast<int>(path.size()) < config_.system_params.path_pad_length) {
            path.push_back(candidate_ids[pick(rng)]);
        }
        paths.push_back(std::move(path));
    }
    const int dummy_count = static_cast<int>(paths.size() * config_.system_params.dummy_rate + 0.5);
    for (int i = 0; i < dummy_count; ++i) {
        std::vector<std::string> path;
        for (int j = 0; j < config_.system_params.path_pad_length; ++j) {
            path.push_back(candidate_ids[pick(rng)]);
        }
        paths.push_back(std::move(path));
    }
    return paths;
}

double RetrievalEnginePRAG1::estimateOee(const std::vector<Ciphertext>& scores, const std::vector<std::vector<std::string>>& paths) const {
    double max_noise = 0.0;
    for (const Ciphertext& score : scores) {
        max_noise = std::max(max_noise, score.noise());
    }
    std::size_t max_path = 0;
    for (const auto& path : paths) {
        max_path = std::max(max_path, path.size());
    }
    return max_noise + 1e-4 * static_cast<double>(max_path) + 1e-5 * config_.chebyshev_degree;
}

}  // namespace prag
