#include "prag/client/query_handler.hpp"

#include <algorithm>
#include <utility>

namespace prag {

QueryHandler::QueryHandler(const CryptoUtils& crypto, PublicKey public_key)
    : crypto_(crypto), public_key_(std::move(public_key)) {}

Ciphertext QueryHandler::encryptQueryVector(const std::vector<double>& vector) const {
    return crypto_.encryptQuery(public_key_, vector);
}

std::vector<int> QueryHandler::selectClusters(
    const std::vector<double>& query_vector,
    const std::unordered_map<int, std::vector<double>>& centroids,
    int cluster_probe) const {
    std::vector<std::pair<int, double>> scores;
    scores.reserve(centroids.size());
    for (const auto& item : centroids) {
        scores.emplace_back(item.first, dot(query_vector, item.second));
    }
    std::sort(scores.begin(), scores.end(), [](const auto& left, const auto& right) {
        return left.second > right.second;
    });
    const int count = std::min<int>(std::max(0, cluster_probe), scores.size());
    std::vector<int> result;
    result.reserve(count);
    for (int i = 0; i < count; ++i) {
        result.push_back(scores[i].first);
    }
    return result;
}

}  // namespace prag

