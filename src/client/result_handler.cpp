#include "prag/client/result_handler.hpp"

#include <algorithm>
#include <utility>

namespace prag {

ResultHandler::ResultHandler(const CryptoUtils& crypto, SecretKey secret_key)
    : crypto_(crypto), secret_key_(std::move(secret_key)) {}

std::vector<double> ResultHandler::decryptScores(const SearchResult& result) const {
    std::vector<double> scores;
    scores.reserve(result.encrypted_scores.size());
    for (const Ciphertext& score : result.encrypted_scores) {
        const std::vector<double> plain = crypto_.decrypt(secret_key_, score);
        scores.push_back(plain.empty() ? 0.0 : plain.front());
    }
    return scores;
}

std::vector<std::string> ResultHandler::rerank(const SearchResult& result) const {
    const std::vector<double> scores = decryptScores(result);
    std::vector<std::pair<std::string, double>> indexed;
    indexed.reserve(result.identifiers.size());
    for (std::size_t i = 0; i < result.identifiers.size(); ++i) {
        indexed.emplace_back(result.identifiers[i], scores[i]);
    }
    std::sort(indexed.begin(), indexed.end(), [](const auto& left, const auto& right) {
        return left.second > right.second;
    });
    std::vector<std::string> result_ids;
    result_ids.reserve(indexed.size());
    for (const auto& item : indexed) {
        result_ids.push_back(item.first);
    }
    return result_ids;
}

}  // namespace prag
