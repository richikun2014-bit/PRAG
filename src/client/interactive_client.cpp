#include "prag/client/interactive_client.hpp"

#include <algorithm>
#include <numeric>
#include <utility>

namespace prag {

InteractiveClient::InteractiveClient(const CryptoUtils& crypto, SecretKey secret_key)
    : crypto_(crypto), secret_key_(std::move(secret_key)) {}

int InteractiveClient::decryptAndCompare(const std::vector<Ciphertext>& encrypted_scores) {
    const std::vector<int> top = decryptAndTopK(encrypted_scores, 1);
    return top.empty() ? -1 : top.front();
}

std::vector<int> InteractiveClient::decryptAndTopK(const std::vector<Ciphertext>& encrypted_scores, int k) {
    ++rounds_;
    for (const Ciphertext& score : encrypted_scores) {
        bytes_received_ += score.byteSize();
    }
    std::vector<std::pair<int, double>> indexed;
    indexed.reserve(encrypted_scores.size());
    for (int i = 0; i < static_cast<int>(encrypted_scores.size()); ++i) {
        const std::vector<double> plain = crypto_.decrypt(secret_key_, encrypted_scores[i]);
        indexed.emplace_back(i, plain.empty() ? 0.0 : plain.front());
    }
    std::sort(indexed.begin(), indexed.end(), [](const auto& left, const auto& right) {
        return left.second > right.second;
    });
    const int count = std::min<int>(std::max(0, k), indexed.size());
    std::vector<int> result;
    result.reserve(count);
    for (int i = 0; i < count; ++i) {
        result.push_back(indexed[i].first);
    }
    return result;
}

std::vector<int> InteractiveClient::selectCluster(const std::vector<Ciphertext>& encrypted_scores, int cluster_probe) {
    return decryptAndTopK(encrypted_scores, cluster_probe);
}

int InteractiveClient::rounds() const {
    return rounds_;
}

std::size_t InteractiveClient::bytesReceived() const {
    return bytes_received_;
}

}  // namespace prag
