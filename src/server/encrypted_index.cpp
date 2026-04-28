#include "prag/server/encrypted_index.hpp"

#include <algorithm>
#include <cstdint>
#include <stdexcept>

namespace prag {

EncryptedIndex::EncryptedIndex(const Config& config) : config_(config) {}

int EncryptedIndex::randomLayer() const {
    std::mt19937 rng(config_.system_params.random_seed + static_cast<std::uint32_t>(nodes_.size() * 7919));
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    int layer = 0;
    while (layer + 1 < config_.hnsw_params.max_layers && dist(rng) < config_.hnsw_params.level_multiplier) {
        ++layer;
    }
    return layer;
}

void EncryptedIndex::insertNode(const EncryptedNode& node) {
    nodes_[node.identifier] = node;
    cluster_members_[node.cluster_id].insert(node.identifier);
    max_layer_ = std::max(max_layer_, node.max_layer);
    if (entry_point_.empty() || node.max_layer > nodes_.at(entry_point_).max_layer) {
        entry_point_ = node.identifier;
    }
}

void EncryptedIndex::link(const std::string& source_id, const std::string& target_id, int layer) {
    if (source_id == target_id) {
        return;
    }
    adjacency_[layer][source_id].insert(target_id);
    adjacency_[layer][target_id].insert(source_id);
}

std::vector<std::string> EncryptedIndex::activeIds(const std::vector<int>& cluster_ids) const {
    std::vector<std::string> ids;
    if (cluster_ids.empty()) {
        ids.reserve(nodes_.size());
        for (const auto& item : nodes_) {
            if (!item.second.deleted) {
                ids.push_back(item.first);
            }
        }
        return ids;
    }
    for (int cluster_id : cluster_ids) {
        const auto found = cluster_members_.find(cluster_id);
        if (found == cluster_members_.end()) {
            continue;
        }
        for (const std::string& identifier : found->second) {
            const auto node_iter = nodes_.find(identifier);
            if (node_iter != nodes_.end() && !node_iter->second.deleted) {
                ids.push_back(identifier);
            }
        }
    }
    return ids;
}

std::vector<std::string> EncryptedIndex::neighbors(const std::string& identifier, int layer) const {
    const auto layer_iter = adjacency_.find(layer);
    if (layer_iter == adjacency_.end()) {
        return {};
    }
    const auto node_iter = layer_iter->second.find(identifier);
    if (node_iter == layer_iter->second.end()) {
        return {};
    }
    std::vector<std::string> out;
    out.reserve(node_iter->second.size());
    for (const std::string& candidate : node_iter->second) {
        const auto found = nodes_.find(candidate);
        if (found != nodes_.end() && !found->second.deleted) {
            out.push_back(candidate);
        }
    }
    return out;
}

const std::string& EncryptedIndex::entryPoint() const {
    return entry_point_;
}

int EncryptedIndex::maxLayer() const {
    return max_layer_;
}

bool EncryptedIndex::markDeleted(const std::string& identifier) {
    const auto found = nodes_.find(identifier);
    if (found == nodes_.end()) {
        return false;
    }
    found->second.deleted = true;
    return true;
}

int EncryptedIndex::sweepDeleted() {
    std::vector<std::string> deleted;
    for (const auto& item : nodes_) {
        if (item.second.deleted) {
            deleted.push_back(item.first);
        }
    }
    for (const std::string& identifier : deleted) {
        const int cluster_id = nodes_.at(identifier).cluster_id;
        nodes_.erase(identifier);
        cluster_members_[cluster_id].erase(identifier);
    }
    for (auto& layer_item : adjacency_) {
        for (auto it = layer_item.second.begin(); it != layer_item.second.end();) {
            if (std::find(deleted.begin(), deleted.end(), it->first) != deleted.end()) {
                it = layer_item.second.erase(it);
            } else {
                for (const std::string& identifier : deleted) {
                    it->second.erase(identifier);
                }
                ++it;
            }
        }
    }
    if (std::find(deleted.begin(), deleted.end(), entry_point_) != deleted.end()) {
        entry_point_ = nodes_.empty() ? std::string{} : nodes_.begin()->first;
    }
    return static_cast<int>(deleted.size());
}

EncryptedNode& EncryptedIndex::node(const std::string& identifier) {
    return nodes_.at(identifier);
}

const EncryptedNode& EncryptedIndex::node(const std::string& identifier) const {
    return nodes_.at(identifier);
}

std::size_t EncryptedIndex::size() const {
    return nodes_.size();
}

bool EncryptedIndex::contains(const std::string& identifier) const {
    return nodes_.find(identifier) != nodes_.end();
}

int EncryptedIndex::nextQueryCounter() {
    ++query_count_;
    return query_count_;
}

}  // namespace prag
