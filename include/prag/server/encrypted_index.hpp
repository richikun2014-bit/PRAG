#pragma once

#include <map>
#include <random>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "prag/common/config.hpp"
#include "prag/common/types.hpp"

namespace prag {

/** Server-resident encrypted index shared by both PRAG modes. */
class EncryptedIndex {
public:
    /** Create an empty encrypted index. */
    explicit EncryptedIndex(const Config& config);

    /** Sample an HNSW layer for a newly inserted node. */
    int randomLayer() const;

    /** Insert a node into encrypted storage without linking it. */
    void insertNode(const EncryptedNode& node);

    /** Create a bidirectional graph link. */
    void link(const std::string& source_id, const std::string& target_id, int layer);

    /** Return active node identifiers, optionally restricted by cluster. */
    std::vector<std::string> activeIds(const std::vector<int>& cluster_ids = {}) const;

    /** Return graph neighbors for an identifier at one HNSW layer. */
    std::vector<std::string> neighbors(const std::string& identifier, int layer) const;

    /** Return the current HNSW entry point identifier. */
    const std::string& entryPoint() const;

    /** Return the maximum HNSW layer currently present. */
    int maxLayer() const;

    /** Mark a node as deleted while keeping it available for routing. */
    bool markDeleted(const std::string& identifier);

    /** Physically purge deleted nodes during offline maintenance. */
    int sweepDeleted();

    /** Return a mutable node by identifier. */
    EncryptedNode& node(const std::string& identifier);

    /** Return an immutable node by identifier. */
    const EncryptedNode& node(const std::string& identifier) const;

    /** Return the number of encrypted nodes. */
    std::size_t size() const;

    /** Return whether an identifier is present. */
    bool contains(const std::string& identifier) const;

    /** Increment and return the query counter. */
    int nextQueryCounter();

private:
    const Config& config_;
    std::unordered_map<std::string, EncryptedNode> nodes_;
    std::map<int, std::unordered_map<std::string, std::set<std::string>>> adjacency_;
    std::unordered_map<int, std::set<std::string>> cluster_members_;
    std::string entry_point_;
    int max_layer_ = 0;
    int query_count_ = 0;
};

}  // namespace prag
