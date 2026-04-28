#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "seal/seal.h"

namespace prag {

class CryptoUtils;
class HomomorphicOps;
class ChebyshevApprox;
class InteractiveClient;

/** Opaque encrypted payload with CKKS-like metadata. */
class Ciphertext {
public:
    /** Construct an empty ciphertext. */
    Ciphertext();

    /** Return the encrypted slot count without revealing values. */
    std::size_t slotCount() const;

    /** Return the key domain identifier. */
    const std::string& keyId() const;

    /** Return the estimated arithmetic noise. */
    double noise() const;

    /** Return the multiplicative level used by the backend. */
    int level() const;

    /** Return a non-semantic token for tracing and tests. */
    const std::string& token() const;

    /** Estimate serialized ciphertext size in bytes. */
    std::size_t byteSize() const;

private:
    friend class CryptoUtils;
    friend class HomomorphicOps;
    friend class ChebyshevApprox;
    friend class InteractiveClient;

    Ciphertext(seal::Ciphertext value, std::size_t slot_count, std::string key_id, double noise, int level, std::string label);

    const seal::Ciphertext& sealValue() const;
    seal::Ciphertext& sealValue();

    seal::Ciphertext value_;
    std::size_t slot_count_ = 0;
    std::string key_id_;
    double noise_ = 0.0;
    int level_ = 0;
    std::string label_;
    std::string token_;
};

/** Encrypted vector with an external document identifier. */
struct EncryptedVector {
    std::string identifier;
    Ciphertext ciphertext;
    std::size_t dimension = 0;
    std::unordered_map<std::string, std::string> metadata;
};

/** Encrypted graph node stored by the server. */
struct EncryptedNode {
    std::string identifier;
    EncryptedVector vector;
    int cluster_id = 0;
    int max_layer = 0;
    bool deleted = false;
};

/** Encrypted retrieval response returned by a server retrieval engine. */
struct SearchResult {
    std::vector<std::string> identifiers;
    std::vector<Ciphertext> encrypted_scores;
    std::vector<std::vector<std::string>> access_paths;
    std::string mode;
    std::size_t communication_bytes = 0;
    double oee_bound = 0.0;
};

/** Status returned by encrypted update engines. */
struct UpdateResult {
    bool success = false;
    std::string identifier;
    std::string operation;
    int touched_nodes = 0;
    std::string message;
};

/** Compute a dot product for trusted local test and demo data. */
double dot(const std::vector<double>& left, const std::vector<double>& right);

/** Normalize a local vector for deterministic demo data. */
std::vector<double> normalize(std::vector<double> values);

}  // namespace prag
