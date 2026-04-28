#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <vector>

#include "prag/common/config.hpp"
#include "prag/common/types.hpp"

namespace prag {

/** Public encryption key descriptor. */
struct PublicKey {
    std::string key_id;
    seal::PublicKey value;
};

/** Client-held secret key descriptor. */
struct SecretKey {
    std::string key_id;
    seal::SecretKey value;
};

/** Evaluation key descriptor uploaded to the server. */
struct EvaluationKey {
    std::string key_id;
    seal::RelinKeys relin_keys;
    seal::GaloisKeys galois_keys;
};

/** Generated keys for a single-client PRAG deployment. */
struct KeyBundle {
    PublicKey public_key;
    SecretKey secret_key;
    EvaluationKey evaluation_key;
};

/** Client-side key management, vector encryption, and decryption utility. */
class CryptoUtils {
public:
    /** Create crypto utilities bound to a PRAG configuration. */
    explicit CryptoUtils(const Config& config);

    /** Generate a single-client key bundle. */
    KeyBundle generateKeys() const;

    /** Return the shared SEAL context. */
    std::shared_ptr<seal::SEALContext> context() const;

    /** Return the CKKS scale used for encoding. */
    double scale() const;

    /** Encrypt a document vector and bind it to an identifier. */
    EncryptedVector encryptVector(
        const PublicKey& public_key,
        const std::string& identifier,
        const std::vector<double>& vector,
        const std::unordered_map<std::string, std::string>& metadata = {}) const;

    /** Encrypt a query vector for server-side retrieval. */
    Ciphertext encryptQuery(const PublicKey& public_key, const std::vector<double>& vector) const;

    /** Decrypt a ciphertext for trusted client-side use. */
    std::vector<double> decrypt(const SecretKey& secret_key, const Ciphertext& ciphertext) const;

private:
    const Config& config_;
    std::shared_ptr<seal::SEALContext> context_;
    std::shared_ptr<seal::CKKSEncoder> encoder_;
};

}  // namespace prag
