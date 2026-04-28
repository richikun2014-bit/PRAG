#include "prag/client/crypto_utils.hpp"

#include <cmath>
#include <random>
#include <sstream>
#include <stdexcept>

namespace prag {
namespace {

std::string makeKeyId() {
    std::random_device device;
    std::mt19937_64 rng(device());
    std::uniform_int_distribution<unsigned long long> dist;
    std::ostringstream out;
    out << std::hex << dist(rng);
    return out.str();
}

}  // namespace

CryptoUtils::CryptoUtils(const Config& config) : config_(config) {
    seal::EncryptionParameters parms(seal::scheme_type::ckks);
    parms.set_poly_modulus_degree(config_.ckks_params.polynomial_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(
        config_.ckks_params.polynomial_modulus_degree,
        config_.ckks_params.coefficient_modulus_bits));
    context_ = std::make_shared<seal::SEALContext>(parms);
    encoder_ = std::make_shared<seal::CKKSEncoder>(*context_);
    if (encoder_->slot_count() < config_.system_params.vector_dim) {
        throw std::invalid_argument("CKKS slot count is smaller than the configured vector dimension.");
    }
}

KeyBundle CryptoUtils::generateKeys() const {
    const std::string key_id = makeKeyId();
    seal::KeyGenerator keygen(*context_);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    seal::GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    return KeyBundle{PublicKey{key_id, public_key}, SecretKey{key_id, secret_key}, EvaluationKey{key_id, relin_keys, galois_keys}};
}

std::shared_ptr<seal::SEALContext> CryptoUtils::context() const {
    return context_;
}

double CryptoUtils::scale() const {
    return config_.ckks_params.scale;
}

EncryptedVector CryptoUtils::encryptVector(
    const PublicKey& public_key,
    const std::string& identifier,
    const std::vector<double>& vector,
    const std::unordered_map<std::string, std::string>& metadata) const {
    if (vector.empty()) {
        throw std::invalid_argument("Cannot encrypt an empty vector.");
    }
    seal::Plaintext plain;
    encoder_->encode(vector, config_.ckks_params.scale, plain);
    seal::Encryptor encryptor(*context_, public_key.value);
    seal::Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    Ciphertext ciphertext(std::move(encrypted), vector.size(), public_key.key_id, 1e-6, 0, "enc_vector");
    return EncryptedVector{identifier, ciphertext, vector.size(), metadata};
}

Ciphertext CryptoUtils::encryptQuery(const PublicKey& public_key, const std::vector<double>& vector) const {
    if (vector.empty()) {
        throw std::invalid_argument("Cannot encrypt an empty query.");
    }
    seal::Plaintext plain;
    encoder_->encode(vector, config_.ckks_params.scale, plain);
    seal::Encryptor encryptor(*context_, public_key.value);
    seal::Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    return Ciphertext(std::move(encrypted), vector.size(), public_key.key_id, 1e-6, 0, "enc_query");
}

std::vector<double> CryptoUtils::decrypt(const SecretKey& secret_key, const Ciphertext& ciphertext) const {
    if (secret_key.key_id != ciphertext.keyId()) {
        throw std::invalid_argument("Secret key does not match ciphertext key domain.");
    }
    seal::Decryptor decryptor(*context_, secret_key.value);
    seal::Plaintext plain;
    decryptor.decrypt(ciphertext.sealValue(), plain);
    std::vector<double> decoded;
    encoder_->decode(plain, decoded);
    if (decoded.size() > ciphertext.slotCount()) {
        decoded.resize(ciphertext.slotCount());
    }
    return decoded;
}

}  // namespace prag
