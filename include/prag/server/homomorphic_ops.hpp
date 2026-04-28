#pragma once

#include <memory>

#include "prag/client/crypto_utils.hpp"
#include "prag/common/types.hpp"

namespace prag {

/** CKKS-style homomorphic operations used by server engines. */
class HomomorphicOps {
public:
    /** Create homomorphic operators from a SEAL context and evaluation keys. */
    HomomorphicOps(std::shared_ptr<seal::SEALContext> context, EvaluationKey evaluation_key, double scale);

    /** Return the shared SEAL context. */
    std::shared_ptr<seal::SEALContext> context() const;

    /** Return evaluation keys used by server-side operations. */
    const EvaluationKey& evaluationKey() const;

    /** Return the CKKS encoding scale. */
    double scale() const;

    /** Homomorphically add two ciphertexts. */
    Ciphertext add(const Ciphertext& left, const Ciphertext& right) const;

    /** Homomorphically multiply two ciphertexts slot-wise. */
    Ciphertext multiply(const Ciphertext& left, const Ciphertext& right) const;

    /** Compute an encrypted inner product. */
    Ciphertext innerProduct(const Ciphertext& left, const Ciphertext& right) const;

    /** Return a similarity score equal to negative squared distance. */
    Ciphertext l2Score(const Ciphertext& query, const Ciphertext& vector) const;

    /** Multiply encrypted slots by a plaintext scalar. */
    Ciphertext scalarMultiply(const Ciphertext& ciphertext, double scalar) const;

    /** Normalize an encrypted vector through a reciprocal-style operation. */
    Ciphertext normalizeCiphertext(const Ciphertext& ciphertext) const;

private:
    void checkKey(const Ciphertext& left, const Ciphertext& right) const;
    void alignForAdd(seal::Ciphertext& left, seal::Ciphertext& right) const;
    seal::Plaintext encodePlain(double value, const seal::parms_id_type& parms_id, double scale) const;
    seal::Ciphertext multiplyPlainScalar(const seal::Ciphertext& ciphertext, double scalar, std::size_t slot_count, const std::string& key_id, double noise, int level) const;

    std::shared_ptr<seal::SEALContext> context_;
    EvaluationKey evaluation_key_;
    double scale_;
    seal::Evaluator evaluator_;
    seal::CKKSEncoder encoder_;
};

}  // namespace prag
