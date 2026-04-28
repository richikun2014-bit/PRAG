#pragma once

#include <vector>

#include "prag/client/crypto_utils.hpp"
#include "prag/common/types.hpp"

namespace prag {

/** Chebyshev polynomial ranking surrogate used by PRAG-I. */
class ChebyshevApprox {
public:
    /** Create a Chebyshev approximation with a bounded degree and scale. */
    ChebyshevApprox(int degree, double tau, std::shared_ptr<seal::SEALContext> context, EvaluationKey evaluation_key, double scale);

    /** Approximate a positive encrypted weight from an encrypted score. */
    Ciphertext evaluate(const Ciphertext& score) const;

    /** Evaluate polynomial scores for a candidate set without decrypting them. */
    std::vector<Ciphertext> evaluateAll(const std::vector<Ciphertext>& scores) const;

private:
    seal::Plaintext encodePlain(double value, const seal::parms_id_type& parms_id, double scale) const;
    void alignForAdd(seal::Ciphertext& left, seal::Ciphertext& right) const;

    int degree_;
    double tau_;
    std::vector<double> coefficients_;
    std::shared_ptr<seal::SEALContext> context_;
    EvaluationKey evaluation_key_;
    double scale_;
    seal::Evaluator evaluator_;
    seal::CKKSEncoder encoder_;
};

}  // namespace prag
