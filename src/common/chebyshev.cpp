#include "prag/common/chebyshev.hpp"

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <utility>

namespace prag {

ChebyshevApprox::ChebyshevApprox(
    int degree,
    double tau,
    std::shared_ptr<seal::SEALContext> context,
    EvaluationKey evaluation_key,
    double scale)
    : degree_(std::max(0, degree)),
      tau_(tau <= 0.0 ? 1.0 : tau),
      context_(std::move(context)),
      evaluation_key_(std::move(evaluation_key)),
      scale_(scale),
      evaluator_(*context_),
      encoder_(*context_) {
    const std::vector<double> exp_coefficients = {
        1.266065877, 1.130318208, 0.271495340, 0.044336850, 0.005474240, 0.000542930
    };
    coefficients_.assign(exp_coefficients.begin(), exp_coefficients.begin() + std::min<int>(degree_ + 1, exp_coefficients.size()));
    while (static_cast<int>(coefficients_.size()) < degree_ + 1) {
        coefficients_.push_back(0.0);
    }
}

seal::Plaintext ChebyshevApprox::encodePlain(double value, const seal::parms_id_type& parms_id, double scale) const {
    seal::Plaintext plain;
    encoder_.encode(value, parms_id, scale, plain);
    return plain;
}

void ChebyshevApprox::alignForAdd(seal::Ciphertext& left, seal::Ciphertext& right) const {
    auto left_data = context_->get_context_data(left.parms_id());
    auto right_data = context_->get_context_data(right.parms_id());
    if (!left_data || !right_data) {
        throw std::invalid_argument("Ciphertext is not valid for the SEAL context.");
    }
    if (left_data->chain_index() > right_data->chain_index()) {
        evaluator_.mod_switch_to_inplace(left, right.parms_id());
    } else if (right_data->chain_index() > left_data->chain_index()) {
        evaluator_.mod_switch_to_inplace(right, left.parms_id());
    }
    const double target_scale = std::min(left.scale(), right.scale());
    left.scale() = target_scale;
    right.scale() = target_scale;
}

Ciphertext ChebyshevApprox::evaluate(const Ciphertext& score) const {
    seal::Ciphertext x = score.sealValue();
    seal::Plaintext inv_tau = encodePlain(1.0 / tau_, x.parms_id(), x.scale());
    evaluator_.multiply_plain_inplace(x, inv_tau);
    evaluator_.rescale_to_next_inplace(x);
    x.scale() = scale_;

    seal::Ciphertext result;
    bool result_set = false;

    auto addTerm = [&](const seal::Ciphertext& term, double coefficient) {
        seal::Ciphertext scaled = term;
        seal::Plaintext plain_coeff = encodePlain(coefficient, scaled.parms_id(), scaled.scale());
        evaluator_.multiply_plain_inplace(scaled, plain_coeff);
        evaluator_.rescale_to_next_inplace(scaled);
        scaled.scale() = scale_;
        if (!result_set) {
            result = scaled;
            result_set = true;
        } else {
            seal::Ciphertext a = result;
            seal::Ciphertext b = scaled;
            alignForAdd(a, b);
            evaluator_.add(a, b, result);
        }
    };

    seal::Ciphertext t0;
    {
        t0 = x;
        seal::Plaintext zero = encodePlain(0.0, t0.parms_id(), t0.scale());
        evaluator_.multiply_plain_inplace(t0, zero);
        evaluator_.rescale_to_next_inplace(t0);
        t0.scale() = scale_;
        seal::Plaintext one = encodePlain(1.0, t0.parms_id(), t0.scale());
        evaluator_.add_plain_inplace(t0, one);
    }
    addTerm(t0, coefficients_[0]);

    if (degree_ >= 1) {
        seal::Ciphertext t1 = x;
        addTerm(t1, coefficients_[1]);
        for (int m = 2; m <= degree_; ++m) {
            seal::Ciphertext x_aligned = x;
            evaluator_.mod_switch_to_inplace(x_aligned, t1.parms_id());
            x_aligned.scale() = t1.scale();
            seal::Ciphertext x_times_t1;
            evaluator_.multiply(x_aligned, t1, x_times_t1);
            evaluator_.relinearize_inplace(x_times_t1, evaluation_key_.relin_keys);
            evaluator_.rescale_to_next_inplace(x_times_t1);
            x_times_t1.scale() = scale_;
            seal::Plaintext two = encodePlain(2.0, x_times_t1.parms_id(), x_times_t1.scale());
            evaluator_.multiply_plain_inplace(x_times_t1, two);
            evaluator_.rescale_to_next_inplace(x_times_t1);
            x_times_t1.scale() = scale_;

            seal::Ciphertext minus_t0 = t0;
            seal::Plaintext minus_one = encodePlain(-1.0, minus_t0.parms_id(), minus_t0.scale());
            evaluator_.multiply_plain_inplace(minus_t0, minus_one);
            evaluator_.rescale_to_next_inplace(minus_t0);
            minus_t0.scale() = scale_;

            seal::Ciphertext a = x_times_t1;
            seal::Ciphertext b = minus_t0;
            alignForAdd(a, b);
            seal::Ciphertext t_next;
            evaluator_.add(a, b, t_next);
            addTerm(t_next, coefficients_[m]);
            t0 = t1;
            t1 = t_next;
        }
    }
    return Ciphertext(std::move(result), 1, score.keyId(), score.noise() + 1e-5 * degree_, score.level() + degree_, "cheby_score");
}

std::vector<Ciphertext> ChebyshevApprox::evaluateAll(const std::vector<Ciphertext>& scores) const {
    std::vector<Ciphertext> out;
    out.reserve(scores.size());
    for (const Ciphertext& score : scores) {
        out.push_back(evaluate(score));
    }
    return out;
}

}  // namespace prag
