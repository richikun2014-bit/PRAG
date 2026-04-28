#include "prag/server/homomorphic_ops.hpp"

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <vector>

namespace prag {

HomomorphicOps::HomomorphicOps(std::shared_ptr<seal::SEALContext> context, EvaluationKey evaluation_key, double scale)
    : context_(std::move(context)),
      evaluation_key_(std::move(evaluation_key)),
      scale_(scale),
      evaluator_(*context_),
      encoder_(*context_) {}

std::shared_ptr<seal::SEALContext> HomomorphicOps::context() const {
    return context_;
}

const EvaluationKey& HomomorphicOps::evaluationKey() const {
    return evaluation_key_;
}

double HomomorphicOps::scale() const {
    return scale_;
}

void HomomorphicOps::checkKey(const Ciphertext& left, const Ciphertext& right) const {
    if (left.keyId() != right.keyId()) {
        throw std::invalid_argument("Ciphertexts belong to different key domains.");
    }
}

void HomomorphicOps::alignForAdd(seal::Ciphertext& left, seal::Ciphertext& right) const {
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

seal::Plaintext HomomorphicOps::encodePlain(double value, const seal::parms_id_type& parms_id, double scale) const {
    seal::Plaintext plain;
    encoder_.encode(value, parms_id, scale, plain);
    return plain;
}

Ciphertext HomomorphicOps::add(const Ciphertext& left, const Ciphertext& right) const {
    checkKey(left, right);
    seal::Ciphertext a = left.sealValue();
    seal::Ciphertext b = right.sealValue();
    alignForAdd(a, b);
    seal::Ciphertext out;
    evaluator_.add(a, b, out);
    return Ciphertext(std::move(out), std::max(left.slotCount(), right.slotCount()), left.keyId(), left.noise() + right.noise() + 1e-6, std::max(left.level(), right.level()), "add");
}

Ciphertext HomomorphicOps::multiply(const Ciphertext& left, const Ciphertext& right) const {
    checkKey(left, right);
    seal::Ciphertext out;
    evaluator_.multiply(left.sealValue(), right.sealValue(), out);
    evaluator_.relinearize_inplace(out, evaluation_key_.relin_keys);
    evaluator_.rescale_to_next_inplace(out);
    out.scale() = scale_;
    return Ciphertext(std::move(out), std::max(left.slotCount(), right.slotCount()), left.keyId(), left.noise() + right.noise() + 1e-5, std::max(left.level(), right.level()) + 1, "mul");
}

Ciphertext HomomorphicOps::innerProduct(const Ciphertext& left, const Ciphertext& right) const {
    checkKey(left, right);
    seal::Ciphertext product;
    evaluator_.multiply(left.sealValue(), right.sealValue(), product);
    evaluator_.relinearize_inplace(product, evaluation_key_.relin_keys);
    evaluator_.rescale_to_next_inplace(product);
    product.scale() = scale_;

    seal::Ciphertext sum = product;
    for (std::size_t step = 1; step < std::max<std::size_t>(1, left.slotCount()); step <<= 1) {
        seal::Ciphertext rotated;
        evaluator_.rotate_vector(sum, static_cast<int>(step), evaluation_key_.galois_keys, rotated);
        seal::Ciphertext a = sum;
        seal::Ciphertext b = rotated;
        alignForAdd(a, b);
        evaluator_.add(a, b, sum);
    }
    const double depth = std::ceil(std::log2(static_cast<double>(std::max<std::size_t>(1, left.slotCount()))));
    return Ciphertext(std::move(sum), 1, left.keyId(), left.noise() + right.noise() + 1e-4 * (1.0 + depth), std::max(left.level(), right.level()) + 1, "homo_ip");
}

Ciphertext HomomorphicOps::l2Score(const Ciphertext& query, const Ciphertext& vector) const {
    checkKey(query, vector);
    seal::Ciphertext diff_a = query.sealValue();
    seal::Ciphertext diff_b = vector.sealValue();
    alignForAdd(diff_a, diff_b);
    evaluator_.sub(diff_a, diff_b, diff_a);
    seal::Ciphertext squared;
    evaluator_.square(diff_a, squared);
    evaluator_.relinearize_inplace(squared, evaluation_key_.relin_keys);
    evaluator_.rescale_to_next_inplace(squared);
    squared.scale() = scale_;

    seal::Ciphertext sum = squared;
    for (std::size_t step = 1; step < std::max<std::size_t>(1, query.slotCount()); step <<= 1) {
        seal::Ciphertext rotated;
        evaluator_.rotate_vector(sum, static_cast<int>(step), evaluation_key_.galois_keys, rotated);
        seal::Ciphertext a = sum;
        seal::Ciphertext b = rotated;
        alignForAdd(a, b);
        evaluator_.add(a, b, sum);
    }
    evaluator_.negate_inplace(sum);
    return Ciphertext(std::move(sum), 1, query.keyId(), query.noise() + vector.noise() + 2e-4, std::max(query.level(), vector.level()) + 1, "negative_l2");
}

Ciphertext HomomorphicOps::scalarMultiply(const Ciphertext& ciphertext, double scalar) const {
    seal::Ciphertext out = ciphertext.sealValue();
    seal::Plaintext plain = encodePlain(scalar, out.parms_id(), out.scale());
    evaluator_.multiply_plain_inplace(out, plain);
    evaluator_.rescale_to_next_inplace(out);
    out.scale() = scale_;
    return Ciphertext(std::move(out), ciphertext.slotCount(), ciphertext.keyId(), ciphertext.noise() + std::abs(scalar) * 1e-6, ciphertext.level() + 1, "scalar_mul");
}

Ciphertext HomomorphicOps::normalizeCiphertext(const Ciphertext& ciphertext) const {
    return ciphertext;
}

}  // namespace prag
