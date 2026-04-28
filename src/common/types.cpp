#include "prag/common/types.hpp"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>

#include "prag/common/config.hpp"

namespace prag {
namespace {

std::string makeToken() {
    static std::mt19937_64 rng{0x50524147ULL};
    std::uniform_int_distribution<unsigned long long> dist;
    std::ostringstream out;
    out << std::hex << dist(rng);
    return out.str();
}

}  // namespace

Ciphertext::Ciphertext() : token_(makeToken()) {}

Ciphertext::Ciphertext(seal::Ciphertext value, std::size_t slot_count, std::string key_id, double noise, int level, std::string label)
    : value_(std::move(value)),
      slot_count_(slot_count),
      key_id_(std::move(key_id)),
      noise_(noise),
      level_(level),
      label_(std::move(label)),
      token_(makeToken()) {}

std::size_t Ciphertext::slotCount() const {
    return slot_count_;
}

const std::string& Ciphertext::keyId() const {
    return key_id_;
}

double Ciphertext::noise() const {
    return noise_;
}

int Ciphertext::level() const {
    return level_;
}

const std::string& Ciphertext::token() const {
    return token_;
}

std::size_t Ciphertext::byteSize() const {
    return value_.save_size(seal::compr_mode_type::none);
}

const seal::Ciphertext& Ciphertext::sealValue() const {
    return value_;
}

seal::Ciphertext& Ciphertext::sealValue() {
    return value_;
}

double dot(const std::vector<double>& left, const std::vector<double>& right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument("Vector dimensions do not match.");
    }
    return std::inner_product(left.begin(), left.end(), right.begin(), 0.0);
}

std::vector<double> normalize(std::vector<double> values) {
    const double norm = std::sqrt(std::inner_product(values.begin(), values.end(), values.begin(), 0.0));
    if (norm <= 1e-12) {
        return values;
    }
    for (double& value : values) {
        value /= norm;
    }
    return values;
}

std::string modeName(PRAGMode mode) {
    return mode == PRAGMode::PRAG_I ? "PRAG-I" : "PRAG-II";
}

}  // namespace prag
