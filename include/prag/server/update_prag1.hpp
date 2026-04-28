#pragma once

#include "prag/common/chebyshev.hpp"
#include "prag/common/config.hpp"
#include "prag/server/encrypted_index.hpp"
#include "prag/server/homomorphic_ops.hpp"
#include "prag/server/update_engine.hpp"

namespace prag {

/** PRAG-I secure update engine using Chebyshev-weighted neighbor selection. */
class UpdateEnginePRAG1 final : public UpdateEngine {
public:
    /** Create a PRAG-I update engine over shared encrypted state. */
    UpdateEnginePRAG1(const Config& config, EncryptedIndex& index, const HomomorphicOps& ops);

    /** Insert a node and link it through encrypted score surrogates. */
    UpdateResult insert(const EncryptedVector& encrypted_vector, int cluster_id = 0) override;

    /** Mark a node as deleted without changing live routing topology. */
    UpdateResult remove(const std::string& identifier) override;

    /** Purge marked nodes during offline reconstruction. */
    UpdateResult sweep() override;

private:
    const Config& config_;
    EncryptedIndex& index_;
    const HomomorphicOps& ops_;
    ChebyshevApprox cheby_;
};

}  // namespace prag

