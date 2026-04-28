#pragma once

#include "prag/client/interactive_client.hpp"
#include "prag/common/config.hpp"
#include "prag/server/encrypted_index.hpp"
#include "prag/server/homomorphic_ops.hpp"
#include "prag/server/update_engine.hpp"

namespace prag {

/** PRAG-II secure update engine using client-assisted exact choices. */
class UpdateEnginePRAG2 final : public UpdateEngine {
public:
    /** Create a PRAG-II update engine over shared encrypted state. */
    UpdateEnginePRAG2(const Config& config, EncryptedIndex& index, const HomomorphicOps& ops, InteractiveClient& client);

    /** Insert a node using client-assisted encrypted score ordering. */
    UpdateResult insert(const EncryptedVector& encrypted_vector, int cluster_id = 0) override;

    /** Mark a node as deleted while keeping graph routing stable. */
    UpdateResult remove(const std::string& identifier) override;

    /** Purge marked nodes during offline reconstruction. */
    UpdateResult sweep() override;

private:
    const Config& config_;
    EncryptedIndex& index_;
    const HomomorphicOps& ops_;
    InteractiveClient& client_;
};

}  // namespace prag

