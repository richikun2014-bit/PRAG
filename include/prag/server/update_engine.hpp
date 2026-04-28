#pragma once

#include "prag/common/types.hpp"

namespace prag {

/** Base interface for encrypted insertion and deletion. */
class UpdateEngine {
public:
    /** Destroy an update engine through the interface pointer. */
    virtual ~UpdateEngine() = default;

    /** Insert an encrypted vector into the encrypted index. */
    virtual UpdateResult insert(const EncryptedVector& encrypted_vector, int cluster_id = 0) = 0;

    /** Mark an encrypted node as deleted. */
    virtual UpdateResult remove(const std::string& identifier) = 0;

    /** Physically remove marked nodes during offline maintenance. */
    virtual UpdateResult sweep() = 0;
};

}  // namespace prag

