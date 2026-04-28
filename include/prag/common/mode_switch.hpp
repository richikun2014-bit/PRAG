#pragma once

#include <memory>

#include "prag/common/config.hpp"

namespace prag {

class EncryptedIndex;
class HomomorphicOps;
class InteractiveClient;
class RetrievalEngine;
class UpdateEngine;

/** Runtime mode switch that reuses one encrypted index across PRAG-I and PRAG-II. */
class ModeSwitch {
public:
    /** Bind mode switching to shared server state and an optional client callback. */
    ModeSwitch(Config& config, EncryptedIndex& index, HomomorphicOps& ops, InteractiveClient* client);

    /** Switch PRAG mode without rebuilding the encrypted index. */
    void setMode(PRAGMode mode);

    /** Return a retrieval engine for the active mode. */
    std::unique_ptr<RetrievalEngine> retrievalEngine() const;

    /** Return an update engine for the active mode. */
    std::unique_ptr<UpdateEngine> updateEngine() const;

private:
    Config& config_;
    EncryptedIndex& index_;
    HomomorphicOps& ops_;
    InteractiveClient* client_;
};

}  // namespace prag

