#include "prag/common/mode_switch.hpp"

#include <stdexcept>

#include "prag/client/interactive_client.hpp"
#include "prag/server/retrieval_prag1.hpp"
#include "prag/server/retrieval_prag2.hpp"
#include "prag/server/update_prag1.hpp"
#include "prag/server/update_prag2.hpp"

namespace prag {

ModeSwitch::ModeSwitch(Config& config, EncryptedIndex& index, HomomorphicOps& ops, InteractiveClient* client)
    : config_(config), index_(index), ops_(ops), client_(client) {}

void ModeSwitch::setMode(PRAGMode mode) {
    config_.mode = mode;
}

std::unique_ptr<RetrievalEngine> ModeSwitch::retrievalEngine() const {
    if (config_.mode == PRAGMode::PRAG_I) {
        return std::make_unique<RetrievalEnginePRAG1>(config_, index_, ops_);
    }
    if (client_ == nullptr) {
        throw std::invalid_argument("PRAG-II requires an interactive client.");
    }
    return std::make_unique<RetrievalEnginePRAG2>(config_, index_, ops_, *client_);
}

std::unique_ptr<UpdateEngine> ModeSwitch::updateEngine() const {
    if (config_.mode == PRAGMode::PRAG_I) {
        return std::make_unique<UpdateEnginePRAG1>(config_, index_, ops_);
    }
    if (client_ == nullptr) {
        throw std::invalid_argument("PRAG-II requires an interactive client.");
    }
    return std::make_unique<UpdateEnginePRAG2>(config_, index_, ops_, *client_);
}

}  // namespace prag

