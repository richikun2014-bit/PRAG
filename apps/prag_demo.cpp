#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "prag/client/crypto_utils.hpp"
#include "prag/client/interactive_client.hpp"
#include "prag/common/mode_switch.hpp"
#include "prag/server/encrypted_index.hpp"
#include "prag/server/homomorphic_ops.hpp"
#include "prag/server/retrieval_engine.hpp"
#include "prag/server/update_engine.hpp"

using namespace prag;

namespace {

std::vector<double> basis(std::size_t dim, std::size_t index) {
    std::vector<double> values(dim, 0.0);
    values[index] = 1.0;
    return values;
}

std::vector<std::pair<std::string, std::vector<double>>> sampleVectors(std::size_t dim) {
    std::vector<std::pair<std::string, std::vector<double>>> vectors;
    vectors.push_back({"doc-alpha", basis(dim, 0)});
    vectors.push_back({"doc-beta", basis(dim, 1)});
    vectors.push_back({"doc-gamma", basis(dim, 2)});
    vectors.push_back({"doc-delta", basis(dim, 3)});
    std::mt19937 rng(13);
    std::normal_distribution<double> normal(0.0, 1.0);
    for (int i = 0; i < 8; ++i) {
        std::vector<double> values(dim, 0.0);
        for (double& value : values) {
            value = normal(rng);
        }
        vectors.push_back({"doc-" + std::to_string(i), normalize(values)});
    }
    return vectors;
}

struct DemoState {
    Config config;
    CryptoUtils crypto;
    KeyBundle keys;
    HomomorphicOps ops;
    EncryptedIndex index;
    InteractiveClient client;
    ModeSwitch mode_switch;

    explicit DemoState(PRAGMode mode)
        : config(),
          crypto(config),
          keys(crypto.generateKeys()),
          ops(crypto.context(), keys.evaluation_key, crypto.scale()),
          index(config),
          client(crypto, keys.secret_key),
          mode_switch(config, index, ops, &client) {
        config.mode = mode;
        config.system_params.top_k = 4;
    }
};

void buildIndex(DemoState& state) {
    std::unique_ptr<UpdateEngine> updater = state.mode_switch.updateEngine();
    for (const auto& item : sampleVectors(state.config.system_params.vector_dim)) {
        EncryptedVector encrypted = state.crypto.encryptVector(state.keys.public_key, item.first, item.second);
        updater->insert(encrypted, 0);
    }
}

void runRetrieval(PRAGMode mode) {
    DemoState state(mode);
    buildIndex(state);
    const std::vector<double> query = basis(state.config.system_params.vector_dim, mode == PRAGMode::PRAG_I ? 0 : 1);
    const Ciphertext encrypted_query = state.crypto.encryptQuery(state.keys.public_key, query);
    SearchResult result = state.mode_switch.retrievalEngine()->search(encrypted_query, state.config.system_params.top_k);
    std::cout << result.mode << " identifiers:";
    for (const std::string& identifier : result.identifiers) {
        std::cout << ' ' << identifier;
    }
    std::cout << "\ncommunication_bytes=" << result.communication_bytes;
    std::cout << "\noee_bound=" << result.oee_bound << '\n';
}

void runUpdate() {
    DemoState state(PRAGMode::PRAG_I);
    buildIndex(state);
    std::unique_ptr<UpdateEngine> updater = state.mode_switch.updateEngine();
    std::vector<double> value(state.config.system_params.vector_dim, 1.0);
    EncryptedVector encrypted = state.crypto.encryptVector(state.keys.public_key, "doc-new", normalize(value));
    UpdateResult inserted = updater->insert(encrypted, 0);
    UpdateResult removed = updater->remove("doc-beta");
    UpdateResult swept = updater->sweep();
    std::cout << "insert_success=" << inserted.success << " touched=" << inserted.touched_nodes << '\n';
    std::cout << "remove_success=" << removed.success << '\n';
    std::cout << "sweep_touched=" << swept.touched_nodes << " remaining=" << state.index.size() << '\n';
}

}  // namespace

int main(int argc, char** argv) {
    std::string mode = "prag-i";
    bool update = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--mode" && i + 1 < argc) {
            mode = argv[++i];
        } else if (arg == "--update") {
            update = true;
        }
    }
    if (update) {
        runUpdate();
        return 0;
    }
    runRetrieval(mode == "prag-ii" ? PRAGMode::PRAG_II : PRAGMode::PRAG_I);
    return 0;
}
