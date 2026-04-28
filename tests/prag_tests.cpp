#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
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

#define CHECK(condition) do { if (!(condition)) { throw std::runtime_error("check failed: " #condition); } } while (false)

std::vector<double> basis(std::size_t dim, std::size_t index) {
    std::vector<double> values(dim, 0.0);
    values[index] = 1.0;
    return values;
}

struct Fixture {
    Config config;
    CryptoUtils crypto;
    KeyBundle keys;
    HomomorphicOps ops;
    EncryptedIndex index;
    InteractiveClient client;
    ModeSwitch mode_switch;

    explicit Fixture(PRAGMode mode)
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

void insertBaseDocs(Fixture& fixture) {
    std::unique_ptr<UpdateEngine> updater = fixture.mode_switch.updateEngine();
    const std::vector<std::pair<std::string, std::vector<double>>> docs = {
        {"doc-alpha", basis(fixture.config.system_params.vector_dim, 0)},
        {"doc-beta", basis(fixture.config.system_params.vector_dim, 1)},
        {"doc-gamma", basis(fixture.config.system_params.vector_dim, 2)},
        {"doc-delta", basis(fixture.config.system_params.vector_dim, 3)},
    };
    for (const auto& item : docs) {
        EncryptedVector encrypted = fixture.crypto.encryptVector(fixture.keys.public_key, item.first, item.second);
        updater->insert(encrypted, 0);
    }
}

void testCryptoRoundTrip() {
    Fixture fixture(PRAGMode::PRAG_I);
    const std::vector<double> vector = {0.1, 0.2, 0.3};
    EncryptedVector encrypted = fixture.crypto.encryptVector(fixture.keys.public_key, "doc", vector);
    const std::vector<double> decrypted = fixture.crypto.decrypt(fixture.keys.secret_key, encrypted.ciphertext);
    for (std::size_t i = 0; i < vector.size(); ++i) {
        CHECK(std::abs(decrypted[i] - vector[i]) < 1e-6);
    }
    CHECK(encrypted.ciphertext.slotCount() == 3);
}

void testPragIRetrieval() {
    Fixture fixture(PRAGMode::PRAG_I);
    insertBaseDocs(fixture);
    const Ciphertext query = fixture.crypto.encryptQuery(fixture.keys.public_key, basis(fixture.config.system_params.vector_dim, 0));
    SearchResult result = fixture.mode_switch.retrievalEngine()->search(query, 3);
    CHECK(result.mode == "PRAG-I");
    CHECK(std::find(result.identifiers.begin(), result.identifiers.end(), "doc-alpha") != result.identifiers.end());
    CHECK(!result.access_paths.empty());
    CHECK(result.communication_bytes > 0);
}

void testPragIIRetrieval() {
    Fixture fixture(PRAGMode::PRAG_II);
    insertBaseDocs(fixture);
    const Ciphertext query = fixture.crypto.encryptQuery(fixture.keys.public_key, basis(fixture.config.system_params.vector_dim, 1));
    SearchResult result = fixture.mode_switch.retrievalEngine()->search(query, 3);
    CHECK(result.mode == "PRAG-II");
    CHECK(!result.identifiers.empty());
    CHECK(result.identifiers.front() == "doc-beta");
    CHECK(fixture.client.rounds() > 0);
}

void testUpdateAndSweep() {
    Fixture fixture(PRAGMode::PRAG_I);
    insertBaseDocs(fixture);
    std::unique_ptr<UpdateEngine> updater = fixture.mode_switch.updateEngine();
    EncryptedVector encrypted = fixture.crypto.encryptVector(fixture.keys.public_key, "doc-inserted", normalize(std::vector<double>(fixture.config.system_params.vector_dim, 1.0)));
    UpdateResult inserted = updater->insert(encrypted, 0);
    UpdateResult removed = updater->remove("doc-inserted");
    CHECK(inserted.success);
    CHECK(removed.success);
    CHECK(fixture.index.contains("doc-inserted"));
    UpdateResult swept = updater->sweep();
    CHECK(swept.touched_nodes == 1);
    CHECK(!fixture.index.contains("doc-inserted"));
}

void testModeSwitchReusesIndex() {
    Fixture fixture(PRAGMode::PRAG_I);
    insertBaseDocs(fixture);
    const std::size_t before = fixture.index.size();
    fixture.mode_switch.setMode(PRAGMode::PRAG_II);
    CHECK(fixture.index.size() == before);
    const Ciphertext query = fixture.crypto.encryptQuery(fixture.keys.public_key, basis(fixture.config.system_params.vector_dim, 1));
    SearchResult result = fixture.mode_switch.retrievalEngine()->search(query, 2);
    CHECK(result.mode == "PRAG-II");
}

}  // namespace

int main() {
    try {
        testCryptoRoundTrip();
        testPragIRetrieval();
        testPragIIRetrieval();
        testUpdateAndSweep();
        testModeSwitchReusesIndex();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "All PRAG C++ tests passed.\n";
    return EXIT_SUCCESS;
}
