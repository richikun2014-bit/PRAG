#pragma once

#include <cstddef>
#include <vector>

#include "prag/client/crypto_utils.hpp"
#include "prag/common/types.hpp"

namespace prag {

/** Client-assisted comparison callback used only by PRAG-II. */
class InteractiveClient {
public:
    /** Create a callback with trusted access to the client secret key. */
    InteractiveClient(const CryptoUtils& crypto, SecretKey secret_key);

    /** Return the index of the largest decrypted score. */
    int decryptAndCompare(const std::vector<Ciphertext>& encrypted_scores);

    /** Return indices of the top-k decrypted scores. */
    std::vector<int> decryptAndTopK(const std::vector<Ciphertext>& encrypted_scores, int k);

    /** Return top cluster indices from encrypted cluster scores. */
    std::vector<int> selectCluster(const std::vector<Ciphertext>& encrypted_scores, int cluster_probe);

    /** Return the number of client-assisted comparison rounds. */
    int rounds() const;

    /** Return encrypted bytes received by the callback. */
    std::size_t bytesReceived() const;

private:
    const CryptoUtils& crypto_;
    SecretKey secret_key_;
    int rounds_ = 0;
    std::size_t bytes_received_ = 0;
};

}  // namespace prag

