#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace prag {

/** Operating mode for a PRAG deployment. */
enum class PRAGMode {
    PRAG_I,
    PRAG_II
};

/** CKKS-style parameter set used by the encrypted arithmetic backend. */
struct CKKSParams {
    std::size_t polynomial_modulus_degree = 16384;
    std::vector<int> coefficient_modulus_bits = {60, 40, 40, 40, 40, 40, 40, 40, 60};
    double scale = 1099511627776.0;
    int security_level_bits = 128;
};

/** HNSW navigation parameters for encrypted graph search. */
struct HNSWParams {
    int max_layers = 3;
    int max_degree = 8;
    int search_depth = 32;
    double level_multiplier = 0.5;
};

/** System-level retrieval and leakage-mitigation parameters. */
struct SystemParams {
    std::size_t vector_dim = 16;
    int cluster_count = 4;
    int cluster_probe = 2;
    int top_k = 5;
    double dummy_rate = 0.2;
    int path_pad_length = 8;
    int reencryption_epoch = 1000;
    std::uint32_t random_seed = 7;
};

/** Runtime configuration shared by client and server modules. */
struct Config {
    PRAGMode mode = PRAGMode::PRAG_I;
    CKKSParams ckks_params;
    HNSWParams hnsw_params;
    SystemParams system_params;
    int chebyshev_degree = 3;
    double chebyshev_scale = 1.0;
    int max_interactive_rounds = 100;
    double oee_margin = 1e-2;
};

/** Convert a PRAG mode to a stable display string. */
std::string modeName(PRAGMode mode);

}  // namespace prag
