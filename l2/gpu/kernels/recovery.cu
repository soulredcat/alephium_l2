// Public signature recovery wrapper. Third-party arithmetic is MIT licensed;
// see vendor/LICENSE and provenance.json. No private signing keys enter GPU.
#include "recovery.cuh"
#include "keccak256.cuh"

extern "C" __global__ __launch_bounds__(128, 2) void l2_recover_public_keys(
    const uint8_t* hashes, const uint8_t* signatures, const int* recovery_ids,
    uint8_t* public_keys, uint8_t* addresses, uint8_t* valid, int count) {
    const int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    using namespace secp256k1::cuda;
    uint8_t* output = public_keys + static_cast<size_t>(index) * 65;
    for (int byte = 0; byte < 65; ++byte) output[byte] = 0;
    uint8_t* address = addresses + static_cast<size_t>(index) * 20;
    for (int byte = 0; byte < 20; ++byte) address[byte] = 0;
    valid[index] = 0;
    const int recid = recovery_ids[index];
    if (recid != 0 && recid != 1) return;
    const uint8_t* compact = signatures + static_cast<size_t>(index) * 64;
    ECDSASignatureGPU signature;
    if (!scalar_from_bytes_strict_nonzero(compact, &signature.r) ||
        !scalar_from_bytes_strict_nonzero(compact + 32, &signature.s) ||
        !scalar_is_low_s(&signature.s)) return;
    JacobianPoint recovered;
    if (!ecdsa_recover(hashes + static_cast<size_t>(index) * 32,
                      &signature, recid, &recovered)) return;
    if (!point_to_uncompressed(&recovered, output)) return;
    secp256k1_gpu::eth_address(output + 1, 64, address);
    valid[index] = 1;
}
