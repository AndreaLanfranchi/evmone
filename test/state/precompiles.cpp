// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles.hpp"
#include "hash_utils.hpp"
#include <intx/intx.hpp>
#include <cassert>
#include <limits>

#include "../../../silkpre/lib/silkpre/precompile.h"

extern "C" {

// Declare functions from Rust precompiles.

SilkpreResult ecadd_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;

SilkpreResult ecpairing_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;

SilkpreResult ripemd160_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;

SilkpreResult ethprecompiles_v1_ecmul_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;

SilkpreResult ethprecompiles1_sha256_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;

SilkpreResult ethprecompiles1_blake2bf_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;

SilkpreResult ethprecompile1_expmod_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept;
}

namespace evmone::state
{
using namespace evmc::literals;

namespace
{
constexpr auto GasCostMax = std::numeric_limits<int64_t>::max();

struct PrecompiledCost
{
    int64_t gas_cost;
    size_t output_size;
};

inline constexpr int64_t num_words(size_t size_in_bytes) noexcept
{
    return static_cast<int64_t>((size_in_bytes + 31) / 32);
}

template <int BaseCost, int WordCost>
inline constexpr int64_t cost_per_input_word(size_t input_size) noexcept
{
    return BaseCost + WordCost * num_words(input_size);
}

inline constexpr PrecompiledCost ecrecover_cost(
    const uint8_t* /*input*/, size_t /*input_size*/, evmc_revision /*rev*/) noexcept
{
    return {3000, 32};
}

inline SilkpreResult ecrecover_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept
{
    static constexpr size_t required_input_size = 128;
    assert(output_size == 32);
    uint8_t in[required_input_size]{};
    std::copy_n(input, std::min(input_size, required_input_size), in);

    uint8_t public_key[64];
    const auto v = intx::be::unsafe::load<intx::uint256>(in + 32);
    if (v != 27 && v != 28)
        return {0, 0};
    if (!eth_ecrecover_v1(public_key, in, in + 64, v != 27))
        return {0, 0};
    const auto hash = keccak256({public_key, std::size(public_key)});
    std::fill_n(output, 12, 0);
    std::copy_n(hash.bytes + 12, 20, output + 12);
    return {0, 32};
}

PrecompiledCost sha256_cost(const uint8_t*, size_t input_size, evmc_revision /*rev*/) noexcept
{
    return {cost_per_input_word<60, 12>(input_size), 32};
}

inline constexpr PrecompiledCost ripemd160_cost(
    const uint8_t* /*input*/, size_t input_size, evmc_revision /*rev*/) noexcept
{
    return {cost_per_input_word<600, 120>(input_size), 32};
}

PrecompiledCost identity_cost(const uint8_t*, size_t input_size, evmc_revision /*rev*/) noexcept
{
    return {cost_per_input_word<15, 3>(input_size), input_size};
}

PrecompiledCost ecadd_cost(const uint8_t*, size_t /*input_size*/, evmc_revision rev) noexcept
{
    return {rev >= EVMC_ISTANBUL ? 150 : 500, 64};
}

inline SilkpreResult ecadd_execute(
    const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size) noexcept
{
    static constexpr size_t required_input_size = 128;
    assert(output_size == 64);
    uint8_t in[required_input_size]{};
    std::copy_n(input, std::min(input_size, required_input_size), in);

    if (!eth_ecadd_v1(output, in, in + 64))
        return {1, 0};
    return {0, 64};
}

PrecompiledCost ecmul_cost(const uint8_t*, size_t /*input_size*/, evmc_revision rev) noexcept
{
    return {rev >= EVMC_ISTANBUL ? 6000 : 40000, 64};
}

PrecompiledCost ecpairing_cost(const uint8_t*, size_t input_size, evmc_revision rev) noexcept
{
    const auto num_inputs = static_cast<int64_t>(input_size / 192);
    return {
        rev >= EVMC_ISTANBUL ? 34'000 * num_inputs + 45'000 : 80'000 * num_inputs + 100'000, 32};
}

PrecompiledCost blake2bf_cost(const uint8_t* input, size_t input_size, evmc_revision) noexcept
{
    return {input_size == 213 ? intx::be::unsafe::load<uint32_t>(input) : GasCostMax, 64};
}

intx::uint256 mult_complexity_eip198(const intx::uint256& x) noexcept
{
    const intx::uint256 x_squared{x * x};
    if (x <= 64)
    {
        return x_squared;
    }
    else if (x <= 1024)
    {
        return (x_squared >> 2) + 96 * x - 3072;
    }
    else
    {
        return (x_squared >> 4) + 480 * x - 199680;
    }
}

intx::uint256 mult_complexity_eip2565(const intx::uint256& max_length) noexcept
{
    const intx::uint256 words{(max_length + 7) >> 3};  // ⌈max_length/8⌉
    return words * words;
}

PrecompiledCost internal_expmod_gas(const uint8_t* ptr, size_t len, evmc_revision rev) noexcept
{
    const int64_t min_gas{rev < EVMC_BERLIN ? 0 : 200};

    std::basic_string<uint8_t> input(ptr, len);
    if (input.size() < 3 * 32)
        input.resize(3 * 32);

    intx::uint256 base_len256{intx::be::unsafe::load<intx::uint256>(&input[0])};
    intx::uint256 exp_len256{intx::be::unsafe::load<intx::uint256>(&input[32])};
    intx::uint256 mod_len256{intx::be::unsafe::load<intx::uint256>(&input[64])};

    if (base_len256 == 0 && mod_len256 == 0)
    {
        return {min_gas, 0};
    }

    if (intx::count_significant_words(base_len256) > 1 ||
        intx::count_significant_words(exp_len256) > 1 ||
        intx::count_significant_words(mod_len256) > 1)
    {
        return {GasCostMax, 0};
    }

    uint64_t base_len64{static_cast<uint64_t>(base_len256)};
    uint64_t exp_len64{static_cast<uint64_t>(exp_len256)};

    input.erase(0, 3 * 32);

    intx::uint256 exp_head{0};  // first 32 bytes of the exponent
    if (input.length() > base_len64)
    {
        input.erase(0, base_len64);
        if (input.size() < 3 * 32)
            input.resize(3 * 32);
        if (exp_len64 < 32)
        {
            input.erase(exp_len64);
            input.insert(0, 32 - exp_len64, '\0');
        }
        exp_head = intx::be::unsafe::load<intx::uint256>(input.data());
    }
    unsigned bit_len{256 - clz(exp_head)};

    intx::uint256 adjusted_exponent_len{0};
    if (exp_len256 > 32)
    {
        adjusted_exponent_len = 8 * (exp_len256 - 32);
    }
    if (bit_len > 1)
    {
        adjusted_exponent_len += bit_len - 1;
    }

    if (adjusted_exponent_len < 1)
    {
        adjusted_exponent_len = 1;
    }

    const intx::uint256 max_length{std::max(mod_len256, base_len256)};

    intx::uint256 gas;
    if (rev < EVMC_BERLIN)
    {
        gas = mult_complexity_eip198(max_length) * adjusted_exponent_len / 20;
    }
    else
    {
        gas = mult_complexity_eip2565(max_length) * adjusted_exponent_len / 3;
    }

    if (gas > std::numeric_limits<int64_t>::max())
    {
        return {GasCostMax, 0};
    }
    else
    {
        return {std::max(min_gas, static_cast<int64_t>(gas)), static_cast<size_t>(mod_len256)};
    }
}

SilkpreResult identity_exec(const uint8_t* input, size_t input_size, uint8_t* output,
    [[maybe_unused]] size_t output_size) noexcept
{
    assert(output_size == input_size);
    std::copy_n(input, input_size, output);
    return {0, input_size};
}

struct PrecompiledTraits
{
    decltype(sha256_cost)* cost = nullptr;
    decltype(ethprecompiled_ecrecover)* exec = nullptr;
};

inline constexpr std::array<PrecompiledTraits, 10> traits{{
    {},  // undefined for 0
    {ecrecover_cost, ecrecover_execute},
    {sha256_cost, ethprecompiles1_sha256_execute},
    {ripemd160_cost, ripemd160_execute},
    {identity_cost, identity_exec},
    {internal_expmod_gas, ethprecompile1_expmod_execute},
    {ecadd_cost, ecadd_execute},
    {ecmul_cost, ethprecompiles_v1_ecmul_execute},
    {ecpairing_cost, ecpairing_execute},
    {blake2bf_cost, ethprecompiles1_blake2bf_execute},
}};
}  // namespace

std::optional<evmc::result> call_precompile(evmc_revision rev, const evmc_message& msg) noexcept
{
    if (evmc::is_zero(msg.code_address) || msg.code_address > 0x09_address)
        return {};

    const auto id = msg.code_address.bytes[19];
    if (rev < EVMC_BYZANTIUM && id > 4)
        return {};

    if (rev < EVMC_ISTANBUL && id > 8)  // TODO: test https://github.com/ethereum/tests/pull/1055
        return {};

    assert(id > 0);
    assert(msg.gas >= 0);

    uint8_t output_buf[256];  // Big enough to handle all "expmod" tests.

    const auto t = traits[id];
    const auto [gas_cost, max_output_size] = t.cost(msg.input_data, msg.input_size, rev);
    const auto gas_left = msg.gas - gas_cost;
    if (gas_left < 0)
        return evmc::result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
    assert(std::size(output_buf) >= max_output_size);
    const auto [status_code, output_size] =
        t.exec(msg.input_data, msg.input_size, output_buf, max_output_size);
    if (status_code != EVMC_SUCCESS)
        return evmc::result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
    return evmc::result{EVMC_SUCCESS, gas_left, output_buf, output_size};
}
}  // namespace evmone::state
