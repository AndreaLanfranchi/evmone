// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles.hpp"
#include <cassert>

#ifdef EVMONE_SILKPRE
#include <silkpre/precompile.h>
#endif

namespace evmone::state
{
using namespace evmc::literals;

std::optional<evmc::result> call_precompile(evmc_revision rev, const evmc_message& msg) noexcept
{
    if (evmc::is_zero(msg.code_address) || msg.code_address > 0x09_address)
        return {};

    const auto id = msg.code_address.bytes[19];
    if (rev < EVMC_BYZANTIUM && id > 4)
        return {};

    if (rev < EVMC_ISTANBUL && id > 8)  // TODO: test https://github.com/ethereum/tests/pull/1055
        return {};

#ifdef EVMONE_SILKPRE
    assert(id > 0);
    const auto index = id - 1;
    assert(index < SILKPRE_NUMBER_OF_ISTANBUL_CONTRACTS);

    const auto contract = kSilkpreContracts[index];
    const uint64_t cost = contract.gas(msg.input_data, msg.input_size, rev);
    assert(msg.gas >= 0);
    if (static_cast<uint64_t>(msg.gas) < cost)
        return evmc::result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
    const auto gas_left = msg.gas - static_cast<int64_t>(cost);

    const auto out = contract.run(msg.input_data, msg.input_size);
    if (out.data == nullptr)  // Null output also means failure.
        return evmc::result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
    evmc::result result{EVMC_SUCCESS, gas_left, out.data, out.size};
    std::free(out.data);
    return result;
#else
    return evmc::result{EVMC_INTERNAL_ERROR, 0, nullptr, 0};  // Not implemented.
#endif
}
}  // namespace evmone::state
