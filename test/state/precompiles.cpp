// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles.hpp"

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

    return evmc::result{EVMC_INTERNAL_ERROR, 0, nullptr, 0};  // Not implemented.
}
}  // namespace evmone::state
