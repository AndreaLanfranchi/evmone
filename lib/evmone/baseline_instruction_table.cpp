// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline_instruction_table.hpp"
#include "instructions_traits.hpp"

namespace evmone::baseline
{
const CostTable& get_baseline_cost_table(evmc_revision rev) noexcept
{
    static constexpr auto cost_tables = []() noexcept {
        std::array<CostTable, EVMC_MAX_REVISION + 1> tables{};
        for (size_t r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
        {
            auto& table = tables[r];
            for (size_t i = 0; i < table.size(); ++i)
            {
                table[i] = instr::gas_costs[r][i];  // Include instr::undefined in the table.
            }
        }
        return tables;
    }();

    return cost_tables[rev];
}

const CostTable& get_baseline_legacy_cost_table(evmc_revision rev) noexcept
{
    static auto cost_tables = []() noexcept {
        std::array<CostTable, EVMC_MAX_REVISION + 1> tables{};
        for (size_t r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r)
            tables[r] = get_baseline_cost_table(static_cast<evmc_revision>(r));

        tables[EVMC_CANCUN][OP_RJUMP] = instr::undefined;
        tables[EVMC_CANCUN][OP_RJUMPI] = instr::undefined;

        return tables;
    }();

    return cost_tables[rev];
}

}  // namespace evmone::baseline
