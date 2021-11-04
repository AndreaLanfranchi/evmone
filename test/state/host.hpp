// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "state.hpp"
#include <optional>
#include <unordered_set>

namespace evmone::state
{
using evmc::uint256be;

class Host : public evmc::Host
{
    evmc_revision m_rev;
    evmc::VM& m_vm;
    State& m_state;
    const BlockInfo& m_block;
    const Transaction& m_tx;
    std::unordered_set<address> m_accessed_addresses;
    int64_t m_refund = 0;
    std::vector<address> m_destructs;
    std::vector<Log> m_logs;

public:
    Host(evmc_revision rev, evmc::VM& vm, State& state, const BlockInfo& block,
        const Transaction& tx) noexcept
      : m_rev{rev}, m_vm{vm}, m_state{state}, m_block{block}, m_tx{tx}
    {}

    [[nodiscard]] int64_t get_refund() const noexcept { return m_refund; }

    [[nodiscard]] const auto& get_destructs() const noexcept { return m_destructs; }

    [[nodiscard]] std::vector<Log>&& take_logs() noexcept { return std::move(m_logs); }

    evmc::result call(const evmc_message& msg) noexcept override;

private:
    bool account_exists(const address& addr) const noexcept override;

    bytes32 get_storage(const address& addr, const bytes32& key) const noexcept override;

    evmc_storage_status set_storage(
        const address& addr, const bytes32& key, const bytes32& value) noexcept override;

    uint256be get_balance(const address& addr) const noexcept override;

    size_t get_code_size(const address& addr) const noexcept override;

    bytes32 get_code_hash(const address& addr) const noexcept override;

    size_t copy_code(const address& addr, size_t code_offset, uint8_t* buffer_data,
        size_t buffer_size) const noexcept override;

    void selfdestruct(const address& addr, const address& beneficiary) noexcept override;

    evmc::result create(const evmc_message& msg) noexcept;

    evmc_tx_context get_tx_context() const noexcept override;

    bytes32 get_block_hash(int64_t block_number) const noexcept override;

    void emit_log(const address& addr, const uint8_t* data, size_t data_size,
        const bytes32 topics[], size_t topics_count) noexcept override;

    evmc_access_status access_account(const address& addr) noexcept override;

    evmc_access_status access_storage(const address& addr, const bytes32& key) noexcept override;

    evmc::result execute_message(const evmc_message& msg) noexcept;
};
}  // namespace evmone::state
