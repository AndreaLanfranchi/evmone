// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "host.hpp"
#include "precompiles.hpp"
#include "rlp.hpp"
#include <iostream>

namespace evmone::state
{
bool Host::account_exists(const address& addr) const noexcept
{
    const auto* const acc = m_state.get_or_null(addr);
    return acc != nullptr && (m_rev < EVMC_SPURIOUS_DRAGON || !acc->is_empty());
}

bytes32 Host::get_storage(const address& addr, const bytes32& key) const noexcept
{
    const auto& acc = m_state.get(addr);
    if (const auto it = acc.storage.find(key); it != acc.storage.end())
        return it->second.current;
    return {};
}

enum storage_status2
{
    ST_MODIFIED_AGAIN,
    ST_ADDED,
    ST_MODIFIED,
    ST_DELETED,
    ST_DELETED_ADDED,
    ST_MODIFIED_DELETED,
    ST_ADDED_DELETED,
    ST_MODIFIED_RESTORED,
    ST_DELETED_RESTORED,
};

struct StorageTrait
{
    evmc_storage_status old_status;
    int32_t refund;
};

static constexpr auto storage_traits = []() noexcept {
    std::array<std::array<StorageTrait, 9>, EVMC_MAX_REVISION + 1> tbl{};

    auto& frontier = tbl[EVMC_FRONTIER];
    frontier[ST_MODIFIED_AGAIN] = {EVMC_STORAGE_MODIFIED_AGAIN, 0};
    frontier[ST_ADDED] = {EVMC_STORAGE_ADDED, 0};
    frontier[ST_MODIFIED] = {EVMC_STORAGE_MODIFIED, 0};
    frontier[ST_DELETED] = {EVMC_STORAGE_DELETED, 15000};
    frontier[ST_DELETED_ADDED] = frontier[ST_ADDED];
    frontier[ST_MODIFIED_DELETED] = frontier[ST_DELETED];
    frontier[ST_ADDED_DELETED] = frontier[ST_DELETED];
    frontier[ST_MODIFIED_RESTORED] = frontier[ST_MODIFIED];
    frontier[ST_DELETED_RESTORED] = frontier[ST_ADDED];

    tbl[EVMC_HOMESTEAD] = frontier;
    tbl[EVMC_TANGERINE_WHISTLE] = frontier;
    tbl[EVMC_SPURIOUS_DRAGON] = frontier;
    tbl[EVMC_BYZANTIUM] = frontier;

    auto& constantinople = tbl[EVMC_CONSTANTINOPLE];

    constantinople[ST_MODIFIED_AGAIN] = {EVMC_STORAGE_MODIFIED_AGAIN, 0};
    constantinople[ST_ADDED] = {EVMC_STORAGE_ADDED, 0};
    constantinople[ST_MODIFIED] = {EVMC_STORAGE_MODIFIED, 0};
    constantinople[ST_DELETED] = {EVMC_STORAGE_DELETED, 15000};
    constantinople[ST_DELETED_ADDED] = {EVMC_STORAGE_MODIFIED_AGAIN, -15000};
    constantinople[ST_MODIFIED_DELETED] = {EVMC_STORAGE_MODIFIED_AGAIN, 15000};
    constantinople[ST_ADDED_DELETED] = {EVMC_STORAGE_MODIFIED_AGAIN, 19800};
    constantinople[ST_MODIFIED_RESTORED] = {EVMC_STORAGE_MODIFIED_AGAIN, 4800};
    constantinople[ST_DELETED_RESTORED] = {EVMC_STORAGE_MODIFIED_AGAIN, 4800 - 15000};

    tbl[EVMC_PETERSBURG] = frontier;

    auto& istanbul = tbl[EVMC_ISTANBUL] = constantinople;
    istanbul[ST_ADDED_DELETED].refund = 19200;
    istanbul[ST_DELETED_RESTORED].refund = 4200 - 15000;
    istanbul[ST_MODIFIED_RESTORED].refund = 4200;

    auto& berlin = tbl[EVMC_BERLIN] = istanbul;
    berlin[ST_ADDED_DELETED].refund = 19900;
    berlin[ST_DELETED_RESTORED].refund = 2800 - 15000;
    berlin[ST_MODIFIED_RESTORED].refund = 2800;

    auto& london = tbl[EVMC_LONDON] = berlin;
    london[ST_DELETED].refund = 4800;
    london[ST_DELETED_RESTORED].refund = 2800 - 4800;
    london[ST_MODIFIED_DELETED].refund = 4800;
    london[ST_DELETED_ADDED].refund = -4800;

    tbl[EVMC_PARIS] = london;
    tbl[EVMC_SHANGHAI] = london;
    tbl[EVMC_CANCUN] = london;

    return tbl;
}();

struct HitMap
{
    std::array<std::array<bool, 9>, EVMC_MAX_REVISION + 1> tbl{};

    ~HitMap()
    {
        for (auto& rev : tbl)
        {
            for (auto b : rev)
                std::cerr << int(b);
            std::cerr << "\n";
        }
    }
};

static HitMap hitmap;

evmc_storage_status Host::set_storage(
    const address& addr, const bytes32& key, const bytes32& value) noexcept
{
    auto& storage = m_state.get(addr).storage;

    // Follow https://eips.ethereum.org/EIPS/eip-2200 specification.

    /* Outdated
    o       c   n                       f t d r   legacy
    0|X →…→ A → A  modified locally     0 0 0 0   m
    0|X →…→ Y → Z  modified locally     1 1 1 1
                                            1
                                            1
                                            1
                                            1
                                            1
                                            1

    X   →…→ X → 0  deleted              1 0 0 0   d
    0   →…→ 0 → X  added                0 1 0 0   a
    X   →…→ X → Y  modified             1 1 0 0   m

    X   →…→ 0 → Y  deleted added        0 1 1 0   a
    X   →…→ 0 → X  deleted restored     0 1 1 1   a
    0   →…→ X → 0  added deleted        1 0 1 1   d
    X   →…→ Y → X  modified restored    1 1 1 1   m
    X   →…→ Y → 0  modified deleted     1 0 1 0   d
    */

    auto& [current, original, _] = storage[key];
    [[maybe_unused]] const auto prev_refund = m_refund;

    const StorageTrait* t = nullptr;
    int xxxx = -1;
    auto st = static_cast<storage_status2>(xxxx);

    if (m_rev <= EVMC_LONDON)
    {
        st = ST_MODIFIED_AGAIN;
        if (current != value)
        {
            if (original == current)
            {
                if (is_zero(current))
                {
                    assert(is_zero(current) && !is_zero(value));
                    st = ST_ADDED;
                }
                else if (!is_zero(value))
                {
                    assert(!is_zero(current));
                    st = ST_MODIFIED;
                }
                else
                {
                    assert(!is_zero(current) && is_zero(value));
                    st = ST_DELETED;
                }
            }
            else  // dirty
            {
                if (original == value)  // restored
                {
                    if (is_zero(value))  // 0 -> Y -> 0 "added deleted"
                    {
                        assert(is_zero(original));
                        assert(is_zero(value));
                        assert(!is_zero(current));
                        st = ST_ADDED_DELETED;
                    }
                    else if (is_zero(current))  // X -> 0 -> X "deleted restored"
                    {
                        st = ST_DELETED_RESTORED;
                    }
                    else  // X -> Y -> X "modified restored"
                    {
                        assert(!is_zero(value));
                        st = ST_MODIFIED_RESTORED;
                    }
                }
                else
                {
                    if (is_zero(value))  // X -> Y -> 0 "modified deleted"
                    {
                        assert(!is_zero(current));
                        assert(is_zero(value));
                        assert(original != value);
                        st = ST_MODIFIED_DELETED;
                    }
                    else if (is_zero(current))  // X -> 0 -> Y "deleted added"
                    {
                        st = ST_DELETED_ADDED;
                    }
                    else
                    {
                        // 0 -> Y -> Z "added modified"
                        // X -> Y -> Z "modified modified"
                        assert(!is_zero(current));
                        assert(!is_zero(value));
                        assert(value != current);
                    }
                }
            }
        }

        hitmap.tbl[m_rev][st] = true;

        // old.current = value;
        // const auto& t = storage_traits[m_rev][st];
        // m_refund += t.refund;
        // return t.old_status;

        t = &storage_traits[m_rev][st];
    }

    auto status = EVMC_STORAGE_MODIFIED_AGAIN;
    if (current != value)
    {
        if (original == current || m_rev < EVMC_CONSTANTINOPLE || m_rev == EVMC_PETERSBURG)
        {
            if (is_zero(current))
            {
                assert(is_zero(current) && !is_zero(value));
                status = EVMC_STORAGE_ADDED;
            }
            else if (!is_zero(value))
            {
                assert(!is_zero(current));
                status = EVMC_STORAGE_MODIFIED;
            }
            else
            {
                assert(!is_zero(current) && is_zero(value));
                status = EVMC_STORAGE_DELETED;
                m_refund += (m_rev >= EVMC_LONDON) ? 4800 : 15000;
            }
        }
        else  // dirty
        {
            if (original == value)  // restored
            {
                if (is_zero(value))  // 0 -> Y -> 0 "added deleted"
                {
                    assert(is_zero(original));
                    assert(is_zero(value));
                    assert(!is_zero(current));
                    m_refund += (m_rev >= EVMC_BERLIN)         ? 19900 :
                                (m_rev == EVMC_CONSTANTINOPLE) ? 19800 :
                                                                 19200;
                }
                else if (is_zero(current))  // X -> 0 -> X "deleted restored"
                {
                    m_refund += (m_rev >= EVMC_LONDON)         ? 2800 - 4800 :
                                (m_rev >= EVMC_BERLIN)         ? 2800 - 15000 :
                                (m_rev == EVMC_CONSTANTINOPLE) ? 4800 - 15000 :
                                                                 4200 - 15000;
                }
                else  // X -> Y -> X "modified restored"
                {
                    assert(!is_zero(value));
                    m_refund += (m_rev >= EVMC_BERLIN)         ? 2800 :
                                (m_rev == EVMC_CONSTANTINOPLE) ? 4800 :
                                                                 4200;
                }
            }
            else
            {
                if (is_zero(value))  // X -> Y -> 0 "modified deleted"
                {
                    assert(!is_zero(current));
                    assert(is_zero(value));
                    assert(original != value);
                    m_refund += (m_rev >= EVMC_LONDON) ? 4800 : 15000;
                }
                else if (is_zero(current))  // X -> 0 -> Y "deleted added"
                {
                    m_refund += (m_rev >= EVMC_LONDON) ? -4800 : -15000;
                }
                else
                {
                    // 0 -> Y -> Z "added modified"
                    // X -> Y -> Z "modified modified"
                    assert(!is_zero(current));
                    assert(!is_zero(value));
                    assert(value != current);
                }
            }
        }
    }

    // assert((m_refund - prev_refund) != 4800);  // X → Y → 0  modified deleted
    // assert((m_refund - prev_refund) != 2800);  // X → Y → X  modified restored
    // assert((m_refund - prev_refund) != 19900);  // 0 → X → 0  added deleted
    // assert((m_refund - prev_refund) != -4800);  // X → 0 → Y  deleted added
    // assert((m_refund - prev_refund) != -2000); // X → 0 → X  deleted restored
    //  std::cerr << std::dec << "REFUND: " << m_refund << " (" << (m_refund - prev_refund) <<
    //  ")\n";

    if (t != nullptr)
    {
        auto old_status = t->old_status;
        if (old_status == EVMC_STORAGE_MODIFIED_AGAIN && current != value &&
            (m_rev < EVMC_CONSTANTINOPLE || m_rev == EVMC_PETERSBURG))
            old_status = EVMC_STORAGE_MODIFIED;

        const auto refund = m_refund - prev_refund;
        if (status != old_status)
        {
            std::cerr << "c: " << status << " n: " << old_status << "\n";
            std::cerr << evmc::hex(original) << " " << hex(current) << " " << hex(value) << "\n";
        }
        assert(status == old_status);
        assert(refund == t->refund);
    }

    current = value;
    return status;
}

uint256be Host::get_balance(const address& addr) const noexcept
{
    const auto* const acc = m_state.get_or_null(addr);
    return (acc != nullptr) ? intx::be::store<uint256be>(acc->balance) : uint256be{};
}

size_t Host::get_code_size(const address& addr) const noexcept
{
    const auto* const acc = m_state.get_or_null(addr);
    return (acc != nullptr) ? acc->code.size() : 0;
}

bytes32 Host::get_code_hash(const address& addr) const noexcept
{
    // TODO: Cache code hash. It will be needed also to compute the MPT hash.
    const auto* const acc = m_state.get_or_null(addr);
    return (acc != nullptr && !acc->is_empty()) ? keccak256(acc->code) : bytes32{};
}

size_t Host::copy_code(const address& addr, size_t code_offset, uint8_t* buffer_data,
    size_t buffer_size) const noexcept
{
    const auto* const acc = m_state.get_or_null(addr);
    const auto code = (acc != nullptr) ? bytes_view{acc->code} : bytes_view{};
    const auto code_slice = code.substr(std::min(code_offset, code.size()));
    const auto num_bytes = std::min(buffer_size, code_slice.size());
    std::copy_n(code_slice.begin(), num_bytes, buffer_data);
    return num_bytes;
}

void Host::selfdestruct(const address& addr, const address& beneficiary) noexcept
{
    auto& beneficiary_acc = m_state.get_or_create(beneficiary);
    beneficiary_acc.touched = true;

    // Immediately transfer all balance to beneficiary.
    // This may happen multiple times per single account as account's balance
    // can be increased with a call following previous selfdestruct.
    if (auto& acc = m_state.get(addr); acc.balance != 0)
    {
        beneficiary_acc.balance += acc.balance;  // Already touched.
        acc.balance = 0;
    }

    // Register the destruction if not done already.
    if (std::find(m_destructs.begin(), m_destructs.end(), addr) == m_destructs.end())
    {
        m_destructs.push_back(addr);
        m_refund += (m_rev < EVMC_LONDON) ? 24000 : 0;
    }
}

static address compute_new_address(const evmc_message& msg, uint64_t sender_nonce) noexcept
{
    hash256 addr_base_hash;
    if (msg.kind == EVMC_CREATE)
    {
        const auto rlp_list = rlp::encode_tuple(address{msg.sender}, sender_nonce);
        addr_base_hash = keccak256(rlp_list);
    }
    else
    {
        const auto init_code_hash = keccak256({msg.input_data, msg.input_size});
        uint8_t buffer[1 + sizeof(msg.sender) + sizeof(msg.create2_salt) + sizeof(init_code_hash)];
        static_assert(std::size(buffer) == 85);
        buffer[0] = 0xff;
        std::memcpy(&buffer[1], msg.sender.bytes, sizeof(msg.sender));
        std::memcpy(
            &buffer[1 + sizeof(msg.sender)], msg.create2_salt.bytes, sizeof(msg.create2_salt));
        std::memcpy(&buffer[1 + sizeof(msg.sender) + sizeof(msg.create2_salt)],
            init_code_hash.bytes, sizeof(init_code_hash));
        addr_base_hash = keccak256({buffer, std::size(buffer)});
    }
    evmc_address new_addr{};
    std::memcpy(new_addr.bytes, &addr_base_hash.bytes[12], sizeof(new_addr));
    return new_addr;
}

evmc::result Host::create(const evmc_message& msg) noexcept
{
    assert(msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2);

    auto& sender_acc = m_state.get(msg.sender);
    const auto sender_nonce = msg.depth == 0 ? sender_acc.nonce - 1 : sender_acc.nonce;
    const auto new_addr = compute_new_address(msg, sender_nonce);

    if (msg.depth != 0)
    {
        if (!m_state.get(msg.sender).bump_nonce())
        {
            // This is light early check and gas it not consumed
            // nor the create-address is "accessed".
            return evmc::result{EVMC_OUT_OF_GAS, msg.gas};
        }
    }

    m_accessed_addresses.insert(new_addr);

    // Check collision as defined in pseudo-EIP https://github.com/ethereum/EIPs/issues/684.
    // All combinations of conditions (nonce, code, storage) are tested.
    if (const auto collision_acc = m_state.get_or_null(new_addr);
        collision_acc != nullptr && !(collision_acc->nonce == 0 && collision_acc->code.empty()))
        return evmc::result{EVMC_OUT_OF_GAS, 0, new_addr};

    auto& new_acc = m_state.get_or_create(new_addr);
    if (m_rev >= EVMC_SPURIOUS_DRAGON)
        new_acc.nonce = 1;
    new_acc.storage.clear();  // In case of collision.

    const auto value = intx::be::load<intx::uint256>(msg.value);
    assert(sender_acc.balance >= value && "EVM must guarantee balance");
    sender_acc.balance -= value;
    new_acc.balance += value;  // The new account may be prefunded.

    evmc_message create_msg{};
    create_msg.kind = msg.kind;
    create_msg.depth = msg.depth;
    create_msg.gas = msg.gas;
    create_msg.recipient = new_addr;
    create_msg.sender = msg.sender;
    create_msg.value = msg.value;

    // Execution can modify the state, iterators are invalidated.
    auto result = m_vm.execute(*this, m_rev, create_msg, msg.input_data, msg.input_size);
    if (result.status_code != EVMC_SUCCESS)
    {
        result.create_address = new_addr;
        return result;
    }

    auto gas_left = result.gas_left;
    assert(gas_left >= 0);

    bytes_view code{result.output_data, result.output_size};
    if (m_rev >= EVMC_SPURIOUS_DRAGON && code.size() > 0x6000)
        return evmc::result{EVMC_OUT_OF_GAS, 0, new_addr};

    const auto cost = static_cast<int64_t>(code.size()) * 200;
    gas_left -= cost;
    if (gas_left < 0)
    {
        evmc::result r{EVMC_OUT_OF_GAS, 0, new_addr};

        if (m_rev == EVMC_FRONTIER)
        {
            r.status_code = EVMC_SUCCESS;
            r.gas_left = result.gas_left;
        }

        return r;
    }

    // Reject EF code.
    if (m_rev >= EVMC_LONDON && !code.empty() && code[0] == 0xEF)
        return evmc::result{EVMC_OUT_OF_GAS, 0, new_addr};

    // TODO: The new_acc pointer is invalid because of the state revert implementation,
    //       but this should change if state journal is implemented.
    m_state.get(new_addr).code = code;

    return evmc::result{result.status_code, gas_left, new_addr};
}

evmc::result Host::execute_message(const evmc_message& msg) noexcept
{
    if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2)
        return create(msg);

    auto* const code_acc = m_state.get_or_null(msg.code_address);

    if (msg.kind == EVMC_CALL)
    {
        // TODO: Should not create empty touched account?
        assert(evmc::address{msg.recipient} == msg.code_address);
        auto& recipient_acc = code_acc != nullptr ? *code_acc : m_state.create(msg.recipient);
        recipient_acc.touched = true;

        // Transfer value.
        const auto value = intx::be::load<intx::uint256>(msg.value);
        assert(m_state.get(msg.sender).balance >= value);
        m_state.get(msg.sender).balance -= value;
        recipient_acc.balance += value;
    }

    if (auto precompiled_result = call_precompile(m_rev, msg); precompiled_result.has_value())
        return std::move(*precompiled_result);

    // Copy of the code. Revert will invalidate the account.
    const auto code = code_acc != nullptr ? code_acc->code : bytes{};
    return m_vm.execute(*this, m_rev, msg, code.data(), code.size());
}

evmc::result Host::call(const evmc_message& msg) noexcept
{
    auto state_snapshot = m_state;
    const auto refund_snapshot = m_refund;
    auto destructs_snapshot = m_destructs.size();
    auto access_addresses_snapshot = m_accessed_addresses;
    auto logs_snapshot = m_logs.size();

    auto result = execute_message(msg);

    if (result.status_code != EVMC_SUCCESS)
    {
        static constexpr auto addr_03 = 0x03_address;
        auto* const acc_03 = m_state.get_or_null(addr_03);
        const auto is_03_touched = acc_03 != nullptr && acc_03->touched;

        // Revert.
        m_state = std::move(state_snapshot);
        m_refund = refund_snapshot;
        m_destructs.resize(destructs_snapshot);
        m_accessed_addresses = std::move(access_addresses_snapshot);
        m_logs.resize(logs_snapshot);

        // The 0x03 quirk: the touch on this address is never reverted.
        if (is_03_touched && m_rev >= EVMC_SPURIOUS_DRAGON)
            m_state.get_or_create(addr_03).touched = true;

        if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2)
        {
            // FIXME: What if the reason of failure is max nonce?
            if (msg.depth != 0)
                (void)m_state.get(msg.sender).bump_nonce();  // Nonce bump is not reverted.

            // By EIP-2929, the  access to new created address is never reverted.
            if (!evmc::is_zero(result.create_address))
                m_accessed_addresses.insert(result.create_address);
        }
    }
    return result;
}

evmc_tx_context Host::get_tx_context() const noexcept
{
    // TODO: The effective gas price is already computed in transaction validation.
    const auto priority_gas_price =
        std::min(m_tx.max_priority_gas_price, m_tx.max_gas_price - m_block.base_fee);
    const auto effective_gas_price = m_block.base_fee + priority_gas_price;

    return evmc_tx_context{
        intx::be::store<uint256be>(effective_gas_price),  // By EIP-1559.
        m_tx.sender,
        m_block.coinbase,
        m_block.number,
        m_block.timestamp,
        m_block.gas_limit,
        m_block.prev_randao,
        0x01_bytes32,  // Chain ID is expected to be 1.
        uint256be{m_block.base_fee},
    };
}

bytes32 Host::get_block_hash(int64_t block_number) const noexcept
{
    (void)block_number;
    // TODO: This is not properly implemented, but only single state test requires BLOCKHASH
    //       and is fine with any value.
    return {};
}

void Host::emit_log(const address& addr, const uint8_t* data, size_t data_size,
    const bytes32 topics[], size_t topics_count) noexcept
{
    m_logs.push_back({addr, {data, data_size}, {topics, topics + topics_count}});
}

evmc_access_status Host::access_account(const address& addr) noexcept
{
    // TODO: Predefined warm addresses can be applied to the state cache before execution.

    // Transaction {sender,to} are always warm.
    if (addr == m_tx.to)
        return EVMC_ACCESS_WARM;
    if (addr == m_tx.sender)
        return EVMC_ACCESS_WARM;

    // Accessing precompiled contracts is always warm.
    if (addr >= 0x01_address && addr <= 0x09_address)
        return EVMC_ACCESS_WARM;

    // Check tx access list.
    for (const auto& [a, _] : m_tx.access_list)
    {
        if (a == addr)
            return EVMC_ACCESS_WARM;
    }

    return m_accessed_addresses.insert(addr).second ? EVMC_ACCESS_COLD : EVMC_ACCESS_WARM;
}

evmc_access_status Host::access_storage(const address& addr, const bytes32& key) noexcept
{
    // Check tx access list.
    // TODO: Tx access list can be applied to the storage cache before execution.
    for (const auto& [a, storage_keys] : m_tx.access_list)
    {
        if (a == addr && std::count(storage_keys.begin(), storage_keys.end(), key) != 0)
            return EVMC_ACCESS_WARM;
    }

    return std::exchange(m_state.get(addr).storage[key].access_status, EVMC_ACCESS_WARM);
}
}  // namespace evmone::state
