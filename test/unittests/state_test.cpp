// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <ethash/keccak.hpp>
#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <evmc/mocked_host.hpp>
#include <gtest/gtest.h>
#include <cstring>

// Better API and utils
// ====================

using evmc::bytes;
using evmc::bytes_view;
using namespace evmc::literals;

/// Better than ethash::hash256 because has some additional handy constructors.
using hash256 = evmc::bytes32;

inline hash256 keccak256(bytes_view data) noexcept
{
    const auto eh = ethash::keccak256(std::data(data), std::size(data));
    hash256 h;
    std::memcpy(h.bytes, eh.bytes, sizeof(h));
    return h;
}

inline hash256 keccak256(const evmc::address& addr) noexcept
{
    return keccak256({addr.bytes, sizeof(addr)});
}

inline hash256 keccak256(const evmc::bytes32& h) noexcept
{
    return keccak256({h.bytes, sizeof(h)});
}

using evmc::address;
using evmc::from_hex;
using evmc::hex;
using Account = evmc::MockedAccount;

inline auto hex(const hash256& h) noexcept
{
    return hex({h.bytes, std::size(h.bytes)});
}

inline bytes to_bytes(std::string_view s)
{
    bytes b;
    b.reserve(std::size(s));
    for (const auto c : s)
        b.push_back(static_cast<uint8_t>(c));
    return b;
}


// Temporary needed up here to hock RLP encoding of an Account.
constexpr auto emptyTrieHash =
    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

constexpr auto emptyCodeHash =
    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;


// RLP
// ===

namespace rlp
{
inline bytes string(bytes_view data)
{
    const auto l = std::size(data);
    if (l == 1 && data[0] <= 0x7f)
        return bytes{data[0]};
    if (l <= 55)
        return bytes{static_cast<uint8_t>(0x80 + l)} + bytes{data};

    // FIXME: Should it skip zero bytes?
    assert(data.size() <= 0xff);
    return bytes{0xb7 + 1, static_cast<uint8_t>(l)} + bytes{data};
}

inline bytes string(const hash256& b)
{
    size_t i = 0;
    for (; i < sizeof(b); ++i)
    {
        if (b.bytes[i] != 0)
            break;
    }
    const size_t l = sizeof(b) - i;
    return string({&b.bytes[i], l});
}

inline bytes string(int x)
{
    // TODO: Account::nonce should be uint64_t.
    uint8_t b[sizeof(x)];
    const auto be = __builtin_bswap32(static_cast<unsigned>(x));
    __builtin_memcpy(b, &be, sizeof(be));

    size_t i = 0;
    for (; i < sizeof(b); ++i)
    {
        if (b[i] != 0)
            break;
    }
    const size_t l = sizeof(b) - i;
    return string({&b[i], l});
}

template <typename... Items>
inline bytes list(const Items&... items)
{
    const bytes string_items[] = {string(items)...};
    size_t items_len = 0;
    for (const auto& s : string_items)
        items_len += std::size(s);
    assert(items_len <= 0xff);
    auto r = (items_len <= 55) ? bytes{static_cast<uint8_t>(0xc0 + items_len)} :
                                 bytes{0xf7 + 1, static_cast<uint8_t>(items_len)};
    for (const auto& s : string_items)
        r += s;
    return r;
}

bytes encode(const Account& a)
{
    assert(a.storage.empty());
    assert(a.code.empty());
    return rlp::list(a.nonce, a.balance, emptyTrieHash, emptyCodeHash);
}
}  // namespace rlp


// State Trie
// ==========

namespace
{
struct BranchNode
{
    hash256 items[16];
    void insert(uint8_t nibble, const hash256& value) { items[nibble] = value; }

    [[nodiscard]] bytes rlp() const
    {
        return rlp::list(items[0], items[1], items[2], items[3], items[4], items[5], items[6],
            items[7], items[8], items[9], items[10], items[11], items[12], items[13], items[14],
            items[15], bytes_view{});
    }

    [[nodiscard]] hash256 hash() const { return keccak256(rlp()); }
};

class Trie
{
    std::map<bytes, bytes> m_map;

public:
    static bytes build_leaf_node(bytes_view path, bytes_view value)
    {
        const auto encoded_path = bytes{0x20} + bytes{path};
        return rlp::list(encoded_path, value);
    }

    void insert(bytes k, bytes v) { m_map[std::move(k)] = std::move(v); }

    /// Helper
    void insert(hash256 k, bytes v) { insert(bytes{k.bytes, sizeof(k)}, std::move(v)); }

    [[nodiscard]] hash256 get_root_hash() const
    {
        const auto size = std::size(m_map);
        if (size == 0)
            return emptyTrieHash;
        else if (size == 1)
        {
            const auto& [k, v] = *m_map.begin();
            return keccak256(build_leaf_node(k, v));
        }

        return {};
    }
};

using State = std::map<address, Account>;
bytes build_leaf_node(const address& addr, const Account& account)
{
    const auto path = keccak256(addr);
    const auto encoded_path = bytes{0x20} + bytes{path.bytes, sizeof(path)};
    const auto value = rlp::encode(account);  // Double RLP encoding.
    return rlp::list(encoded_path, value);
}

bytes build_leaf_node(const hash256& key, const hash256& value)
{
    const auto path = keccak256(key);
    const auto encoded_path = bytes{0x20} + bytes{path.bytes, sizeof(path)};
    return rlp::list(encoded_path, rlp::string(value));
}

hash256 hash_leaf_node(const address& addr, const Account& account)
{
    const auto node = build_leaf_node(addr, account);
    return keccak256(node);
}


[[maybe_unused]] ethash::hash256 compute_state_root(const State& state)
{
    (void)state;
    return {};
}
}  // namespace


TEST(state, empty_code_hash)
{
    const auto empty = keccak256(bytes_view{});
    EXPECT_EQ(hex(empty), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    EXPECT_EQ(emptyCodeHash, empty);
}

TEST(state, rlp_v1)
{
    const auto expected = from_hex(
        "f8 44"
        "80"
        "01"
        "a0 56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        "a0 c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    Account a;
    a.set_balance(1);
    EXPECT_EQ(hex(rlp::encode(a)), hex(expected));
    EXPECT_EQ(rlp::encode(a).size(), 70);

    EXPECT_EQ(hex(rlp::string(0x31)), "31");
}

TEST(state, empty_trie)
{
    const auto rlp_null = bytes{0x80};
    const auto empty_trie_hash = keccak256(rlp_null);
    EXPECT_EQ(empty_trie_hash, emptyTrieHash);

    Trie trie;
    EXPECT_EQ(trie.get_root_hash(), emptyTrieHash);
}

TEST(state, hashed_address)
{
    const auto addr = 0x0000000000000000000000000000000000000002_address;
    const auto hashed_addr = keccak256(addr);
    EXPECT_EQ(hex(hashed_addr), "d52688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62");
}

TEST(state, build_leaf_node)
{
    State state;
    const auto addr = 0x0000000000000000000000000000000000000002_address;
    state[addr].set_balance(1);
    const auto node = build_leaf_node(addr, state[addr]);
    EXPECT_EQ(hex(node),
        "f86aa120d52688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62b846f8448001a056e8"
        "1f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc7"
        "03c0e500b653ca82273b7bfad8045d85a470");
}

TEST(state, single_account_v1)
{
    // Expected value computed in go-ethereum.

    Account a;
    const auto addr = 0x0000000000000000000000000000000000000002_address;
    a.set_balance(1);

    const auto h = hash_leaf_node(addr, a);
    EXPECT_EQ(hex(h), "084f337237951e425716a04fb0aaa74111eda9d9c61767f2497697d0a201c92e");

    Trie trie;
    trie.insert(keccak256(addr), rlp::encode(a));
    EXPECT_EQ(hex(trie.get_root_hash()),
        "084f337237951e425716a04fb0aaa74111eda9d9c61767f2497697d0a201c92e");
}

TEST(state, storage_trie_v1)
{
    const auto key = 0_bytes32;
    const auto value = 0x00000000000000000000000000000000000000000000000000000000000001ff_bytes32;
    const auto node = build_leaf_node(key, value);
    EXPECT_EQ(hex(node),
        "e6a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563838201ff");
    const auto root = keccak256(node);
    EXPECT_EQ(hex(root), "d9aa83255221f68fdd4931f73f8fe6ea30c191a9619b5fc60ce2914eee1e7e54");

    Trie trie;
    trie.insert(keccak256(key), rlp::string(value));
    EXPECT_EQ(hex(trie.get_root_hash()),
        "d9aa83255221f68fdd4931f73f8fe6ea30c191a9619b5fc60ce2914eee1e7e54");
}

TEST(state, trie_ex1)
{
    Trie trie;
    const auto k = to_bytes("\x01\x02\x03");
    const auto v = to_bytes("hello");
    EXPECT_EQ(hex(Trie::build_leaf_node(k, v)), "cb84200102038568656c6c6f");
    trie.insert(k, v);
    EXPECT_EQ(hex(trie.get_root_hash()),
        "5fbc6aa40edcd095c560e3f55917899a939bf24a2ab47021d2736c7b885d9ddf");
    EXPECT_EQ(hex(trie.get_root_hash()),
        "82c8fd36022fbc91bd6b51580cfd941d3d9994017d59ab2e8293ae9c94c3ab6e");
}

TEST(state, trie_branch_node)
{
    Trie trie;
    const auto k1 = to_bytes("A");
    const auto k2 = to_bytes("z");
    const auto v1 = to_bytes("v___________________________1");
    const auto v2 = to_bytes("v___________________________2");

    const auto n1 = uint8_t(k1[0] >> 4);
    const auto n2 = uint8_t(k2[0] >> 4);
    EXPECT_EQ(n1, 4);
    EXPECT_EQ(n2, 7);

    auto hp1 = k1;
    hp1[0] = 0x30 | (hp1[0] & 0x0f);
    EXPECT_EQ(hex(hp1), "31");
    auto hp2 = k2;
    hp2[0] = 0x30 | (hp2[0] & 0x0f);

    const auto node1 = rlp::list(hp1, v1);
    EXPECT_EQ(hex(node1), "df319d765f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31");
    const auto node2 = rlp::list(hp2, v2);


    BranchNode branch;
    branch.insert(n1, keccak256(node1));
    branch.insert(n2, keccak256(node2));
    EXPECT_EQ(hex(branch.rlp()),
        "f85180808080a05806d69cca87e01a0e7567781f037a6e86cdc72dff63366b000d7e00eedd36478080a0ddcda2"
        "25116d4479645995715b72cc33ab2ac7229345297556354ff6baa5a7e5808080808080808080");
    EXPECT_EQ(
        hex(branch.hash()), "56e911635579e0f86dce3c116af12b30448e01cc634aac127e037efbd29e7f9f");


    // trie.insert(to_bytes("A"), v1);
    // trie.insert(to_bytes("B"), v2);
    // EXPECT_EQ(hex(trie.get_root_hash()),
    //     "54d77fcd6e44eacae56a57fdf41c55c2029f232d0f1fccaded720c5abfcb6354");
}

TEST(state, trie_extension_node)
{
    Trie trie;
    const auto k1 = to_bytes("XXA");
    const auto k2 = to_bytes("XXZ");
    const auto v1 = to_bytes("v___________________________1");
    const auto v2 = to_bytes("v___________________________2");

    const auto common_prefix = k1.substr(0, 2);
    EXPECT_EQ(common_prefix, k2.substr(0, 2));
    const auto n1 = uint8_t(k1[2] >> 4);
    const auto n2 = uint8_t(k2[2] >> 4);
    EXPECT_EQ(n1, 4);
    EXPECT_EQ(n2, 5);

    const auto hp1 = bytes{uint8_t(0x30 | (k1[2] & 0x0f))};
    EXPECT_EQ(hex(hp1), "31");
    const auto hp2 = bytes{uint8_t(0x30 | (k2[2] & 0x0f))};

    const auto node1 = rlp::list(hp1, v1);
    EXPECT_EQ(hex(node1), "df319d765f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31");
    const auto node2 = rlp::list(hp2, v2);


    BranchNode branch;
    branch.insert(n1, keccak256(node1));
    branch.insert(n2, keccak256(node2));
    EXPECT_EQ(hex(branch.rlp()),
        "f85180808080a05806d69cca87e01a0e7567781f037a6e86cdc72dff63366b000d7e00eedd3647a0ddcda22511"
        "6d4479645995715b72cc33ab2ac7229345297556354ff6baa5a7e58080808080808080808080");
    EXPECT_EQ(
        hex(branch.hash()), "1aaa6f712413b9a115730852323deb5f5d796c29151a60a1f55f41a25354cd26");

    const auto hp_prefix = bytes{0x00} + common_prefix;
    const auto ext = rlp::list(hp_prefix, branch.hash());
    EXPECT_EQ(
        hex(keccak256(ext)), "3eefc183db443d44810b7d925684eb07256e691d5c9cb13215660107121454f9");


    // trie.insert(to_bytes("A"), v1);
    // trie.insert(to_bytes("B"), v2);
    // EXPECT_EQ(hex(trie.get_root_hash()),
    //     "54d77fcd6e44eacae56a57fdf41c55c2029f232d0f1fccaded720c5abfcb6354");
}


TEST(state, trie_extension_node2)
{
    Trie trie;
    const auto k1 = to_bytes("XXA");
    const auto k2 = to_bytes("XYZ");
    const auto v1 = to_bytes("v___________________________1");
    const auto v2 = to_bytes("v___________________________2");

    const auto n1 = uint8_t(k1[1] & 0x0f);
    const auto n2 = uint8_t(k2[1] & 0x0f);
    EXPECT_EQ(n1, 8);
    EXPECT_EQ(n2, 9);

    const auto hp1 = bytes{0x20} + k1.substr(2);
    EXPECT_EQ(hex(hp1), "2041");
    const auto hp2 = bytes{0x20} + k2.substr(2);

    const auto node1 = rlp::list(hp1, v1);
    EXPECT_EQ(hex(node1), "e18220419d765f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31");
    const auto node2 = rlp::list(hp2, v2);
    EXPECT_EQ(hex(node2), "e182205a9d765f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32");

    BranchNode branch;
    branch.insert(n1, keccak256(node1));
    branch.insert(n2, keccak256(node2));
    EXPECT_EQ(hex(branch.rlp()),
        "f8518080808080808080a030afaabf307606fe3b9afa75de1e2b3ff5a735ec7c4d78c48dfefbcb88b4553da075"
        "a7752e1452fb347efd915ff49f693793d396f9b205fb989f7f2a927da7baf780808080808080");
    EXPECT_EQ(
        hex(branch.hash()), "01746f8ab5a4cc5d6175cbd9ea9603357634ec06b2059f90710243f098e0ee82");

    const auto hp_prefix =
        bytes{uint8_t(0x10 | (k1[0] >> 4)), uint8_t((k1[0] << 4) | (k1[1] >> 4))};
    const auto ext = rlp::list(hp_prefix, branch.hash());
    EXPECT_EQ(
        hex(keccak256(ext)), "ac28c08fa3ff1d0d2cc9a6423abb7af3f4dcc37aa2210727e7d3009a9b4a34e8");


    // trie.insert(to_bytes("A"), v1);
    // trie.insert(to_bytes("B"), v2);
    // EXPECT_EQ(hex(trie.get_root_hash()),
    //     "54d77fcd6e44eacae56a57fdf41c55c2029f232d0f1fccaded720c5abfcb6354");
}
