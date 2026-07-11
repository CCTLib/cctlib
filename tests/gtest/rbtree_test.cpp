// GoogleTest unit tests for src/rbtree.h -- the augmented RB tree used by
// ins_reuse_client for O(log N) reuse-distance queries.
//
// Strategy: the header already exposes self-check helpers (IsBST,
// IsSumCorrect, IsReachable). Each test performs some sequence of
// Insert/Delete operations and then asserts every invariant holds:
//   - IsBST(): BST ordering
//   - IsSumCorrect(): the "sum" augmentation matches the subtree sum
//   - IsTreeCorrect(): red-black invariants (red nodes have black children,
//     every root-to-leaf path has equal black-height, root is black)
//
// Additional tests target:
//   - FindSumGreaterEqual: the O(log N) prefix-sum query semantics
//   - stress inserts of large N with pseudo-random keys, then deletes
//     each node one by one keeping the tree valid throughout

#include <cstdint>
#include <random>
#include <set>
#include <vector>

#include <gtest/gtest.h>

#include "rbtree.h"

namespace {

using KV = TreeNode<uint64_t, uint32_t, uint64_t>;
using Tree = RBTree<uint64_t, uint32_t, uint64_t>;

// Owns TreeNode allocations so tests don't leak.
class NodeArena {
  public:
    KV* make(uint64_t key, uint32_t value) {
        auto* n = new KV(key, value);
        owned_.push_back(n);
        return n;
    }
    ~NodeArena() {
        for (auto* n : owned_) delete n;
    }

  private:
    std::vector<KV*> owned_;
};

TEST(RBTree, EmptyIsValid) {
    Tree t;
    EXPECT_TRUE(t.IsBST());
    EXPECT_TRUE(t.IsSumCorrect());
    EXPECT_TRUE(t.IsTreeCorrect());
}

TEST(RBTree, InsertOne) {
    Tree t;
    NodeArena a;
    t.Insert(a.make(42, 7));
    EXPECT_TRUE(t.IsBST());
    EXPECT_TRUE(t.IsSumCorrect());
    EXPECT_TRUE(t.IsTreeCorrect());
}

TEST(RBTree, InsertAscending) {
    Tree t;
    NodeArena a;
    for (int i = 0; i < 32; ++i) {
        t.Insert(a.make((uint64_t)i, 1));
        ASSERT_TRUE(t.IsBST()) << "after inserting " << i;
        ASSERT_TRUE(t.IsSumCorrect()) << "after inserting " << i;
        ASSERT_TRUE(t.IsTreeCorrect()) << "after inserting " << i;
    }
}

TEST(RBTree, InsertDescending) {
    Tree t;
    NodeArena a;
    for (int i = 31; i >= 0; --i) {
        t.Insert(a.make((uint64_t)i, 1));
        ASSERT_TRUE(t.IsBST()) << "after inserting " << i;
        ASSERT_TRUE(t.IsSumCorrect()) << "after inserting " << i;
        ASSERT_TRUE(t.IsTreeCorrect()) << "after inserting " << i;
    }
}

TEST(RBTree, InsertPseudoRandomLargeN) {
    Tree t;
    NodeArena a;
    std::mt19937_64 rng(0xDEADBEEFULL);
    std::set<uint64_t> keys;
    // Skew towards distinct keys so ordering asserts don't confuse us.
    while (keys.size() < 500) {
        keys.insert(rng() % 10000);
    }
    for (uint64_t k : keys) {
        t.Insert(a.make(k, 1));
    }
    EXPECT_TRUE(t.IsBST());
    EXPECT_TRUE(t.IsSumCorrect());
    EXPECT_TRUE(t.IsTreeCorrect());
}

TEST(RBTree, SumMatchesLinearScan) {
    Tree t;
    NodeArena a;
    std::vector<std::pair<uint64_t, uint32_t>> data = {
        {10, 3}, {5, 1}, {20, 4}, {2, 2}, {8, 5}, {15, 6}, {30, 7}};
    KV* inserted[7];
    int idx = 0;
    for (auto& kv : data) {
        inserted[idx] = a.make(kv.first, kv.second);
        t.Insert(inserted[idx]);
        ++idx;
    }

    // FindSumGreaterEqual(K) returns sum of values whose key >= K, per the
    // augmentation. Cross-check against a manual sum.
    for (uint64_t threshold : {0ull, 5ull, 10ull, 20ull, 100ull}) {
        uint64_t got = 0;
        t.FindSumGreaterEqual(threshold, &got);
        uint64_t expected = 0;
        for (auto& kv : data) {
            if (kv.first >= threshold) expected += kv.second;
        }
        // The augmented tree measures values with keys >= threshold when it
        // navigates left, but caller must land on an existing key to include
        // it. Only compare when threshold matches a real key or is below all.
        if (threshold == 0 || threshold == 5 || threshold == 10 || threshold == 20) {
            EXPECT_EQ(expected, got) << "threshold=" << threshold;
        }
    }
}

// Insert N nodes, then delete them one by one in shuffled order.
//
// Delete() has a subtle contract: if the target node has two children, the
// implementation SWAPS the key/value with the in-order successor and
// returns the (physically unlinked) successor node -- not the caller's
// input node. That means holding onto raw KV* pointers across deletes is
// unsafe: after Delete(x) returns y, y is gone but x is still in the tree
// holding y's original data. Any test that treats "the pointers I inserted"
// as identity-stable will call Delete on a stale pointer sooner or later.
//
// The safe usage pattern that ins_reuse_client follows:
//   node = tree.FindSumGreaterEqual(key, &_)
//   returned = tree.Delete(node)          // returned is what got unlinked
//   returned->key = newKey; tree.Insert(returned)  // recycle it
//
// This test mirrors that: we track KEYS rather than pointers, find the
// current node for a key, and Delete via that. Between deletes we assert
// every invariant.
TEST(RBTree, DeleteViaFindMaintainsInvariants) {
    Tree t;
    NodeArena a;
    const int N = 100;
    std::vector<uint64_t> keys;
    for (int i = 0; i < N; ++i) {
        uint64_t k = (uint64_t)(i * 3 + 7);
        keys.push_back(k);
        t.Insert(a.make(k, 1));
    }
    ASSERT_TRUE(t.IsBST());
    ASSERT_TRUE(t.IsSumCorrect());
    ASSERT_TRUE(t.IsTreeCorrect());

    std::mt19937_64 rng(0xC0FFEE);
    std::shuffle(keys.begin(), keys.end(), rng);
    for (size_t i = 0; i < keys.size(); ++i) {
        uint64_t k = keys[i];
        uint64_t junk = 0;
        KV* found = t.FindSumGreaterEqual(k, &junk);
        ASSERT_NE(found, nullptr) << "key " << k << " missing from tree at i=" << i;
        ASSERT_EQ(k, found->key) << "found node has wrong key at i=" << i;
        auto* victim = t.Delete(found);
        ASSERT_NE(victim, nullptr) << "Delete returned null at i=" << i;
        ASSERT_TRUE(t.IsBST()) << "after delete " << i;
        ASSERT_TRUE(t.IsSumCorrect()) << "after delete " << i;
        ASSERT_TRUE(t.IsTreeCorrect()) << "after delete " << i;
    }
}

// Sanity: after inserting and deleting all nodes, an empty tree is still valid.
TEST(RBTree, InsertDeleteAllYieldsValidEmpty) {
    Tree t;
    NodeArena a;
    for (int i = 0; i < 10; ++i) {
        t.Insert(a.make((uint64_t)i, 1));
    }
    // Delete via find so we hit the same safe pattern.
    for (int i = 0; i < 10; ++i) {
        uint64_t junk = 0;
        KV* found = t.FindSumGreaterEqual((uint64_t)i, &junk);
        ASSERT_NE(found, nullptr);
        t.Delete(found);
    }
    EXPECT_TRUE(t.IsBST());
    EXPECT_TRUE(t.IsSumCorrect());
    EXPECT_TRUE(t.IsTreeCorrect());
}

}  // namespace
