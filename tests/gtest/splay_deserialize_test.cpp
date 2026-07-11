// GoogleTest unit test proving the CCT-deserialize splay-tree insertion bug.
//
// Migrated from tests/splay_deserialize_test.cpp. The insert() helper runs
// the deserialize logic in two modes: baseline (buggy -- missing the
// `*rootp = newNode;` line) and fixed. The test asserts:
//   FIXED: every inserted key is reachable from root; every splay lookup
//   for that key succeeds.
//   BUGGY: at least one inserted key is unreachable / lookup-fails on some
//   scenario. If BUGGY ever passes cleanly the fix would be unnecessary,
//   and this test forces us to notice.

#include <cstdint>
#include <set>
#include <vector>

#include <gtest/gtest.h>

#include "splay-macros.h"

namespace {

struct TraceSplay {
    uintptr_t key;
    int value;
    TraceSplay* left;
    TraceSplay* right;
};

TraceSplay* splay(TraceSplay* root, uintptr_t key) {
    REGULAR_SPLAY_TREE(TraceSplay, root, key, key, left, right);
    return root;
}

// NOLINTBEGIN(clang-analyzer-cplusplus.NewDeleteLeaks) -- when apply_fix is
// false the buggy path intentionally leaks newNode.
void insert(TraceSplay** rootp, uintptr_t key, int value, bool apply_fix) {
    auto* newNode = new TraceSplay{key, value, nullptr, nullptr};
    if (*rootp == nullptr) {
        *rootp = newNode;
        return;
    }
    TraceSplay* found = splay(*rootp, key);
    if (apply_fix) {
        *rootp = newNode;
    }
    if (key < found->key) {
        newNode->left = found->left;
        newNode->right = found;
        found->left = nullptr;
    } else {
        newNode->left = found;
        newNode->right = found->right;
        found->right = nullptr;
    }
}
// NOLINTEND(clang-analyzer-cplusplus.NewDeleteLeaks)

void collect_keys(TraceSplay* root, std::set<uintptr_t>& out) {
    if (!root) return;
    if (!out.insert(root->key).second) return;
    collect_keys(root->left, out);
    collect_keys(root->right, out);
}

bool splay_finds(TraceSplay** rootp, uintptr_t key) {
    if (!*rootp) return false;
    *rootp = splay(*rootp, key);
    return (*rootp)->key == key;
}

struct Diagnosis {
    size_t missing_reachable = 0;
    size_t missing_splay = 0;
};

Diagnosis run(bool apply_fix, const std::vector<uintptr_t>& seq) {
    TraceSplay* root = nullptr;
    for (size_t i = 0; i < seq.size(); ++i) {
        insert(&root, seq[i], (int)i, apply_fix);
    }
    std::set<uintptr_t> reachable;
    collect_keys(root, reachable);
    Diagnosis d;
    for (uintptr_t k : seq) {
        if (!reachable.count(k)) ++d.missing_reachable;
    }
    for (uintptr_t k : seq) {
        if (!splay_finds(&root, k)) ++d.missing_splay;
    }
    return d;
}

class SplayDeserialize : public ::testing::TestWithParam<std::vector<uintptr_t>> {};

TEST_P(SplayDeserialize, FixedIsWellFormed) {
    Diagnosis d = run(/*apply_fix=*/true, GetParam());
    EXPECT_EQ(0u, d.missing_reachable) << "keys missing from tree";
    EXPECT_EQ(0u, d.missing_splay) << "splay lookups failed";
}

TEST_P(SplayDeserialize, BuggyLosesKeys) {
    Diagnosis d = run(/*apply_fix=*/false, GetParam());
    EXPECT_GT(d.missing_reachable + d.missing_splay, 0u)
        << "buggy variant unexpectedly did not lose any keys -- fix may be "
           "unnecessary or the test scenario is too weak";
}

INSTANTIATE_TEST_SUITE_P(
    Scenarios, SplayDeserialize,
    ::testing::Values(
        std::vector<uintptr_t>{100, 200, 300, 400, 500, 600, 700, 800},   // ascending
        std::vector<uintptr_t>{800, 700, 600, 500, 400, 300, 200, 100},   // descending
        std::vector<uintptr_t>{500, 100, 900, 300, 700, 200, 800, 400, 600}  // mixed
    ));

}  // namespace
