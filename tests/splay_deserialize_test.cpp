// Standalone unit test for the splay-tree insertion pattern used by
// cctlib.cpp's CCT deserialization path (DeserializeCCTNode).
//
// The deserialize logic in question:
//
//   newNode = new Splay{key, value};
//   if (root == NULL) {
//       root = newNode;
//       newNode->left = NULL;
//       newNode->right = NULL;
//   } else {
//       found = splay(root, key);
//       // BUG: baseline is missing `root = newNode;` here.
//       if (key < found->key) {
//           newNode->left  = found->left;
//           newNode->right = found;
//           found->left    = NULL;
//       } else {
//           newNode->left  = found;
//           newNode->right = found->right;
//           found->right   = NULL;
//       }
//   }
//
// The reference implementation for live-instrumentation insertion (same file,
// InstrumentTraceEntry) always sets `root = newNode;` before the branch. This
// unit test proves the deserialize code is INCORRECT without that line by
// running both variants against the same sequence of inserts and comparing
// tree well-formedness:
//   - well-formed: every inserted key is discoverable via `splay(root, key)`.
//   - malformed:   at least one inserted key is unreachable from `root`, i.e.
//                  the outer pointer no longer references the tree we grew.
//
// Compile-time flag SPLAY_FIX selects the fixed variant. The main() below
// runs BOTH and asserts the expected diagnosis (buggy fails, fixed passes).

#include "splay-macros.h"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <set>
#include <vector>

struct TraceSplay {
    uintptr_t key;
    int value; // scalar so we can spot the leak
    TraceSplay* left;
    TraceSplay* right;
};

static TraceSplay* splay(TraceSplay* root, uintptr_t key) {
    REGULAR_SPLAY_TREE(TraceSplay, root, key, key, left, right);
    return root;
}

// Insert `key` into the splay tree rooted at *rootp. `apply_fix` controls
// whether we install newNode as the new root before the branch split.
// NOLINTBEGIN(clang-analyzer-cplusplus.NewDeleteLeaks) -- when apply_fix
// is false the buggy path intentionally leaks newNode; that IS the bug
// this test demonstrates and cleans up on program exit.
static void insert(TraceSplay** rootp, uintptr_t key, int value, bool apply_fix) {
    TraceSplay* newNode = new TraceSplay{key, value, nullptr, nullptr};
    if (*rootp == nullptr) {
        *rootp = newNode;
        return;
    }
    TraceSplay* found = splay(*rootp, key);
    // *rootp = found;   // the splay left `found` as the root of the reordered tree

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

// Collect all keys reachable from `root` via left/right pointers.
static void collect_keys(TraceSplay* root, std::set<uintptr_t>& out) {
    if (!root)
        return;
    if (!out.insert(root->key).second)
        return; // cycle safety
    collect_keys(root->left, out);
    collect_keys(root->right, out);
}

// Try to find `key` by repeatedly splaying and checking the root's key.
static bool splay_finds(TraceSplay** rootp, uintptr_t key) {
    if (!*rootp)
        return false;
    *rootp = splay(*rootp, key);
    return (*rootp)->key == key;
}

static bool run_scenario(bool apply_fix, const char* label,
                         const std::vector<uintptr_t>& insertion_order) {
    TraceSplay* root = nullptr;
    for (size_t i = 0; i < insertion_order.size(); ++i) {
        insert(&root, insertion_order[i], (int)i, apply_fix);
    }

    // Collect reachable keys and verify each inserted key is discoverable
    // via splay(root, key). Splay is destructive but idempotent for existence.
    std::set<uintptr_t> reachable;
    collect_keys(root, reachable);

    size_t missing_reachable = 0;
    for (uintptr_t k : insertion_order) {
        if (!reachable.count(k))
            ++missing_reachable;
    }

    // Independently, try splay-based lookup (this is how any real caller
    // discovers whether a key is in the tree). Even if all nodes are
    // reachable structurally, splay may fail to land on the intended root
    // when the outer pointer went stale.
    size_t missing_splay = 0;
    for (uintptr_t k : insertion_order) {
        if (!splay_finds(&root, k))
            ++missing_splay;
    }

    fprintf(stderr,
            "[%s] insert=%zu reachable=%zu splay_lookups_failed=%zu missing_reachable=%zu\n",
            label, insertion_order.size(), reachable.size(),
            missing_splay, missing_reachable);
    return missing_reachable == 0 && missing_splay == 0;
}

// NOLINTBEGIN(bugprone-exception-escape) -- unit-test main; std::bad_alloc
// from std::vector allocations escaping here properly terminates the run.
int main() {
    // Sequences chosen so the splay+split path fires often. First insert is
    // always the "root=null" case; each subsequent insert exercises the
    // buggy `else` branch.
    std::vector<uintptr_t> asc = {100, 200, 300, 400, 500, 600, 700, 800};
    std::vector<uintptr_t> desc = {800, 700, 600, 500, 400, 300, 200, 100};
    std::vector<uintptr_t> mix = {500, 100, 900, 300, 700, 200, 800, 400, 600};

    struct Case {
        const char* name;
        const std::vector<uintptr_t>* seq;
    };
    Case cases[] = {
        {"ascending", &asc},
        {"descending", &desc},
        {"mixed", &mix},
    };

    int failures = 0;
    for (const Case& c : cases) {
        fprintf(stderr, "\n== scenario: %s ==\n", c.name);
        (void)run_scenario(/*apply_fix=*/false, "BUGGY", *c.seq);
        bool fixed_ok = run_scenario(/*apply_fix=*/true, "FIXED", *c.seq);

        // The test's diagnostic contract:
        //   FIXED must always pass. If it doesn't, the fix is wrong.
        //   BUGGY must FAIL on at least one of the scenarios. If it doesn't,
        //   the code path we thought was broken is actually fine and the
        //   splay-tree fix is unnecessary.
        if (!fixed_ok) {
            fprintf(stderr, "[FAIL] FIXED scenario '%s' should have passed\n", c.name);
            ++failures;
        }
    }

    // Composite bug demonstration: BUGGY must fail on at least one scenario.
    fprintf(stderr, "\n== composite (BUGGY must fail at least one scenario) ==\n");
    bool any_buggy_failure = false;
    for (const Case& c : cases) {
        if (!run_scenario(/*apply_fix=*/false, c.name, *c.seq)) {
            any_buggy_failure = true;
        }
    }
    if (!any_buggy_failure) {
        fprintf(stderr, "[FAIL] baseline BUGGY variant unexpectedly passed all scenarios\n");
        ++failures;
    } else {
        fprintf(stderr, "[OK ] baseline BUGGY variant does fail as expected\n");
    }

    fprintf(stderr, "\n%d failures\n", failures);
    return failures == 0 ? 0 : 1;
}
// NOLINTEND(bugprone-exception-escape)
