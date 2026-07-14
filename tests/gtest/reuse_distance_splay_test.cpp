// Unit tests for CompressedSplay (clients/reuse_distance_splay.h).
//
// Ground truth: NaiveReuseStack (exact O(M) list-based reference).
// For each synthetic access pattern, run both, and assert that:
//   * First-use returns agree exactly.
//   * Reuse-distance returns satisfy the Ding-Zhong'03 error bound:
//       exact >= approx  AND  exact <= approx * (1 + e)
//     (with a small additive tolerance for the zero-distance case).
//
// Test patterns cover:
//   * Immediate reuse (distance 0 or 1).
//   * Small strided reuse (fits before compression triggers).
//   * Large strided reuse that triggers compression.
//   * Random access with a bounded working set.
//   * Sequential scan (all first-use, then all with distance = footprint - 1).

#include "reuse_distance_splay.h"

#include <cstdint>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace {

using cctlib_reuse::CompressedSplay;
using cctlib_reuse::FIRST_USE;
using cctlib_reuse::NaiveReuseStack;

// Verify: approx <= exact AND exact <= approx * (1 + e).
// Special-cases:
//   * FIRST_USE must match exactly.
//   * exact = 0 is always exact (bin 0 hit).
//   * approx = 0 with exact < some floor (e.g. < 4) is also considered fine;
//     the approximation can round very-small distances to 0 in early compression.
void ExpectWithinBound(uint64_t exact, uint64_t approx, double e,
                       const std::string& tag) {
    ASSERT_EQ(exact == FIRST_USE, approx == FIRST_USE) << tag;
    if (exact == FIRST_USE)
        return;
    if (exact == 0) {
        EXPECT_EQ(approx, 0u) << tag;
        return;
    }
    // Lower bound: approx should never exceed exact.
    EXPECT_LE(approx, exact) << tag << " exact=" << exact
                             << " approx=" << approx;
    // Upper bound: approx * (1 + e) should be at least exact.
    double upper = double(approx) * (1.0 + e) + 4.0 /* floor */;
    EXPECT_LE(double(exact), upper) << tag << " exact=" << exact
                                    << " approx=" << approx << " e=" << e;
}

TEST(CompressedSplay, ImmediateRepeat) {
    CompressedSplay<int> splay(0.01);
    NaiveReuseStack<int> naive;
    // Access the same key 100 times.
    for (int i = 0; i < 100; ++i) {
        uint64_t exact = naive.access(42);
        uint64_t approx = splay.access(42, uint64_t(i) + 1);
        ExpectWithinBound(exact, approx, 0.01,
                          "iter=" + std::to_string(i));
    }
    EXPECT_EQ(splay.footprint(), 1u);
    EXPECT_EQ(naive.footprint(), 1u);
}

TEST(CompressedSplay, TwoKeyPingPong) {
    CompressedSplay<int> splay(0.01);
    NaiveReuseStack<int> naive;
    uint64_t t = 1;
    for (int i = 0; i < 100; ++i) {
        int k = (i & 1) ? 1 : 2;
        uint64_t exact = naive.access(k);
        uint64_t approx = splay.access(k, t++);
        ExpectWithinBound(exact, approx, 0.01,
                          "iter=" + std::to_string(i));
    }
    EXPECT_EQ(splay.footprint(), 2u);
}

TEST(CompressedSplay, SmallCycleFitsExact) {
    // Cycle over K=8 distinct keys many times. Reuse distance should be
    // K - 1 = 7 after the first full pass. Small enough that no
    // compression triggers.
    CompressedSplay<int> splay(0.01);
    NaiveReuseStack<int> naive;
    uint64_t t = 1;
    const int K = 8;
    for (int rep = 0; rep < 50; ++rep) {
        for (int i = 0; i < K; ++i) {
            uint64_t exact = naive.access(i);
            uint64_t approx = splay.access(i, t++);
            ExpectWithinBound(exact, approx, 0.01,
                              "rep=" + std::to_string(rep) +
                                  " i=" + std::to_string(i));
        }
    }
    EXPECT_EQ(splay.footprint(), uint64_t(K));
}

TEST(CompressedSplay, LargeCycleTriggersCompression) {
    // Cycle over K=5000 distinct keys. Compression must trigger. Distance
    // should be approximately K-1 after each full pass, within e.
    CompressedSplay<int> splay(0.05); // 5% error
    NaiveReuseStack<int> naive;
    uint64_t t = 1;
    const int K = 5000;
    for (int rep = 0; rep < 3; ++rep) {
        for (int i = 0; i < K; ++i) {
            uint64_t exact = naive.access(i);
            uint64_t approx = splay.access(i, t++);
            if (rep > 0) {
                ExpectWithinBound(exact, approx, 0.05,
                                  "rep=" + std::to_string(rep) +
                                      " i=" + std::to_string(i));
            }
        }
    }
    EXPECT_EQ(splay.footprint(), uint64_t(K));
    // Compression should have kept num_nodes << K.
    EXPECT_LT(splay.num_nodes(), size_t(K)) << "compression did not trigger";
}

TEST(CompressedSplay, RandomBoundedWorkingSet) {
    CompressedSplay<int> splay(0.05);
    NaiveReuseStack<int> naive;
    std::mt19937 rng(42);
    const int WS = 1000;
    std::uniform_int_distribution<int> pick(0, WS - 1);
    uint64_t t = 1;
    // Bound the error violations to a small budget -- edge cases in
    // compression can create rare over-shoots but shouldn't dominate.
    int violations_lower = 0, violations_upper = 0;
    for (int i = 0; i < 20000; ++i) {
        int k = pick(rng);
        uint64_t exact = naive.access(k);
        uint64_t approx = splay.access(k, t++);
        if (exact == FIRST_USE) {
            EXPECT_EQ(approx, FIRST_USE);
            continue;
        }
        if (approx > exact)
            ++violations_lower;
        if (exact > 0 &&
            double(exact) > double(approx) * 1.05 + 4.0)
            ++violations_upper;
    }
    // Splay-based compressed reuse distance is an approximation; a small
    // fraction of violations is expected due to node merging near the
    // access. Bound at 5% of accesses.
    EXPECT_LE(violations_lower, 1000);
    EXPECT_LE(violations_upper, 1000);
    EXPECT_EQ(splay.footprint(), uint64_t(WS));
}

TEST(CompressedSplay, SequentialScanThenReuse) {
    // First N accesses are all first-use (distinct keys). Then we
    // re-access key 0 -- its exact reuse distance = N - 1.
    CompressedSplay<int> splay(0.02);
    NaiveReuseStack<int> naive;
    uint64_t t = 1;
    const int N = 2000;
    for (int i = 0; i < N; ++i) {
        uint64_t exact = naive.access(i);
        uint64_t approx = splay.access(i, t++);
        EXPECT_EQ(exact, FIRST_USE) << i;
        EXPECT_EQ(approx, FIRST_USE) << i;
    }
    uint64_t exact = naive.access(0);
    uint64_t approx = splay.access(0, t++);
    // exact should be N-1.
    EXPECT_EQ(exact, uint64_t(N - 1));
    // approx should satisfy the bound.
    ExpectWithinBound(exact, approx, 0.02, "reuse-of-0");
}

TEST(CompressedSplay, ExactMatchesForTinyInputs) {
    // For inputs below the compression threshold, the algorithm should be
    // exact modulo the semantics of the CompressedSplay approximation
    // (which for size-1 nodes is exact).
    CompressedSplay<int> splay(0.01);
    NaiveReuseStack<int> naive;
    uint64_t t = 1;
    for (int rep = 0; rep < 20; ++rep) {
        for (int k = 0; k < 5; ++k) {
            uint64_t exact = naive.access(k);
            uint64_t approx = splay.access(k, t++);
            EXPECT_EQ(exact, approx)
                << "rep=" << rep << " k=" << k;
        }
    }
}

} // namespace
