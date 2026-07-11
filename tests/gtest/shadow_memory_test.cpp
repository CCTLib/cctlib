// GoogleTest unit tests for src/shadow_memory.H.
//
// Migrated from the ad-hoc tests/shadow_memory_unittest.cpp (still kept as a
// fallback binary for build environments without gtest). Same coverage: the
// free-function GetOrCreateShadowAddress<I> and the base
// GetOrCreateShadowBaseAddress path, single- and multi-threaded, both
// ShadowMemory and ConcurrentShadowMemory. See the header comment on the
// legacy file for background on the `auto` vs `auto&` bug.

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "shadow_memory.H"

namespace {

TEST(ShadowMemory, WriteReadSingle) {
    ShadowMemory<uint64_t> sm;
    const size_t addr = 0x1234'5678'9abc'0000ULL;
    const uint64_t value = 0xdeadbeefcafef00dULL;

    *GetOrCreateShadowAddress<0>(sm, addr) = value;
    EXPECT_EQ(value, *GetOrCreateShadowAddress<0>(sm, addr));
}

TEST(ShadowMemory, MultipleAddressesSamePage) {
    ShadowMemory<uint64_t> sm;
    const size_t base = 0x1000'0000ULL;
    for (int i = 0; i < 4096; ++i) {
        *GetOrCreateShadowAddress<0>(sm, base + i * 8) = uint64_t{static_cast<uint64_t>(i)} * 7 + 3;
    }
    for (int i = 0; i < 4096; ++i) {
        EXPECT_EQ(uint64_t{static_cast<uint64_t>(i)} * 7 + 3,
                  *GetOrCreateShadowAddress<0>(sm, base + i * 8))
            << "at i=" << i;
    }
}

TEST(ShadowMemory, MultiplePages) {
    ShadowMemory<uint64_t> sm;
    const size_t addrs[] = {
        0x0000'0000ULL,
        0x0001'0000ULL,          // next l2 slot
        0x0000'1000'0000ULL,     // next l1 slot
        0x1234'5678'0000ULL,
        0x7fff'ffff'0000ULL,     // near top of 47-bit user space
    };
    const int n = sizeof(addrs) / sizeof(addrs[0]);
    for (int i = 0; i < n; ++i) {
        *GetOrCreateShadowAddress<0>(sm, addrs[i]) = 0xa5a5a5a5'00000000ULL | i;
    }
    for (int i = 0; i < n; ++i) {
        EXPECT_EQ(0xa5a5a5a5'00000000ULL | i, *GetOrCreateShadowAddress<0>(sm, addrs[i]));
    }
}

TEST(ShadowMemory, MultiTypeTuple) {
    ShadowMemory<uint8_t, uint32_t> sm;
    const size_t addr = 0xcafeb0ba'0000ULL;
    *GetOrCreateShadowAddress<0>(sm, addr) = 0x5a;
    *GetOrCreateShadowAddress<1>(sm, addr) = 0xdeadbeef;
    EXPECT_EQ(0x5a, *GetOrCreateShadowAddress<0>(sm, addr));
    EXPECT_EQ(0xdeadbeefu, *GetOrCreateShadowAddress<1>(sm, addr));
}

// Regression for the auto-copy bug: writing via the free function must be
// visible via the direct base function, and vice versa.
TEST(ShadowMemory, FreeFnMatchesBaseFn) {
    ShadowMemory<uint64_t> sm;
    const size_t addr = 0x0f0f'0000'1234ULL;
    const uint64_t value = 0x1122334455667788ULL;

    *GetOrCreateShadowAddress<0>(sm, addr) = value;
    auto& page = sm.GetOrCreateShadowBaseAddress(addr);
    EXPECT_EQ(value, std::get<0>(page)[PAGE_OFFSET(addr)]);
}

TEST(ShadowMemory, BaseFnMatchesFreeFn) {
    ShadowMemory<uint64_t> sm;
    const size_t addr = 0x0e0e'ffff'5678ULL;
    const uint64_t value = 0x8899aabbccddeeffULL;

    auto& page = sm.GetOrCreateShadowBaseAddress(addr);
    std::get<0>(page)[PAGE_OFFSET(addr)] = value;
    EXPECT_EQ(value, *GetOrCreateShadowAddress<0>(sm, addr));
}

TEST(ShadowMemory, PointerStable) {
    ShadowMemory<uint64_t> sm;
    const size_t addr = 0x2222'3333'4444ULL;
    uint64_t* p1 = GetOrCreateShadowAddress<0>(sm, addr);
    uint64_t* p2 = GetOrCreateShadowAddress<0>(sm, addr);
    EXPECT_EQ(p1, p2);
}

TEST(ShadowMemory, InitPatternDataCentricShape) {
    ShadowMemory<uint64_t> sm;
    const size_t base = 0x8000'0000ULL;
    for (int i = 0; i < 256; ++i) {
        *GetOrCreateShadowAddress<0>(sm, base + i * 8) = 0xf00d0000ULL + i;
    }
    for (int i = 0; i < 256; ++i) {
        EXPECT_EQ(0xf00d0000ULL + i, *GetOrCreateShadowAddress<0>(sm, base + i * 8));
    }
}

TEST(ConcurrentShadowMemory, WriteReadSingle) {
    ConcurrentShadowMemory<uint64_t> sm;
    const size_t addr = 0x1234'5678'9abc'0000ULL;
    const uint64_t value = 0xdeadbeefcafef00dULL;
    *GetOrCreateShadowAddress<0>(sm, addr) = value;
    EXPECT_EQ(value, *GetOrCreateShadowAddress<0>(sm, addr));
}

TEST(ConcurrentShadowMemory, FreeFnMatchesBaseFn) {
    ConcurrentShadowMemory<uint64_t> sm;
    const size_t addr = 0x0f0f'0000'1234ULL;
    const uint64_t value = 0x1122334455667788ULL;
    *GetOrCreateShadowAddress<0>(sm, addr) = value;
    auto& page = sm.GetOrCreateShadowBaseAddress(addr);
    EXPECT_EQ(value, std::get<0>(page)[PAGE_OFFSET(addr)]);
}

TEST(ConcurrentShadowMemory, MultiTypeTuple) {
    ConcurrentShadowMemory<uint8_t, uint32_t> sm;
    const size_t addr = 0xcafeb0ba'0000ULL;
    *GetOrCreateShadowAddress<0>(sm, addr) = 0x5a;
    *GetOrCreateShadowAddress<1>(sm, addr) = 0xdeadbeef;
    EXPECT_EQ(0x5a, *GetOrCreateShadowAddress<0>(sm, addr));
    EXPECT_EQ(0xdeadbeefu, *GetOrCreateShadowAddress<1>(sm, addr));
}

// N threads share the same L1 page-table slot (via stride within a single L1
// bucket) and race on L1 sub-page allocation. The free()->munmap() fix in
// ConcurrentShadowMemory keeps this from occasionally segfaulting under -O2.
TEST(ConcurrentShadowMemory, MultiThreadStress) {
    ConcurrentShadowMemory<uint64_t> sm;
    const int nthreads = 8;
    const int per_thread = 1024;
    const size_t stride = 0x100'0000ULL;

    auto writer = [&](int tid) {
        for (int i = 0; i < per_thread; ++i) {
            size_t addr = (size_t)tid * stride + (size_t)i * 8;
            *GetOrCreateShadowAddress<0>(sm, addr) = (uint64_t)tid * 1000000ULL + i;
        }
    };
    std::vector<std::thread> ts;
    ts.reserve(nthreads);
    for (int t = 0; t < nthreads; ++t) ts.emplace_back(writer, t);
    for (auto& th : ts) th.join();

    std::atomic<int> mismatches{0};
    auto reader = [&](int tid) {
        for (int i = 0; i < per_thread; ++i) {
            size_t addr = (size_t)tid * stride + (size_t)i * 8;
            if (*GetOrCreateShadowAddress<0>(sm, addr) != (uint64_t)tid * 1000000ULL + i) {
                mismatches.fetch_add(1);
            }
        }
    };
    ts.clear();
    for (int t = 0; t < nthreads; ++t) ts.emplace_back(reader, t);
    for (auto& th : ts) th.join();

    EXPECT_EQ(0, mismatches.load());
}

// Mirrors the exact layout cctlib.cpp's USE_SHADOW_FOR_DATA_CENTRIC path uses.
TEST(ConcurrentShadowMemory, DataHandleShape) {
    struct FakeHandle { uint8_t type; uint32_t path; };
    ConcurrentShadowMemory<FakeHandle> sm;
    const size_t base = 0x7ff0'0000'0000ULL;
    const int n = 128;
    for (int i = 0; i < n; ++i) {
        FakeHandle* slot = GetOrCreateShadowAddress<0>(sm, base + i);
        slot->type = 2;
        slot->path = 0xabc00000u + (uint32_t)i;
    }
    for (int i = 0; i < n; ++i) {
        FakeHandle h = *GetOrCreateShadowAddress<0>(sm, base + i);
        EXPECT_EQ(2, (int)h.type);
        EXPECT_EQ(0xabc00000u + (uint32_t)i, h.path);
    }
}

}  // namespace
