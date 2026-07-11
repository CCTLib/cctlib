// Standalone unit tests for src/shadow_memory.H. Not a Pin tool -- built and
// run directly by `make check`.
//
// The header is a two-level page table that hands out shadow pages of
// SHADOW_PAGE_SIZE (65536) entries per type in a parameter pack. Two variants
// exist: ShadowMemory (single-threaded, raw pointers) and ConcurrentShadowMemory
// (atomics + CAS). Both expose GetOrCreateShadowBaseAddress(addr) returning a
// reference to the tuple that owns the shadow page.
//
// A free function template GetOrCreateShadowAddress<I>(sm, addr) sits on top
// and hands back a typed pointer to the single shadow slot for `addr`. This
// unittest primarily targets that free function, because its historical form
// used `auto shadowPage = sm.GetOrCreateShadowBaseAddress(address);` -- `auto`
// on a reference-returning call strips the reference and value-copies the tuple
// (a T[65536] per pack element) into the caller's stack, then returns a pointer
// into the copy. Writes through that pointer never reach real shadow memory,
// and subsequent reads observe zero-initialized copies.
//
// Each test writes through the free function and reads back both via the free
// function and via the ground-truth path (GetOrCreateShadowBaseAddress + get<>)
// so a divergence between the two immediately fingerprints the bug.

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include <atomic>

// The Pin build path brings <stdio.h> in transitively before shadow_memory.H;
// when compiling standalone we need `perror` visible for the header's ADL-free
// calls, so include stdio (already done above) before pulling the header in.
#include "shadow_memory.H"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK_EQ(actual, expected, msg) do {                                  \
    ++g_checks;                                                               \
    auto _a = (actual);                                                       \
    auto _e = (expected);                                                     \
    if (_a != _e) {                                                           \
        ++g_failures;                                                         \
        fprintf(stderr, "  FAIL %s:%d %s: got %lld expected %lld\n",          \
                __FILE__, __LINE__, msg,                                      \
                (long long)_a, (long long)_e);                                \
    }                                                                         \
} while (0)

#define RUN_TEST(fn) do {                                                     \
    int before = g_failures;                                                  \
    fprintf(stderr, "[RUN ] %s\n", #fn);                                      \
    fn();                                                                     \
    fprintf(stderr, "[%s] %s\n",                                              \
            (g_failures == before) ? "PASS" : "FAIL", #fn);                   \
} while (0)


// ---------------------------------------------------------------------------
// Tests for ShadowMemory (single-threaded)
// ---------------------------------------------------------------------------

// A single write followed by a read of the SAME address must return the
// written value. This is the minimum contract of the API and the smoking gun
// for the auto-copy bug.
static void test_shadow_write_read_single() {
    ShadowMemory<uint64_t> sm;
    const size_t addr = 0x1234'5678'9abc'0000ULL;
    const uint64_t value = 0xdeadbeefcafef00dULL;

    *GetOrCreateShadowAddress<0>(sm, addr) = value;
    uint64_t readback = *GetOrCreateShadowAddress<0>(sm, addr);
    CHECK_EQ(readback, value, "single write/read");
}

// Distinct addresses inside the SAME shadow page must not collide, and reads
// must see the last write to each address.
static void test_shadow_multiple_addresses_same_page() {
    ShadowMemory<uint64_t> sm;
    const size_t base = 0x1000'0000ULL;
    for (int i = 0; i < 4096; ++i) {
        *GetOrCreateShadowAddress<0>(sm, base + i * 8) = uint64_t{static_cast<uint64_t>(i)} * 7 + 3;
    }
    for (int i = 0; i < 4096; ++i) {
        uint64_t v = *GetOrCreateShadowAddress<0>(sm, base + i * 8);
        CHECK_EQ(v, uint64_t{static_cast<uint64_t>(i)} * 7 + 3, "same-page slot");
    }
}

// Distinct pages (l1/l2 slots differ) must not alias. This exercises page
// creation on both levels.
static void test_shadow_multiple_pages() {
    ShadowMemory<uint64_t> sm;
    const size_t addrs[] = {
        0x0000'0000ULL,
        0x0001'0000ULL,               // next l2 slot
        0x0000'1000'0000ULL,          // next l1 slot
        0x1234'5678'0000ULL,          // arbitrary
        0x7fff'ffff'0000ULL,          // near top of a 47-bit user space
    };
    const int n = sizeof(addrs) / sizeof(addrs[0]);
    for (int i = 0; i < n; ++i) {
        *GetOrCreateShadowAddress<0>(sm, addrs[i]) = 0xa5a5a5a5'00000000ULL | i;
    }
    for (int i = 0; i < n; ++i) {
        uint64_t v = *GetOrCreateShadowAddress<0>(sm, addrs[i]);
        CHECK_EQ(v, 0xa5a5a5a5'00000000ULL | i, "cross-page slot");
    }
}

// A tuple-of-mixed-types shadow (as used by data-centric code paths, e.g.
// ConcurrentShadowMemory<uint8_t, ContextHandle_t>) exercises tuple::get<I>
// for I != 0.
static void test_shadow_multi_type_tuple() {
    ShadowMemory<uint8_t, uint32_t> sm;
    const size_t addr = 0xcafeb0ba'0000ULL;
    *GetOrCreateShadowAddress<0>(sm, addr) = 0x5a;
    *GetOrCreateShadowAddress<1>(sm, addr) = 0xdeadbeef;
    CHECK_EQ(*GetOrCreateShadowAddress<0>(sm, addr), 0x5a, "type-0 slot");
    CHECK_EQ(*GetOrCreateShadowAddress<1>(sm, addr), 0xdeadbeef, "type-1 slot");
}

// The free function must agree with the direct GetOrCreateShadowBaseAddress
// path -- writing through one and reading through the other proves shadow
// memory is actually mutated (i.e. the write did not land in a stack copy).
static void test_shadow_free_fn_matches_base_fn() {
    ShadowMemory<uint64_t> sm;
    const size_t addr = 0x0f0f'0000'1234ULL;
    const uint64_t value = 0x1122334455667788ULL;

    *GetOrCreateShadowAddress<0>(sm, addr) = value;
    ShadowTuple<uint64_t>& page = sm.GetOrCreateShadowBaseAddress(addr);
    uint64_t via_base = std::get<0>(page)[PAGE_OFFSET(addr)];
    CHECK_EQ(via_base, value, "write via free-fn observed via base-fn");
}

// Symmetric of the above: write via base function, read via free function.
static void test_shadow_base_fn_matches_free_fn() {
    ShadowMemory<uint64_t> sm;
    const size_t addr = 0x0e0e'ffff'5678ULL;
    const uint64_t value = 0x8899aabbccddeeffULL;

    ShadowTuple<uint64_t>& page = sm.GetOrCreateShadowBaseAddress(addr);
    std::get<0>(page)[PAGE_OFFSET(addr)] = value;
    uint64_t via_free = *GetOrCreateShadowAddress<0>(sm, addr);
    CHECK_EQ(via_free, value, "write via base-fn observed via free-fn");
}

// A pointer returned from GetOrCreateShadowAddress on address A must be equal
// to a pointer subsequently returned for the same A -- i.e. every call must
// point into the same underlying shadow page, not a fresh stack copy.
static void test_shadow_pointer_stable() {
    ShadowMemory<uint64_t> sm;
    const size_t addr = 0x2222'3333'4444ULL;
    uint64_t* p1 = GetOrCreateShadowAddress<0>(sm, addr);
    uint64_t* p2 = GetOrCreateShadowAddress<0>(sm, addr);
    CHECK_EQ(p1 == p2, true, "pointer stability across calls");
}

// Interleaved writes at different offsets inside one page must all persist.
// This is the exact pattern InitShadowSpaceForDataCentric uses (write N
// consecutive slots via successive GetOrCreateShadowAddress calls).
static void test_shadow_init_pattern() {
    ShadowMemory<uint64_t> sm;
    const size_t base = 0x8000'0000ULL;
    for (int i = 0; i < 256; ++i) {
        *GetOrCreateShadowAddress<0>(sm, base + i * 8) = 0xf00d0000ULL + i;
    }
    for (int i = 0; i < 256; ++i) {
        CHECK_EQ(*GetOrCreateShadowAddress<0>(sm, base + i * 8),
                 0xf00d0000ULL + i, "init-pattern slot");
    }
}


// ---------------------------------------------------------------------------
// Same battery for ConcurrentShadowMemory
// ---------------------------------------------------------------------------

static void test_concurrent_write_read_single() {
    ConcurrentShadowMemory<uint64_t> sm;
    const size_t addr = 0x1234'5678'9abc'0000ULL;
    const uint64_t value = 0xdeadbeefcafef00dULL;

    *GetOrCreateShadowAddress<0>(sm, addr) = value;
    uint64_t readback = *GetOrCreateShadowAddress<0>(sm, addr);
    CHECK_EQ(readback, value, "single write/read (concurrent)");
}

static void test_concurrent_free_fn_matches_base_fn() {
    ConcurrentShadowMemory<uint64_t> sm;
    const size_t addr = 0x0f0f'0000'1234ULL;
    const uint64_t value = 0x1122334455667788ULL;

    *GetOrCreateShadowAddress<0>(sm, addr) = value;
    ShadowTuple<uint64_t>& page = sm.GetOrCreateShadowBaseAddress(addr);
    uint64_t via_base = std::get<0>(page)[PAGE_OFFSET(addr)];
    CHECK_EQ(via_base, value, "concurrent: write via free-fn observed via base-fn");
}

static void test_concurrent_multi_type_tuple() {
    ConcurrentShadowMemory<uint8_t, uint32_t> sm;
    const size_t addr = 0xcafeb0ba'0000ULL;
    *GetOrCreateShadowAddress<0>(sm, addr) = 0x5a;
    *GetOrCreateShadowAddress<1>(sm, addr) = 0xdeadbeef;
    CHECK_EQ(*GetOrCreateShadowAddress<0>(sm, addr), 0x5a, "type-0 slot (concurrent)");
    CHECK_EQ(*GetOrCreateShadowAddress<1>(sm, addr), 0xdeadbeef, "type-1 slot (concurrent)");
}

// N threads each write a unique value into disjoint shadow addresses through
// the free-function overload, then all threads read back and verify. Exercises
// CAS-based page creation under contention plus the write-through path.
static void test_concurrent_multi_thread() {
    ConcurrentShadowMemory<uint64_t> sm;
    const int nthreads = 8;
    const int per_thread = 1024;
    const size_t stride = 0x100'0000ULL;   // one entry per l2 slot

    std::atomic<int> mismatches{0};

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

    auto reader = [&](int tid) {
        for (int i = 0; i < per_thread; ++i) {
            size_t addr = (size_t)tid * stride + (size_t)i * 8;
            uint64_t v = *GetOrCreateShadowAddress<0>(sm, addr);
            if (v != (uint64_t)tid * 1000000ULL + i) mismatches.fetch_add(1);
        }
    };
    ts.clear();
    for (int t = 0; t < nthreads; ++t) ts.emplace_back(reader, t);
    for (auto& th : ts) th.join();

    CHECK_EQ(mismatches.load(), 0, "concurrent multi-thread write/read mismatches");
}

// Mimics the exact usage cctlib.cpp::InitShadowSpaceForDataCentric applies to
// the shadow, which is the sole write path for USE_SHADOW_FOR_DATA_CENTRIC.
// If the free-function overload does not persist writes, GetDataObjectHandle
// will silently return the zero-initialized shadow forever.
static void test_concurrent_init_pattern_data_centric_shape() {
    struct FakeHandle { uint8_t type; uint32_t path; };  // ~ DataHandle_t
    ConcurrentShadowMemory<FakeHandle> sm;

    const size_t base = 0x7ff0'0000'0000ULL;
    const int n = 128;
    for (int i = 0; i < n; ++i) {
        FakeHandle* slot = GetOrCreateShadowAddress<0>(sm, base + i);
        slot->type = 2;                       // DYNAMIC_OBJECT
        slot->path = 0xabc00000u + (uint32_t)i;
    }
    for (int i = 0; i < n; ++i) {
        FakeHandle h = *GetOrCreateShadowAddress<0>(sm, base + i);
        CHECK_EQ((int)h.type, 2, "data-centric shape type persisted");
        CHECK_EQ(h.path, 0xabc00000u + (uint32_t)i, "data-centric shape path persisted");
    }
}


// NOLINTNEXTLINE(bugprone-exception-escape) -- unit-test main; std::bad_alloc
// (from thread/vector allocations) escaping here properly terminates the run.
int main() {
    RUN_TEST(test_shadow_write_read_single);
    RUN_TEST(test_shadow_multiple_addresses_same_page);
    RUN_TEST(test_shadow_multiple_pages);
    RUN_TEST(test_shadow_multi_type_tuple);
    RUN_TEST(test_shadow_free_fn_matches_base_fn);
    RUN_TEST(test_shadow_base_fn_matches_free_fn);
    RUN_TEST(test_shadow_pointer_stable);
    RUN_TEST(test_shadow_init_pattern);

    RUN_TEST(test_concurrent_write_read_single);
    RUN_TEST(test_concurrent_free_fn_matches_base_fn);
    RUN_TEST(test_concurrent_multi_type_tuple);
    RUN_TEST(test_concurrent_multi_thread);
    RUN_TEST(test_concurrent_init_pattern_data_centric_shape);

    fprintf(stderr, "\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
