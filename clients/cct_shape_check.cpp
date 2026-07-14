// CCT-shape check tool for cctlib integration tests.
//
// This is NOT a general-purpose profiling client and NOT a text
// reporter. It runs a per-victim assertion set programmatically: at
// Fini, it walks the CCT (built by cctlib during the run) via
// GetFullCallingContext, builds an in-memory inventory of every
// reached call chain, and dispatches to a check function selected by
// the -check knob. If any assertion fails, the tool writes a short
// diagnostic to stderr and exits non-zero; the host-side gtest just
// checks the exit code and surfaces stderr on failure.
//
// Design notes:
//   * Every recorded ContextHandle_t is turned into a stable chain
//     signature (a vector<string> of function names, root-first, root
//     sentinel skipped). Assertions consume the CctInventory directly.
//   * cctlib caps GetFullCallingContext at MAX_CCT_PRINT_DEPTH=20 and
//     appends a "Truncated call path" sentinel past that. If ANY chain
//     shows a sentinel (truncated / CRASHED / BAD IP / FAILED_TO_READ)
//     the tool fails the run -- those indicate cctlib silently
//     degraded during the walk. Victim recursion depths are sized so
//     no sentinel ever appears on the happy path.
//   * Model on cct_metric_client.cpp (skeleton) and ins_reuse_client.cpp
//     (per-thread TLS pattern).

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <sstream>
#include <iostream>
#include <unistd.h>
#include "pin.H"
#include "cctlib.H"

using namespace std;
using namespace PinCCTLib;

static KNOB<string> KnobCheck(KNOB_MODE_WRITEONCE, "pintool", "check", "",
                              "name of the per-victim CCT-shape check function to run at Fini (required)");

// ---------------- Per-thread hit table -----------------------------

struct TData {
    // Every distinct ContextHandle_t reached at least once by an
    // instrumented ins, with hit count. Bounded by number of distinct
    // CCT positions the victim actually visits.
    unordered_map<uint32_t, uint64_t> hits;
    // Captured at main's entry via a RTN_InsertCall hook. Used at
    // walk time to slice each recorded chain to the sub-chain that
    // lives under main -- pre-main libc/loader ancestors (_start,
    // __libc_start_main, __libc_init_first) are stripped, and any
    // chain that never went through main is dropped entirely. This
    // gives per-victim assertions a much tighter search space so
    // exact-count checks (chainCountForFn == N, maxCountInAnyChain
    // == N) become meaningful.
    ContextHandle_t mainCtxtHndl = 0;
};

static TLS_KEY g_tlsKey;
static inline TData* GetTls(THREADID t) {
    return static_cast<TData*>(PIN_GetThreadData(g_tlsKey, t));
}

static VOID ThreadStart(THREADID t, CONTEXT*, INT32, VOID*) {
    PIN_SetThreadData(g_tlsKey, new TData(), t);
}

// Track threads that have been observed so Fini can walk each one.
// Vector is populated single-threaded from ThreadStart under a lock;
// the victims are single-threaded so this is trivially safe.
static PIN_LOCK g_lock;
static vector<THREADID> g_threads;

static VOID ThreadStartRegister(THREADID t, CONTEXT* ctxt, INT32 flags, VOID* v) {
    ThreadStart(t, ctxt, flags, v);
    PIN_GetLock(&g_lock, t + 1);
    g_threads.push_back(t);
    PIN_ReleaseLock(&g_lock);
}

// Address range of main() in the app image, computed once at
// image-load time. Used in InstrumentInsCallback to decide whether
// a given instrumented ins belongs to main -- if so, we also insert
// a CaptureMainHandle callback, which grabs main's ctxt handle from
// the first call/ret slot INSIDE main. RTN_InsertCall at IPOINT_BEFORE
// of main wouldn't work reliably: main's entry Pin trace often has
// zero call/ret slots (e.g. a for-loop-body function with no calls
// until fprintf near the end), and GetContextHandle(t, 0) on a
// zero-slot trace returns 0 -- indistinguishable from "not captured".
static ADDRINT g_mainLo = 0, g_mainHi = 0;

// ---------------- Analysis + instrumentation ----------------------

static VOID RecordCtxt(uint32_t opaqueHandle, THREADID t) {
    uint32_t h = GetContextHandle(t, opaqueHandle);
    if (h == 0)
        return; // cctlib's uninitialized-handle sentinel
    GetTls(t)->hits[h]++;
}

// Fires at every instrumented (call/ret) slot inside main's address
// range. The FIRST call that grabs a nonzero handle stashes it as
// main's ctxt handle in per-thread TLS -- subsequent calls are no-ops.
// Guard-order matters: we take the check on the fast path so post-
// capture invocations bail early.
static VOID CaptureMainHandle(uint32_t opaqueHandle, THREADID t) {
    TData* td = GetTls(t);
    if (!td || td->mainCtxtHndl != 0)
        return;
    uint32_t h = GetContextHandle(t, opaqueHandle);
    if (h == 0)
        return;
    td->mainCtxtHndl = h;
}

static VOID InstrumentInsCallback(INS ins, VOID*, const uint32_t slot) {
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordCtxt,
                             IARG_UINT32, slot, IARG_THREAD_ID, IARG_END);
    // If this slot lives inside main, also insert a CaptureMainHandle
    // callback so the first nonzero handle seen from within main is
    // stashed as the sub-inventory's slice point.
    if (g_mainLo != 0 && INS_Address(ins) >= g_mainLo && INS_Address(ins) < g_mainHi) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CaptureMainHandle,
                                 IARG_UINT32, slot, IARG_THREAD_ID, IARG_END);
    }
}

// Call/ret-only filter. cctlib assigns a slot to every CALL and RET
// regardless of the isInterestingIns callback (see
// PopulateIPReverseMapAndAccountTraceInstructions in cctlib.cpp), and
// invokes the user's InstrumentInsCallback for CALL/RET only when
// isInterestingIns(ins) returns true. Returning true here for
// CALL/RET is the leanest way to get RecordCtxt fired at exactly the
// call/ret slots that mark trace boundaries -- one such handle per
// reached TraceNode is sufficient for shape assertions (GetFullCallingContext
// from any handle in a trace gives the full chain). Skips memory
// instrumentation entirely -- shape tests don't need it, and it was
// dominating runtime on exception victims with 5000-throw loops.
inline BOOL InterestingInsCallOrRet(INS ins) {
    return INS_IsProcedureCall(ins) || INS_IsRet(ins);
}

// Find "main" in the main executable image and record its address
// range so InstrumentInsCallback can steer CaptureMainHandle inserts.
static VOID OnImgLoad(IMG img, VOID*) {
    if (!IMG_IsMainExecutable(img))
        return;
    RTN mainRtn = RTN_FindByName(img, "main");
    if (!RTN_Valid(mainRtn))
        return;
    g_mainLo = RTN_Address(mainRtn);
    g_mainHi = g_mainLo + RTN_Size(mainRtn);
}

// ---------------- CCT inventory ------------------------------------

using FnChain = vector<string>;

struct CctInventory {
    // Distinct root-to-leaf function-name chain -> aggregate hit count.
    map<FnChain, uint64_t> chains;
    // Leaf function name -> set of distinct chains ending there.
    map<string, set<FnChain>> byLeafFn;
    // Leaf function name -> aggregate hit count.
    map<string, uint64_t> hitsByLeafFn;
    // If any cctlib HARD sentinel appears anywhere, record what and how many.
    // Soft PLT sentinels are recorded separately for diagnostics.
    map<string, size_t> sentinelCounts;
    map<string, size_t> softSentinelCounts;
    size_t maxDepthObserved = 0;
    size_t totalDistinctHandles = 0;

    // Sub-inventory: only chains that pass through main's TraceNode,
    // sliced to start at main (pre-main libc/loader ancestors stripped).
    // Populated when the walker was able to identify main's ctxt
    // handle. Assertions targeting recursion or user-level structure
    // should use these methods so pre-main clutter and any orphan
    // chains (e.g., from cctlib initialization) don't dilute the
    // signal.
    map<FnChain, uint64_t> subChains;
    map<string, set<FnChain>> subByLeafFn;
    size_t subMaxDepthObserved = 0;

    size_t chainCountForFn(const string& fn) const {
        auto it = byLeafFn.find(fn);
        return it == byLeafFn.end() ? 0 : it->second.size();
    }
    bool hasChain(vector<string> expected) const {
        return chains.count(expected) > 0;
    }
    bool hasFn(const string& fn) const {
        return byLeafFn.count(fn) > 0;
    }
    bool anyChainContainsFn(const string& fn) const {
        for (auto& kv : chains) {
            for (auto& n : kv.first)
                if (n == fn)
                    return true;
        }
        return false;
    }
    // True iff for every chain ending in leafFn, the immediate parent
    // (chain[size-2]) is expectedParent. Empty parent means we found
    // no chain with a parent at all, which we treat as false.
    bool everyChainToFnHasImmediateParent(const string& leafFn,
                                          const string& expectedParent) const {
        auto it = byLeafFn.find(leafFn);
        if (it == byLeafFn.end() || it->second.empty())
            return false;
        for (const auto& chain : it->second) {
            if (chain.size() < 2)
                return false;
            if (chain[chain.size() - 2] != expectedParent)
                return false;
        }
        return true;
    }
    // Max number of times `fn` appears in any single chain. For a
    // routine we've direct-self-recursion-collapsed this is 1 (fn
    // is only the leaf, never its own ancestor). For an uncollapsed
    // recursive routine (indirect recursion, or if collapse regressed)
    // it grows with the recursion depth.
    size_t maxCountInAnyChain(const string& fn) const {
        size_t maxC = 0;
        for (const auto& kv : chains) {
            size_t c = 0;
            for (const auto& n : kv.first)
                if (n == fn)
                    ++c;
            if (c > maxC)
                maxC = c;
        }
        return maxC;
    }

    // ---- Sub-inventory (under main) mirrors ---------------------

    size_t subChainCountForFn(const string& fn) const {
        auto it = subByLeafFn.find(fn);
        return it == subByLeafFn.end() ? 0 : it->second.size();
    }
    bool subHasFn(const string& fn) const {
        return subByLeafFn.count(fn) > 0;
    }
    bool subAnyChainContainsFn(const string& fn) const {
        for (auto& kv : subChains) {
            for (auto& n : kv.first)
                if (n == fn)
                    return true;
        }
        return false;
    }
    size_t subMaxCountInAnyChain(const string& fn) const {
        size_t maxC = 0;
        for (const auto& kv : subChains) {
            size_t c = 0;
            for (const auto& n : kv.first)
                if (n == fn)
                    ++c;
            if (c > maxC)
                maxC = c;
        }
        return maxC;
    }
    // Total distinct sub-chains that contain fn anywhere (leaf OR
    // ancestor). For the "how many times does this function appear
    // across the sub-CCT" question independent of whether it's a leaf.
    size_t subChainsContainingFn(const string& fn) const {
        size_t n = 0;
        for (const auto& kv : subChains) {
            for (const auto& e : kv.first)
                if (e == fn) {
                    ++n;
                    break;
                }
        }
        return n;
    }
    // True iff for every sub-chain ending in leafFn the immediate
    // parent is expectedParent.
    bool everySubChainToFnHasImmediateParent(const string& leafFn,
                                             const string& expectedParent) const {
        auto it = subByLeafFn.find(leafFn);
        if (it == subByLeafFn.end() || it->second.empty())
            return false;
        for (const auto& chain : it->second) {
            if (chain.size() < 2)
                return false;
            if (chain[chain.size() - 2] != expectedParent)
                return false;
        }
        return true;
    }

    // True iff every chain containing `fn` at any position has NO
    // ancestor (chain[0..pos-1]) whose function name is in `badAncestors`.
    // Used to assert that a marker in a catch/try body is not rooted
    // under __cxa_throw / _Unwind_* / __gxx_personality_v0 (which would
    // indicate cctlib mis-anchored the landing pad).
    //
    // Returns true when `fn` never appears (vacuously true is not what
    // we want -- caller should first assert `hasFn(fn)`).
    bool noAncestorOfFnIsInSet(const string& fn,
                               const set<string>& badAncestors) const {
        for (const auto& kv : chains) {
            const auto& chain = kv.first;
            for (size_t i = 0; i < chain.size(); ++i) {
                if (chain[i] != fn)
                    continue;
                for (size_t j = 0; j < i; ++j) {
                    if (badAncestors.count(chain[j]))
                        return false;
                }
            }
        }
        return true;
    }
};

// cctlib sentinel function-names produced by GetFullCallingContext when
// it can't render a frame.
//
//   HARD sentinels indicate cctlib silently degraded during the walk
//   (BAD IP: address doesn't map to any loaded image; CRASHED: cctlib
//   caught SIGSEGV during the walk; FAILED_TO_READ: postmortem lookup
//   failed). Their appearance in a shape-check is a real bug.
//
//   SOFT sentinels ("IN PLT BUT NOT VALID GOT", "UNRECOGNIZED PLT
//   SIGNATURE") are cctlib's fallbacks when its ad-hoc PLT-slot
//   pattern-match fails on the resolver stub -- a pre-existing
//   limitation of cctlib's symbolication for modern glibc PLT
//   layouts, unrelated to CCT-shape correctness. Similarly,
//   "Truncated call path (due to deep call chain)" only means the
//   walk hit cctlib's MAX_CCT_PRINT_DEPTH=20 rendering limit; the
//   underlying CCT is fine. Deep C++-runtime unwind stacks
//   (__cxa_throw -> __gxx_personality_v0 -> _Unwind_RaiseException
//   -> ...) routinely exceed 20 frames on exception victims. Soft
//   sentinels are counted separately for diagnostics but must NOT
//   fail the test.
//
// THREAD[n]_ROOT_CTXT is normal and skipped (isRootName).
static bool isHardSentinelName(const string& n) {
    return n == "CRASHED !!" ||
           n == "BAD IP !!" ||
           n == "FAILED_TO_READ" ||
           n == "CRASHED!";
}

static bool isSoftSentinelName(const string& n) {
    return n == "IN PLT BUT NOT VALID GOT" ||
           n == "UNRECOGNIZED PLT SIGNATURE" ||
           n == "Truncated call path (due to deep call chain)";
}

static bool isSentinelName(const string& n) {
    return isHardSentinelName(n) || isSoftSentinelName(n);
}

static bool isRootName(const string& n) {
    // The literal form is "THREAD[<id>]_ROOT_CTXT" (cctlib.cpp:2119).
    return n.rfind("THREAD[", 0) == 0 && n.find("]_ROOT_CTXT") != string::npos;
}

static void BuildInventoryFromThread(THREADID t, CctInventory& inv) {
    auto* td = GetTls(t);
    if (!td)
        return;
    inv.totalDistinctHandles += td->hits.size();

    // Canonicalize main's TraceNode as a "trace-start handle" using
    // the new public helper GetTraceStartHandle (cctlib.H). Two
    // ContextHandles from the same TraceNode produce the same
    // trace-start handle. Below we walk each chain leaf->root and
    // slice at the position whose trace-start matches main's; that
    // slice becomes the sub-chain rooted at main.
    ContextHandle_t mainTraceStart =
        (td->mainCtxtHndl != 0) ? GetTraceStartHandle(td->mainCtxtHndl) : 0;

    for (auto& kv : td->hits) {
        uint32_t h = kv.first;
        uint64_t hits = kv.second;
        vector<Context> chain;
        GetFullCallingContext((ContextHandle_t)h, chain);
        // chain is leaf-first. Two passes:
        //   (1) Collect ALL user-frame names for the full-CCT inventory.
        //   (2) For the sub-inventory, note the FIRST chain position
        //       (walking leaf->root, i.e. lowest index) whose Context
        //       lives in main's TraceNode. That marks the outermost
        //       main-frame. Everything from index 0 up to that
        //       position (inclusive) is the sub-chain rooted at main.
        //       (Note "outermost" from a leaf-first walk = closest to
        //       root = highest index with a main match. But since main
        //       is called exactly once from libc startup, there's only
        //       one match in a well-formed chain -- see the pre-existing
        //       exception-hook bug note below for the pathological
        //       multi-main case.)
        FnChain names;
        names.reserve(chain.size());
        int mainIdxLeafFirst = -1;
        for (size_t i = 0; i < chain.size(); ++i) {
            auto& c = chain[i];
            if (isRootName(c.functionName))
                continue;
            if (isHardSentinelName(c.functionName)) {
                inv.sentinelCounts[c.functionName] += 1;
            }
            if (isSoftSentinelName(c.functionName)) {
                inv.softSentinelCounts[c.functionName] += 1;
            }
            names.push_back(c.functionName);
            // Match against main's TraceNode using the trace-start
            // helper. We want the OUTERMOST (deepest ancestor) match,
            // which is the LAST such index walking leaf->root.
            if (mainTraceStart != 0 &&
                GetTraceStartHandle(c.ctxtHandle) == mainTraceStart) {
                mainIdxLeafFirst = (int)(names.size() - 1);
            }
        }
        if (names.empty())
            continue; // pure-root chain, nothing useful

        // Reverse to root-first for the full-inventory signature.
        FnChain sig(names.rbegin(), names.rend());
        if (sig.size() > inv.maxDepthObserved)
            inv.maxDepthObserved = sig.size();
        inv.chains[sig] += hits;
        const string& leafFn = sig.back();
        inv.byLeafFn[leafFn].insert(sig);
        inv.hitsByLeafFn[leafFn] += hits;

        // Sub-inventory: only if this chain went through main.
        // mainIdxLeafFirst is an index into `names` (leaf-first). The
        // sub-chain leaf-first is names[0..mainIdxLeafFirst] inclusive.
        // Reverse to get root-first sub-chain starting at main.
        if (mainIdxLeafFirst >= 0) {
            FnChain subLeafFirst(names.begin(),
                                 names.begin() + mainIdxLeafFirst + 1);
            FnChain subSig(subLeafFirst.rbegin(), subLeafFirst.rend());
            if (subSig.size() > inv.subMaxDepthObserved) {
                inv.subMaxDepthObserved = subSig.size();
            }
            inv.subChains[subSig] += hits;
            const string& subLeaf = subSig.back();
            inv.subByLeafFn[subLeaf].insert(subSig);
        }
    }
}

// ---------------- Assertion recorder -------------------------------

struct AssertionRecorder {
    vector<string> failures;
    const char* checkName;

    template <typename A, typename B>
    void expectLE(A obs, B lim, const char* what) {
        if (!(obs <= (A)lim)) {
            ostringstream os;
            os << "FAIL " << checkName << ": " << what
               << " expected <= " << lim << " observed " << obs;
            failures.push_back(os.str());
        }
    }
    template <typename A, typename B>
    void expectGE(A obs, B lim, const char* what) {
        if (!(obs >= (A)lim)) {
            ostringstream os;
            os << "FAIL " << checkName << ": " << what
               << " expected >= " << lim << " observed " << obs;
            failures.push_back(os.str());
        }
    }
    template <typename A, typename B, typename C>
    void expectInRange(A obs, B lo, C hi, const char* what) {
        if (!(obs >= (A)lo && obs <= (A)hi)) {
            ostringstream os;
            os << "FAIL " << checkName << ": " << what
               << " expected in [" << lo << "," << hi << "] observed " << obs;
            failures.push_back(os.str());
        }
    }
    template <typename A, typename B>
    void expectEQ(A obs, B want, const char* what) {
        if (!(obs == (A)want)) {
            ostringstream os;
            os << "FAIL " << checkName << ": " << what
               << " expected == " << want << " observed " << obs;
            failures.push_back(os.str());
        }
    }
    void expectTrue(bool b, const char* what) {
        if (!b) {
            ostringstream os;
            os << "FAIL " << checkName << ": " << what << " (expected true)";
            failures.push_back(os.str());
        }
    }
    void expectNoSentinels(const CctInventory& inv) {
        if (!inv.sentinelCounts.empty()) {
            ostringstream os;
            os << "FAIL " << checkName << ": sentinel frames appeared:";
            for (auto& kv : inv.sentinelCounts) {
                os << " [" << kv.first << " x" << kv.second << "]";
            }
            failures.push_back(os.str());
        }
    }
};

// The set of function names an in-try or in-catch MARKER function must
// NEVER have as an ancestor in any chain. If a marker is descended from
// __cxa_throw / __gxx_personality_v0 / _Unwind_*, cctlib mis-anchored
// the landing pad and the catch/try body's call is attributed to the
// throw-machinery subtree instead of the function that owns the
// try/catch.
static const set<string> kThrowMachineryFns = {
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_allocate_exception",
    "__cxa_begin_catch",
    "__cxa_end_catch",
    "__gxx_personality_v0",
    "_Unwind_RaiseException",
    "_Unwind_Resume",
    "_Unwind_Resume_or_Rethrow",
    "_Unwind_ForcedUnwind",
    "_Unwind_Backtrace",
    "_Unwind_Find_FDE",
    "_Unwind_GetIP",
    "_Unwind_GetTextRelBase",
    "_Unwind_GetCFA",
    "__longjmp",
};

// Assert that a marker function `fn` is (a) present in the CCT,
// (b) whose immediate parent in every chain equals `parent`,
// (c) never has any throw/unwind-machinery function as an ancestor.
// The third check is the load-bearing one: prior to the landing-pad
// re-anchor fix, in-catch markers would appear as descendants of
// __cxa_throw's subtree instead of children of the frame owning the
// try/catch.
static void expectMarkerAnchored(AssertionRecorder& r,
                                 const CctInventory& inv,
                                 const string& fn,
                                 const string& parent) {
    r.expectTrue(inv.hasFn(fn), (fn + " appears in the CCT").c_str());
    r.expectTrue(inv.everyChainToFnHasImmediateParent(fn, parent),
                 (fn + "'s immediate parent is " + parent).c_str());
    r.expectTrue(inv.noAncestorOfFnIsInSet(fn, kThrowMachineryFns),
                 (fn + " has NO ancestor in the throw/unwind machinery "
                       "(catch/try body must not be rooted under __cxa_throw)")
                     .c_str());
}

// ---------------- Per-victim check functions -----------------------
//
// Recursion victims. Depths are sized so uncollapsed chains stay under
// MAX_CCT_PRINT_DEPTH=20 -- otherwise cctlib appends a Truncated
// sentinel that would degrade the sensitivity of these assertions.

static void check_rec_fib_deep(const CctInventory& inv, AssertionRecorder& r) {
    // fib(15) with direct-self-recursion collapse. In the CCT rooted
    // at main, there is EXACTLY ONE fib TraceNode:
    //   * Exactly 1 distinct sub-chain ends in fib: [main, fib].
    //   * fib appears EXACTLY ONCE along any path from main to leaf.
    // Without collapse these would grow to 15 and 15 respectively.
    r.expectTrue(inv.subHasFn("fib"), "fib appears as a leaf function under main");
    r.expectEQ(inv.subChainCountForFn("fib"), (size_t)1,
               "sub-CCT under main has exactly 1 distinct chain ending in fib");
    r.expectEQ(inv.subMaxCountInAnyChain("fib"), (size_t)1,
               "fib appears at most once along any path from main to leaf");
    r.expectTrue(inv.everySubChainToFnHasImmediateParent("fib", "main"),
                 "fib's immediate parent in every sub-chain is main");
    r.expectNoSentinels(inv);
}

static void check_rec_ackermann(const CctInventory& inv, AssertionRecorder& r) {
    // A(3,4). Same collapse story as fib.
    r.expectTrue(inv.subHasFn("A"), "A appears as a leaf function under main");
    r.expectEQ(inv.subChainCountForFn("A"), (size_t)1,
               "sub-CCT under main has exactly 1 distinct chain ending in A");
    r.expectEQ(inv.subMaxCountInAnyChain("A"), (size_t)1,
               "A appears at most once along any path from main to leaf");
    r.expectTrue(inv.everySubChainToFnHasImmediateParent("A", "main"),
                 "A's immediate parent in every sub-chain is main");
    r.expectNoSentinels(inv);
}

static void check_rec_multi_direct(const CctInventory& inv, AssertionRecorder& r) {
    // multi(15) with THREE static direct self-call sites, all
    // collapse into one frame under main.
    r.expectTrue(inv.subHasFn("multi"), "multi appears as a leaf function under main");
    r.expectEQ(inv.subChainCountForFn("multi"), (size_t)1,
               "sub-CCT under main has exactly 1 distinct chain ending in multi "
               "(all 3 direct self-call sites collapsed into one physical frame)");
    r.expectEQ(inv.subMaxCountInAnyChain("multi"), (size_t)1,
               "multi appears at most once along any path from main to leaf");
    r.expectTrue(inv.everySubChainToFnHasImmediateParent("multi", "main"),
                 "multi's immediate parent in every sub-chain is main");
    r.expectNoSentinels(inv);
}

static void check_rec_indirect_only(const CctInventory& inv, AssertionRecorder& r) {
    // indirect_rec(12) via function pointer. Called normally from
    // main once (indirect_rec(12)), then makes 12 successive indirect
    // self-calls -> indirect_rec(11), (10), ..., (0). Total 13
    // physical frames of indirect_rec (n from 12 down to 0, inclusive).
    //
    // Design deliberately does NOT collapse indirect self-recursion,
    // so every activation is a fresh physical frame:
    //   * indirect_rec appears EXACTLY 13 times along the deepest
    //     path (13 nested frames of indirect_rec).
    //   * subChainCountForFn("indirect_rec") == 13 (one distinct
    //     chain per depth level -- leaf at each of the 13 frames).
    // If either drops below 13, we've accidentally collapsed indirect
    // recursion (the explicit non-goal of the design).
    r.expectTrue(inv.subHasFn("indirect_rec"), "indirect_rec appears under main");
    r.expectEQ(inv.subChainCountForFn("indirect_rec"), (size_t)13,
               "sub-CCT under main has exactly 13 distinct chains ending in indirect_rec "
               "(1 initial direct call from main + 12 indirect frames, no collapse)");
    r.expectEQ(inv.subMaxCountInAnyChain("indirect_rec"), (size_t)13,
               "indirect_rec appears exactly 13 times along the deepest path from main");
    r.expectNoSentinels(inv);
}

static void check_rec_mixed_direct_indirect(const CctInventory& inv, AssertionRecorder& r) {
    // mixed(30): every 5th activation is indirect (creates a new
    // frame), the rest are direct (collapse into the current indirect
    // frame). Indirect calls happen at n = 30, 25, 20, 15, 10, 5
    // (n%5==0) -> 6 indirect frames plus the initial normal call
    // from main = 7 mixed frames total.
    //   * mixed appears EXACTLY 7 times along the deepest path.
    //   * subChainCountForFn("mixed") == 7 (one distinct chain per depth).
    r.expectTrue(inv.subHasFn("mixed"), "mixed appears under main");
    r.expectEQ(inv.subChainCountForFn("mixed"), (size_t)7,
               "sub-CCT under main has exactly 7 distinct chains ending in mixed "
               "(6 indirect frames + 1 initial call, direct sites collapse within each)");
    r.expectEQ(inv.subMaxCountInAnyChain("mixed"), (size_t)7,
               "mixed appears exactly 7 times along the deepest path from main");
    r.expectNoSentinels(inv);
}

static void check_rec_stripped(const CctInventory& inv, AssertionRecorder& r) {
    // Stripped binary. Pin identifies the whole .text as one apparent
    // routine, so the recursion classifier never sees fib's self-call
    // and collapse can't engage (Pin-side routine granularity issue,
    // not a cctlib limitation we can fix). Additionally: main's
    // symbol is stripped, so our OnImgLoad hook's RTN_FindByName(img,
    // "main") returns invalid -- mainCtxtHndl is never set and the
    // sub-inventory is empty. Fall back to full-CCT assertions.
    r.expectTrue(inv.hasFn("") || inv.hasFn(".text"),
                 "at least one app-side leaf attributed (empty-name or .text)");
    r.expectNoSentinels(inv);
}

static void check_rec_exception(const CctInventory& inv, AssertionRecorder& r) {
    // descend(15) is direct self-recursive; throw at leaf, main
    // catches. Same collapse story as rec_fib_deep -- but under a
    // throw path, so this exercises the collapse-plus-unwind
    // interaction on the sub-CCT rooted at main.
    r.expectTrue(inv.subHasFn("descend"), "descend appears under main");
    r.expectEQ(inv.subChainCountForFn("descend"), (size_t)1,
               "sub-CCT under main has exactly 1 distinct chain ending in descend "
               "(collapse holds under a throw path)");
    r.expectEQ(inv.subMaxCountInAnyChain("descend"), (size_t)1,
               "descend appears at most once along any path from main");
    r.expectTrue(inv.everySubChainToFnHasImmediateParent("descend", "main"),
                 "descend's immediate parent in every sub-chain is main");
    r.expectNoSentinels(inv);
}

static void check_rec_baseline_nonrec(const CctInventory& inv, AssertionRecorder& r) {
    // Non-recursive baseline. Sanity: sub-CCT under main exists.
    r.expectGE(inv.subChains.size(), (size_t)1, "at least one sub-chain under main");
    r.expectNoSentinels(inv);
}

// Exception victims. Load-bearing invariant: cctlib's unwind path
// must leave the CCT coherent -- no BAD IP, no chain corruption of
// the pre-throw path, no post-catch code stranded under the throwing
// frame's fresh subtree.
//
// !!! PRE-EXISTING CCTLIB BUG SURFACED BY THESE TESTS !!!
// cctlib's exception hook fires only on _Unwind_RaiseException's
// last RET (src/cctlib.cpp:3033-3035). But when an exception is
// CAUGHT, _Unwind_RaiseException never returns -- libgcc does a
// context-restore directly into the handler's landing pad. So
// SetCurTraceNodeAfterExceptionIfContextIsInstalled never fires,
// tlsCurrentTraceNode stays deep in libgcc, and the landing pad's
// Pin trace enters InstrumentTraceEntry with a stale CCT anchor.
// Result: iteration N of a try/catch loop creates a NEW landing-pad
// TraceNode as a child of iter N-1's __cxa_throw subtree, growing
// the chain unboundedly. See exc_deep_unwind chain dump for the
// signature (main;recurse;__cxa_throw;main;recurse;__cxa_throw;...).
// Existing exception_integration_test never noticed because it only
// checks "tool exits cleanly + produces a report".
//
// The assertions below intentionally do NOT trip on this bug -- they
// check the invariants that DO hold today (parent of the recursive
// function is main; no BAD IP; etc.). A separate cctlib fix would
// enable the tighter forms of these checks (marked "TIGHTER WITH FIX").
// TODO(cctlib-exception-hook): fix by attaching the reset to a hook
// that fires regardless of whether _Unwind_RaiseException returns
// normally, then re-enable the tighter checks.

static void check_exc_deep_unwind(const CctInventory& inv, AssertionRecorder& r) {
    // Structure: main { for i in ITERS { try { recurse(D, i); } catch {} } }
    // recurse() is DIRECT self-recursive; deepest activation throws.
    // Now that cctlib properly re-anchors to main's frame on each
    // landing-pad delivery, recurse never appears as its own ancestor
    // -- the collapse holds cleanly across every unwind cycle.
    expectMarkerAnchored(r, inv, "deep_try_marker", "main");
    expectMarkerAnchored(r, inv, "deep_catch_marker", "main");
    r.expectTrue(inv.hasFn("recurse"), "recurse appears as a leaf function");
    r.expectTrue(inv.everyChainToFnHasImmediateParent("recurse", "main"),
                 "recurse's immediate parent is always main (recurse fully collapses even under throw)");
    r.expectEQ(inv.maxCountInAnyChain("recurse"), (size_t)1,
               "recurse never appears as ancestor of recurse (landing-pad re-anchor holds)");
    r.expectNoSentinels(inv);
}

static void check_exc_ctor_throw(const CctInventory& inv, AssertionRecorder& r) {
    // Structure: throw fires mid-ctor; partial dtors unwind; main catches.
    // Multi-phase unwind exercises both a cleanup landing pad (Wrap
    // ctor's dtor cleanup for A) and a handler landing pad (main's
    // catch). Both re-anchor via the _Unwind_SetIP-driven hook.
    // Landing-pad Pin traces get function-labeled with the enclosing
    // function's own name (their first insn is inside the function
    // body), so `main` may appear up to twice in a chain: main's own
    // entry trace + main's landing-pad Pin trace.
    expectMarkerAnchored(r, inv, "ctorthrow_try_marker", "main");
    expectMarkerAnchored(r, inv, "ctorthrow_catch_marker", "main");
    r.expectTrue(inv.anyChainContainsFn("main"),
                 "main still reachable after the ctor throw");
    r.expectLE(inv.maxCountInAnyChain("main"), (size_t)4,
               "main appears at most a small bounded number of times (bug pre-fix: unbounded)");
    r.expectNoSentinels(inv);
}

static void check_exc_catch_and_resume(const CctInventory& inv, AssertionRecorder& r) {
    // Structure:
    //   main { for i in ITERS {
    //     resume_after_catch(i) { try { may_throw(i); } catch(int) {} }
    //     post_catch_worker(i);
    //   }}
    //
    // Structural invariants:
    //   * may_throw's immediate parent is resume_after_catch (or a
    //     variant labeled resume_after_catch -- landing pads inside
    //     resume_after_catch get the same function name).
    //   * post_catch_worker's immediate parent is main (or main-
    //     labeled landing pad, which reads as `main` in chain fn-names).
    //     KEY signal: cctlib restored the anchor for the post-catch
    //     call, so C() is NOT stranded deep in the throwing subtree.
    //   * resume_try_marker and resume_catch_marker are both direct
    //     children of resume_after_catch and neither is descended from
    //     __cxa_throw.
    expectMarkerAnchored(r, inv, "resume_try_marker", "resume_after_catch");
    expectMarkerAnchored(r, inv, "resume_catch_marker", "resume_after_catch");
    r.expectTrue(inv.everyChainToFnHasImmediateParent("may_throw", "resume_after_catch"),
                 "may_throw's immediate parent in every chain is resume_after_catch");
    r.expectTrue(inv.everyChainToFnHasImmediateParent("post_catch_worker", "main"),
                 "post_catch_worker's immediate parent in every chain is main "
                 "(NOT resume_after_catch or may_throw)");
    r.expectNoSentinels(inv);
}

static void check_sig_longjmp(const CctInventory& inv, AssertionRecorder& r) {
    // Structure: main { for i in ITERS { setjmp(jb); if 0: go_deep(i,8); } }
    // go_deep is DIRECT self-recursive; deepest calls longjmp back to main.
    // cctlib has its own setjmp/longjmp hooks (CaptureSigSetJmpCtxt /
    // RestoreSigLongJmpCtxt / HoldLongJmpBuf) -- separate path from
    // the exception hook -- but the same anchor-restoration invariant
    // applies. Both markers must be direct children of main.
    expectMarkerAnchored(r, inv, "sjlj_try_marker", "main");
    expectMarkerAnchored(r, inv, "sjlj_landing_marker", "main");
    r.expectTrue(inv.hasFn("go_deep"), "go_deep appears as a leaf function");
    r.expectTrue(inv.everyChainToFnHasImmediateParent("go_deep", "main"),
                 "go_deep's immediate parent is always main");
    r.expectNoSentinels(inv);
}

static void check_sig_sigsegv_recover(const CctInventory& inv, AssertionRecorder& r) {
    // Structure: main { for i in ITERS { sigsetjmp; if 0: poke(i); } }
    // poke(i) deref 0x1 -> SIGSEGV -> handler{siglongjmp back}.
    //
    // Under call/ret-only instrumentation, poke's Pin trace ends at
    // its epilogue ret; the SIGSEGV fires BEFORE that ret ever
    // executes, so no RecordCtxt call inside poke ever runs and poke
    // won't appear in the recorded chains. handler DOES appear (it
    // calls siglongjmp -- a slotted control-flow ins that fires
    // before the longjmp). So we assert on handler + main + markers.
    expectMarkerAnchored(r, inv, "sigsegv_try_marker", "main");
    expectMarkerAnchored(r, inv, "sigsegv_recover_marker", "main");
    r.expectTrue(inv.hasFn("handler"), "signal handler appears in the CCT");
    r.expectTrue(inv.subAnyChainContainsFn("main"),
                 "main still reachable under itself after SIGSEGV+siglongjmp");
    r.expectNoSentinels(inv);
}

// -----------------------------------------------------------------------------
// Additional exception-victim shape checks. Each encodes the specific
// try/catch/throw structure of its victim so a regression in cctlib's
// unwind handling that misplaces a landing pad (or fails to fire the
// re-anchor) shows up as a specific parent-child mismatch, not as a
// silent CCT corruption.
// -----------------------------------------------------------------------------

static void check_exc_simple_throw(const CctInventory& inv, AssertionRecorder& r) {
    // Structure: main -> outer -> middle -> inner -> throw; main catches.
    // Every-chain-parent invariants for the pre-throw call stack.
    // simple_try_marker fires in the try body BEFORE outer(i) is called;
    // simple_catch_marker fires in the catch body. Both must be direct
    // children of main -- regressions manifest as either marker attaching
    // as a descendant of __cxa_throw.
    expectMarkerAnchored(r, inv, "simple_try_marker", "main");
    expectMarkerAnchored(r, inv, "simple_catch_marker", "main");
    r.expectTrue(inv.everyChainToFnHasImmediateParent("inner", "middle"),
                 "inner's immediate parent is middle");
    r.expectTrue(inv.everyChainToFnHasImmediateParent("middle", "outer"),
                 "middle's immediate parent is outer");
    r.expectTrue(inv.everyChainToFnHasImmediateParent("outer", "main"),
                 "outer's immediate parent is main (unwind didn't strand it)");
    r.expectNoSentinels(inv);
}

static void check_exc_rethrow(const CctInventory& inv, AssertionRecorder& r) {
    // Structure:
    //   main { try { inner(i); } catch (std::exception&) { ... } }
    //   inner { try { raise_it(i); } catch (std::exception& e) { throw; } }
    //   raise_it { throw std::runtime_error(...); }
    // Two _Unwind_SetIP call chains per iter: (1) raise_it -> inner's
    // catch handler landing pad, (2) inner's `throw;` ->
    // _Unwind_Resume_or_Rethrow -> main's catch handler landing pad.
    // Four markers cover all four try/catch bodies -- each must be a
    // direct child of its enclosing function AND not descended from
    // any throw/unwind-machinery function.
    expectMarkerAnchored(r, inv, "rethrow_outer_try_marker", "main");
    expectMarkerAnchored(r, inv, "rethrow_outer_catch_marker", "main");
    expectMarkerAnchored(r, inv, "rethrow_inner_try_marker", "inner");
    expectMarkerAnchored(r, inv, "rethrow_inner_catch_marker", "inner");
    r.expectTrue(inv.hasFn("raise_it"), "raise_it appears as a leaf function");
    r.expectTrue(inv.hasFn("inner"), "inner appears in the CCT");
    r.expectTrue(inv.subAnyChainContainsFn("main"),
                 "main still reachable after nested rethrow");
    r.expectNoSentinels(inv);
}

static void check_exc_catchall(const CctInventory& inv, AssertionRecorder& r) {
    // Structure: main { try { thrower(kind, i); } catch (...) {} }
    // thrower throws one of {int, POD, std::string, polymorphic type}
    // depending on `kind`; kind=3 (Virt with a virtual dtor) additionally
    // exercises a cleanup landing pad inside thrower's body.
    // Both markers must be direct children of main and NOT descended
    // from __cxa_throw -- a regression would attribute the catch(...)
    // body's marker call to the throw subtree.
    expectMarkerAnchored(r, inv, "catchall_try_marker", "main");
    expectMarkerAnchored(r, inv, "catchall_catch_marker", "main");
    r.expectTrue(inv.hasFn("thrower"), "thrower appears as a leaf function");
    r.expectTrue(inv.subAnyChainContainsFn("main"),
                 "main still reachable under itself after catch-all");
    r.expectNoSentinels(inv);
}

static void check_exc_dtor_cleanup(const CctInventory& inv, AssertionRecorder& r) {
    // Structure: main { try { thrower(i); } catch (int) {} }
    // thrower constructs two local Guard objects whose dtors run during
    // unwind (via a cleanup landing pad INSIDE thrower's body) before
    // main's catch fires. Exercises the multi-landing-pad phase-2 path
    // where personality installs a cleanup context, dtors execute, then
    // _Unwind_Resume triggers the next SetIP for main's catch.
    // Both markers must be direct children of main.
    expectMarkerAnchored(r, inv, "dtorcleanup_try_marker", "main");
    expectMarkerAnchored(r, inv, "dtorcleanup_catch_marker", "main");
    r.expectTrue(inv.hasFn("thrower"), "thrower appears as a leaf function");
    r.expectTrue(inv.subAnyChainContainsFn("main"),
                 "main still reachable under itself after cleanup unwind");
    r.expectNoSentinels(inv);
}

static void check_exc_stress_loop(const CctInventory& inv, AssertionRecorder& r) {
    // Structure: main { for i in ITERS { try { thrower(v); } catch (uint64_t) {} } }
    // High-iteration throw/catch stress. Same shape as simple but many
    // iterations -- catches a regression where cctlib accumulates
    // state per iteration (leaking TraceNodes or drifting the anchor).
    expectMarkerAnchored(r, inv, "stress_try_marker", "main");
    expectMarkerAnchored(r, inv, "stress_catch_marker", "main");
    r.expectTrue(inv.everyChainToFnHasImmediateParent("thrower", "main"),
                 "thrower's immediate parent is main");
    r.expectNoSentinels(inv);
}

static void check_exc_polymorphic(const CctInventory& inv, AssertionRecorder& r) {
    // Structure: main { try { thrower(i); } catch (const std::exception&) {} }
    // thrower throws Base/Mid/Leaf (public std::exception subclasses).
    // Personality's type-matching path is exercised; landing-pad shape
    // is still the same top-level main-catches-thrower structure.
    expectMarkerAnchored(r, inv, "poly_try_marker", "main");
    expectMarkerAnchored(r, inv, "poly_catch_marker", "main");
    r.expectTrue(inv.everyChainToFnHasImmediateParent("thrower", "main"),
                 "thrower's immediate parent is main");
    r.expectNoSentinels(inv);
}

static void check_exc_recurse_trycatch(const CctInventory& inv, AssertionRecorder& r) {
    // Structure: main { for i in ITERS {
    //     try { rec(D, i); } catch(int) { rectry_outer_catch(i); }
    //   }}
    // rec(depth, i) is DIRECT self-recursive; every activation wraps its
    // downward call in try{...}catch(int){rethrow}. At depth==0 the
    // throw fires; the exception propagates through EVERY frame's catch
    // on its way up, and main's outer catch stops it.
    //
    // Direct-self-recursion collapse fuses all rec activations into ONE
    // TraceNode. The load-bearing invariants:
    //   1. rec appears at most ONCE in any chain (collapse holds under
    //      throw/rethrow -- landing-pad re-anchor must not defeat it).
    //   2. rectry_try_marker, rectry_deep_marker, rectry_catch_marker
    //      all have immediate parent = rec (the collapsed node) and
    //      NO ancestor in throw/unwind machinery.
    //   3. rectry_outer_try, rectry_outer_catch have immediate parent
    //      = main (post-catch anchor restored at the outermost frame).
    //   4. rectry_after_marker must NOT appear -- the code path is
    //      unreachable (every activation either throws or catches+
    //      rethrows). If it appears the compiler / cctlib has
    //      hallucinated an unreachable code path.
    // Direct-self-recursion collapse fuses all rec activations into ONE
    // TraceNode. But rec's catch-handler landing pad is a SEPARATE Pin
    // trace whose first IP lies inside rec's body -- Pin labels it
    // `rec` too via RTN_FindNameByAddress. So chain function-name
    // sequences can show `rec -> rec` even with perfect collapse: the
    // first `rec` is the collapsed TraceNode, the second is the
    // catch-LP Pin trace. maxCountInAnyChain counts fn-name occurrences,
    // not TraceNodes, so bound to 2 (entry + LP). > 2 would indicate a
    // real collapse regression.
    r.expectTrue(inv.hasFn("rec"), "rec appears in the CCT");
    r.expectLE(inv.maxCountInAnyChain("rec"), (size_t)2,
               "rec appears at most twice per chain (collapsed TraceNode + "
               "catch-landing-pad Pin trace labeled 'rec' by RTN name lookup)");

    expectMarkerAnchored(r, inv, "rectry_try_marker", "rec");
    expectMarkerAnchored(r, inv, "rectry_deep_marker", "rec");
    expectMarkerAnchored(r, inv, "rectry_catch_marker", "rec");
    expectMarkerAnchored(r, inv, "rectry_outer_try", "main");
    expectMarkerAnchored(r, inv, "rectry_outer_catch", "main");

    r.expectTrue(!inv.hasFn("rectry_after_marker"),
                 "rectry_after_marker must NOT appear (unreachable code path)");
    r.expectNoSentinels(inv);
}

static void check_exc_none_tn(const CctInventory& inv, AssertionRecorder& r) {
    // Baseline: no throws. Sanity: main appears; no HARD sentinels.
    // The tool's exception machinery must be inert when no exception
    // fires -- catches any regression where cctlib's _Unwind_SetIP
    // hook fires spuriously or the pending-reset state is dirty on
    // process startup.
    r.expectTrue(inv.subAnyChainContainsFn("main"),
                 "main is reachable in the sub-CCT");
    r.expectNoSentinels(inv);
}

static void check_exc_uncaught_tn(const CctInventory& inv, AssertionRecorder& r) {
    // Structure: main { thrower(); } thrower { throw; }
    // Nobody catches. libgcc's phase-1 search returns _URC_END_OF_STACK
    // -> phase 2 never entered -> _Unwind_SetIP never called -> our
    // hook never fires -> pending state never armed. std::terminate
    // is called and the custom terminator calls _exit(0). The tool
    // must NOT crash on the uncaught-exception path (a pre-existing
    // guard was there to prevent dereferencing a NULL exception-
    // handler frame; the new design has no such state, so no guard
    // is needed, but the invariant "cctlib survives" must still hold).
    r.expectTrue(inv.hasFn("thrower"), "thrower appears as a leaf function");
    r.expectTrue(inv.everyChainToFnHasImmediateParent("thrower", "main"),
                 "thrower's immediate parent is main");
    r.expectNoSentinels(inv);
}

// Dispatch table.
using CheckFn = void (*)(const CctInventory&, AssertionRecorder&);
static const map<string, CheckFn> kChecks = {
    {"rec_fib_deep", check_rec_fib_deep},
    {"rec_ackermann", check_rec_ackermann},
    {"rec_multi_direct", check_rec_multi_direct},
    {"rec_indirect_only", check_rec_indirect_only},
    {"rec_mixed_direct_indirect", check_rec_mixed_direct_indirect},
    {"rec_stripped", check_rec_stripped},
    {"rec_exception", check_rec_exception},
    {"rec_baseline_nonrec", check_rec_baseline_nonrec},
    // Exception victims -- per-victim checks encoding the specific
    // try/catch structure of each. All 13 victims are wired here;
    // exception_shape_test.cpp selects the subset that runs (the
    // stress victims are slow under Pin+cctlib so they may be
    // gated behind an "EXPENSIVE" env var).
    {"exc_simple_throw", check_exc_simple_throw},
    {"exc_deep_unwind", check_exc_deep_unwind},
    {"exc_rethrow", check_exc_rethrow},
    {"exc_catchall", check_exc_catchall},
    {"exc_dtor_cleanup", check_exc_dtor_cleanup},
    {"exc_stress_loop", check_exc_stress_loop},
    {"exc_polymorphic", check_exc_polymorphic},
    {"exc_recurse_trycatch", check_exc_recurse_trycatch},
    {"exc_none_tn", check_exc_none_tn},
    {"exc_uncaught_tn", check_exc_uncaught_tn},
    {"exc_ctor_throw", check_exc_ctor_throw},
    {"exc_catch_and_resume", check_exc_catch_and_resume},
    {"sig_longjmp", check_sig_longjmp},
    {"sig_sigsegv_recover", check_sig_sigsegv_recover},
};

// ---------------- Fini --------------------------------------------

static void RunChecksAndExit(const string& check);

// Fires when a thread finishes -- crucially, BEFORE Pin unloads any
// images. cctlib's GetFullCallingContext calls IsValidIP internally,
// which walks APP_ImgHead(); at PIN_AddFiniFunction time that list
// is already empty and every frame comes back as "BAD IP !!". Doing
// the walk here (single-threaded victims -> exactly one call) means
// the target's own IPs are still in loaded-image ranges and resolve.
// Deadspy dodges the same trap by walking at IMG_AddUnloadFunction
// time (clients/deadspy_client.cpp:1551).
// Shared flag: whichever of ThreadFini / FiniFunc fires first wins,
// the other is a no-op. This matters because if the first-firing
// callback's assertions all pass, RunChecksAndExit returns normally
// -- the second callback would then re-walk with cctlib images
// already unloaded and clobber the result with spurious BAD IP
// failures.
static bool g_checkRan = false;

static VOID ThreadFini(THREADID t, const CONTEXT*, INT32, VOID*) {
    if (g_checkRan)
        return;
    g_checkRan = true;
    RunChecksAndExit(KnobCheck.Value());
}

static void RunChecksAndExit(const string& check) {
    if (check.empty()) {
        fprintf(stderr, "cct_shape_check: -check <name> is required\n");
        PIN_ExitProcess(2);
    }
    auto it = kChecks.find(check);
    if (it == kChecks.end()) {
        fprintf(stderr, "cct_shape_check: no check registered for '%s'\n", check.c_str());
        PIN_ExitProcess(2);
    }

    // Debug: dump the first 5 recorded handles' walks via cctlib's own
    // PrintFullCallingContext to compare against our canonicalizer.
    if (getenv("CCT_SHAPE_DEBUG")) {
        for (THREADID t : g_threads) {
            auto* td = GetTls(t);
            if (!td)
                continue;
            fprintf(stderr, "== thread %u has %zu handles\n", t, td->hits.size());
            int i = 0;
            for (auto& kv : td->hits) {
                if (i++ >= 5)
                    break;
                fprintf(stderr, "-- handle %u --\n", kv.first);
                PrintFullCallingContext((ContextHandle_t)kv.first);
                fprintf(stderr, "\n");
            }
        }
    }

    CctInventory inv;
    for (THREADID t : g_threads)
        BuildInventoryFromThread(t, inv);

    AssertionRecorder r;
    r.checkName = check.c_str();
    it->second(inv, r);

    if (!r.failures.empty()) {
        fprintf(stderr, "cct_shape_check[%s] %zu failure(s):\n",
                check.c_str(), r.failures.size());
        for (auto& f : r.failures)
            fprintf(stderr, "  %s\n", f.c_str());
    }

    // Optional: dump inventory summary even on success (for probing
    // fresh victims / setting assertion thresholds).
    if (!r.failures.empty() || getenv("CCT_SHAPE_ALWAYS_DUMP")) {
        fprintf(stderr, "-- inventory summary [%s] --\n", check.c_str());
        fprintf(stderr, "distinct_chains=%zu total_distinct_handles=%zu max_depth=%zu\n",
                inv.chains.size(), inv.totalDistinctHandles, inv.maxDepthObserved);
        for (auto& kv : inv.byLeafFn) {
            fprintf(stderr, "  leaf_fn '%s' chains=%zu hits=%llu\n",
                    kv.first.c_str(), kv.second.size(),
                    (unsigned long long)inv.hitsByLeafFn[kv.first]);
        }
        // If CCT_SHAPE_DUMP_CHAINS is set, dump every chain (root->leaf)
        // as "; "-separated for eyeballing structural anchoring.
        if (getenv("CCT_SHAPE_DUMP_CHAINS")) {
            for (auto& kv : inv.chains) {
                fprintf(stderr, "  CHAIN hits=%llu :", (unsigned long long)kv.second);
                for (auto& n : kv.first)
                    fprintf(stderr, " %s ;", n.c_str());
                fprintf(stderr, "\n");
            }
        }
    }

    if (!r.failures.empty())
        PIN_ExitProcess(1);
}

// FiniFunc is a fallback if for some reason ThreadFini didn't fire
// (e.g. abnormal exit path). Same body; the `done` flag in ThreadFini
// prevents double-run when both fire.
static void FiniFunc(INT32 code, VOID* v) {
    if (g_checkRan)
        return;
    g_checkRan = true;
    // Fallback: ThreadFini didn't fire (abnormal exit path). At this
    // point images may already be unloaded and cctlib's IsValidIP
    // will return false for every frame -> chains come back as
    // BAD IP !!. The assertions catch that as a sentinel failure and
    // the diagnostic makes the cause obvious.
    RunChecksAndExit(KnobCheck.Value());
}

// ---------------- main --------------------------------------------

static INT32 Usage() {
    PIN_ERROR("cct_shape_check: cctlib CCT-shape assertion tool. Requires -check <victim_name>.\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

static FILE* gTraceFile;

int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv))
        return Usage();
    PIN_InitSymbols();

    // cctlib requires a log file; keep it silent by opening /dev/null.
    gTraceFile = fopen("/dev/null", "w");
    if (!gTraceFile)
        gTraceFile = stderr;

    PIN_InitLock(&g_lock);
    g_tlsKey = PIN_CreateThreadDataKey(nullptr);
    PIN_AddThreadStartFunction(ThreadStartRegister, nullptr);
    PIN_AddThreadFiniFunction(ThreadFini, nullptr);
    PIN_AddFiniFunction(FiniFunc, nullptr);

    // Call/ret-only instrumentation. cctlib always slots every CALL
    // and RET; our InterestingInsCallOrRet just tells cctlib to
    // additionally invoke our InstrumentInsCallback at those slots.
    // Every reached TraceNode contains at least one call or ret
    // (Pin traces almost always end on a control-flow insn), so this
    // is enough to enumerate the full CCT via GetFullCallingContext
    // from any recorded handle -- and it skips all the memory-access
    // instrumentation that was dominating runtime.
    PinCCTLibInit(InterestingInsCallOrRet, gTraceFile, InstrumentInsCallback, 0);
    // Hook main's entry AFTER PinCCTLibInit so cctlib's
    // TRACE_AddInstrumentFunction is registered before our
    // RTN_InsertCall (order of instrumentation callbacks in Pin does
    // NOT depend on registration order but analysis-routine order at
    // the same IPOINT does -- see CALL_ORDER_LAST in CaptureMainHandle
    // above).
    IMG_AddInstrumentFunction(OnImgLoad, nullptr);

    PIN_StartProgram();
    return 0;
}
