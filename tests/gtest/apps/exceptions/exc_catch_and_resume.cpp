// Throw + catch + continue normally (no rethrow). After the catch block
// finishes, execution resumes right after the try/catch and the outer
// function returns cleanly. Then the OUTER caller does more work that
// deadspy must still attribute to the right CCT node.
//
// The purpose is to catch a hypothetical regression where cctlib
// forgets to fully restore its per-thread CCT anchor after an exception
// is caught locally - subsequent function calls would then be attributed
// to a stale ancestor and dead-write attribution would smear across
// unrelated contexts. Correct behavior: after `resume_after_catch`
// returns, the next call to `post_catch_worker` sees the same CCT
// parent as if no exception had happened.
//
// resume_try_marker (inside the try block of resume_after_catch) and
// resume_catch_marker (inside the catch block) both must appear as
// direct children of resume_after_catch, NOT under __cxa_throw.
#include <cstdint>
#include <cstdio>
#define ITERS 2000
static volatile uint64_t sink;
static uint64_t pre_marker[ITERS];
static uint64_t catch_marker[ITERS];
static uint64_t post_marker[ITERS];

extern "C" __attribute__((noinline)) void resume_try_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i;
}
extern "C" __attribute__((noinline)) void resume_catch_marker(int i) {
    __asm__ __volatile__("" ::: "memory"); sink ^= (uint64_t)i << 8;
}

static void may_throw(int i) {
    pre_marker[i] = 0xAAAA;
    if ((i & 1) == 0) throw i;      // half the iters throw
    pre_marker[i] |= 0x00BB0000;    // odd iters skip the throw
}

// Catch locally and return normally (no rethrow).
static void resume_after_catch(int i) {
    try {
        resume_try_marker(i);
        may_throw(i);
    } catch (int v) {
        resume_catch_marker(i);
        catch_marker[i] = (uint64_t)v ^ 0xCCCCCCCC;
    }
    // We land here for BOTH the throw and the non-throw path. cctlib's
    // CCT anchor for this frame must be identical in both cases.
}

// Simple downstream worker: cctlib should attribute these writes to
// the SAME CCT-node ancestor whether or not the try above threw.
static void post_catch_worker(int i) {
    post_marker[i] = ((uint64_t)i * 0x1111ULL) ^ 0xF00DBABE;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    for (int i = 0; i < ITERS; ++i) {
        resume_after_catch(i);
        post_catch_worker(i);
    }
    // Validate. Every iter should have:
    //   pre_marker[i]  = 0xAAAA (even) or 0xAAAA | 0x00BB0000 (odd)
    //   catch_marker[i]= v ^ 0xCCCCCCCC for even (v==i); 0 for odd
    //   post_marker[i] = i*0x1111 ^ 0xF00DBABE for every i
    int ok = 0;
    for (int i = 0; i < ITERS; ++i) {
        uint64_t expected_pre  = (i & 1) ? (0xAAAAULL | 0x00BB0000ULL) : 0xAAAAULL;
        uint64_t expected_catch = (i & 1) ? 0ULL : ((uint64_t)i ^ 0xCCCCCCCCULL);
        uint64_t expected_post = ((uint64_t)i * 0x1111ULL) ^ 0xF00DBABEULL;
        if (pre_marker[i] == expected_pre &&
            catch_marker[i] == expected_catch &&
            post_marker[i] == expected_post) ++ok;
        sink ^= pre_marker[i] ^ catch_marker[i] ^ post_marker[i];
    }
    fprintf(stderr, "exc_catch_and_resume: ok=%d/%d sink=%llx\n",
            ok, ITERS, (unsigned long long)sink);
    return ok == ITERS ? 0 : 1;
}
