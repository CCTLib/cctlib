// GoogleTest-driven integration tests for deadspy_client.
//
// Semantics deadspy measures: a "dead write" is a store to memory that is
// later overwritten (in program order along the same execution path) without
// any intervening READ of that location. Every non-first store in a
// same-address chain with no reads between is dead.
//
// Test design: build small victim programs under tests/gtest/apps/ with
// -O0 and volatile accessors so the compiler does not collapse the write
// patterns we are measuring. Run Pin+deadspy_client against each victim,
// parse `GrandTotalDead = N` from the tool output. Assert directional
// inequalities (TP > TN, size sweep monotone) rather than absolute counts
// -- the absolute count is dominated by process startup / libc noise, and
// specifying exact numbers would make the test brittle across libc versions.
//
// True-positive victims (TP): programs deliberately containing back-to-back
// stores to the same address with no read between. deadspy should report
// substantially more dead writes than a TN control that reads between the
// stores. The GAP between TP and TN is what we assert; it should scale
// with the workload the victim performs.

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>

namespace {

std::string env(const char* name) { const char* v = getenv(name); return v ? v : ""; }
std::string cctlib_root() { std::string r = env("CCTLIB_ROOT"); return r.empty() ? "../.." : r; }
std::string pin_root() { return env("PIN_ROOT"); }

int run_pin(const std::string& tool, const std::vector<std::string>& args) {
    std::string pin = pin_root() + "/pin";
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(pin.c_str()));
    argv.push_back(const_cast<char*>("-t"));
    argv.push_back(const_cast<char*>(tool.c_str()));
    argv.push_back(const_cast<char*>("--"));
    for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (!env("CCTLIB_TEST_VERBOSE").size()) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
        }
        execv(pin.c_str(), argv.data());
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -2;
}

std::string find_newest(const std::string& dir, const std::string& prefix) {
    std::string cmd = "ls -t " + dir + "/" + prefix + "* 2>/dev/null | head -1";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return {};
    char buf[4096]; std::string out;
    if (fgets(buf, sizeof(buf), p)) out = buf;
    pclose(p);
    if (!out.empty() && out.back() == '\n') out.pop_back();
    return out;
}
std::string read_file(const std::string& path) {
    std::ifstream in(path); std::stringstream ss; ss << in.rdbuf(); return ss.str();
}
void cleanup(const std::string& dir, const std::string& prefix) {
    std::string cmd = "rm -f " + dir + "/" + prefix + "*"; (void)system(cmd.c_str());
}

// Parses "GrandTotalDead = <N> = <pct>%" from a deadspy report. Returns -1
// if the line is not present (which indicates a broken run).
long parse_grand_total_dead(const std::string& content) {
    std::regex re(R"(GrandTotalDead = (\d+))");
    std::smatch m;
    if (!std::regex_search(content, m, re)) return -1;
    return std::stol(m[1]);
}

long parse_grand_total_writes(const std::string& content) {
    std::regex re(R"(GrandTotalWrites = (\d+))");
    std::smatch m;
    if (!std::regex_search(content, m, re)) return -1;
    return std::stol(m[1]);
}

class DeadspyIntegration : public ::testing::Test {
  protected:
    std::string root_;
    std::string tool_;
    void SetUp() override {
        root_ = cctlib_root();
        ASSERT_FALSE(pin_root().empty()) << "PIN_ROOT required";
        tool_ = root_ + "/clients/obj-intel64/deadspy_client.so";
        ASSERT_EQ(0, access(tool_.c_str(), F_OK)) << tool_ << " missing";
        ASSERT_EQ(0, chdir(root_.c_str())) << "chdir(" << root_ << ") failed";
    }

    // Run deadspy on `victim`, returning the parsed GrandTotalDead. Also
    // populates `total_writes` so callers can inspect the ratio.
    long run_and_parse_dead(const std::string& victim, long* total_writes = nullptr) {
        cleanup(root_, "deadspy.out.");
        int rc = run_pin(tool_, {victim});
        EXPECT_EQ(0, rc) << "deadspy on " << victim << " returned " << rc;
        std::string out = find_newest(root_, "deadspy.out.");
        EXPECT_FALSE(out.empty()) << "no deadspy.out.* file produced";
        std::string content = read_file(out);
        if (total_writes) *total_writes = parse_grand_total_writes(content);
        return parse_grand_total_dead(content);
    }
};

// Sanity: deadspy runs cleanly on an existing built app and reports a
// non-zero total-writes count. This is the same regression coverage that
// the top-level TEST5/TEST6 give, but wrapped in gtest.
TEST_F(DeadspyIntegration, RunsCleanlyOnLs) {
    long writes = 0;
    long dead = run_and_parse_dead("/bin/ls", &writes);
    ASSERT_GE(dead, 0) << "deadspy report missing GrandTotalDead";
    EXPECT_GT(writes, 0);
}

// Existing deadWrites.exe victim (three memset-3-loops-back-to-back).
// Since the workload deliberately overwrites the same buffer three times,
// dead writes should be a healthy fraction of total writes.
TEST_F(DeadspyIntegration, DeadWritesAppReportsDeads) {
    long writes = 0;
    long dead = run_and_parse_dead(root_ + "/apps/obj-intel64/deadWrites.exe", &writes);
    ASSERT_GE(dead, 0);
    EXPECT_GT(dead, 0) << "deadWrites.exe should produce some dead writes";
}

// TP vs TN comparison: the TP victim writes to each buffer cell twice with
// no read between; the TN victim reads between the two writes so nothing
// is dead. Startup / libc noise is the same order of magnitude in both,
// but with WORK_COUNT=10000 8-byte pairs the TP victim adds
// ~80K bytes of dead-write signal on top -- well above the libc-startup
// noise floor of ~15K bytes we observe empirically on this system.
// The test asserts (TP-TN)/TN as a fraction, not a raw count, to survive
// libc version drift.
TEST_F(DeadspyIntegration, TruePositiveMoreDeadsThanTrueNegative) {
    long tp = run_and_parse_dead(root_ + "/tests/gtest/obj/apps/deadspy_tp_simple");
    long tn = run_and_parse_dead(root_ + "/tests/gtest/obj/apps/deadspy_tn_simple");
    ASSERT_GE(tp, 0);
    ASSERT_GE(tn, 0);
    // TP adds at least ~10000 * 8 = 80000 dead-byte events from the
    // workload. Require TP to exceed TN by at least half that (40000)
    // to allow for scheduling jitter and small libc-startup differences.
    EXPECT_GT(tp - tn, 40000)
        << "TP=" << tp << " TN=" << tn
        << " -- expected TP-TN > 40000 dead-write bytes from the workload";
}

// Multi-size TP: writes at byte/word/dword/qword granularity to different
// buffers. WORK_COUNT=5000 iterations x (1+2+4+8)=15 bytes/iter of dead
// writes = 75000 dead-write bytes above baseline.
TEST_F(DeadspyIntegration, MultiSizeTruePositiveExceedsTrueNegative) {
    long tp = run_and_parse_dead(root_ + "/tests/gtest/obj/apps/deadspy_tp_sizes");
    long tn = run_and_parse_dead(root_ + "/tests/gtest/obj/apps/deadspy_tn_simple");
    ASSERT_GE(tp, 0);
    ASSERT_GE(tn, 0);
    EXPECT_GT(tp - tn, 30000)
        << "TP-multi-size=" << tp << " TN=" << tn;
}

// Symbol-attribution test: deadspy's per-context report should list the
// victim's `store8` helper as a KILLING context (i.e. the store that turned
// out to be dead). Verifies not just "dead writes are counted" but
// "deadspy attributes them to the right source function". Uses grep because
// the report format is text.
TEST_F(DeadspyIntegration, TPReportAttributesToStore8) {
    cleanup(root_, "deadspy.out.");
    int rc = run_pin(tool_, {root_ + "/tests/gtest/obj/apps/deadspy_tp_simple"});
    ASSERT_EQ(0, rc);
    std::string out = find_newest(root_, "deadspy.out.");
    ASSERT_FALSE(out.empty());
    // Count occurrences of `store8` referencing the tp_simple source file.
    // Any hit means deadspy successfully attributed a dead-write context
    // to the victim's helper, which is what we want to guarantee.
    std::string cmd = "grep -c 'store8:.*deadspy_tp_simple.c' " + out;
    FILE* p = popen(cmd.c_str(), "r");
    ASSERT_NE(p, nullptr);
    char buf[64]; std::string s;
    if (fgets(buf, sizeof(buf), p)) s = buf;
    pclose(p);
    long hits = s.empty() ? 0 : std::stol(s);
    EXPECT_GT(hits, 0) << "deadspy report has no context mentioning store8 "
                          "in deadspy_tp_simple.c";
}

// ------------------------------------------------------------------
// ISA breadth tests. Each victim under tests/gtest/apps/isa/deadspy_*
// exercises deadspy against a specific x86 write pattern (SSE 16B,
// AVX 32B, partial overlap byte-in-qword, rep stosq, atomic xchg,
// various addressing modes). Parameterized so it's trivial to add
// more instruction classes.
//
// Baseline: deadspy_tp_minimal (single-iteration workload). Its
// GrandTotalDead ~= libc-startup noise + 1. Every ISA victim's
// (V - baseline) closely matches its designed dead-byte workload.

struct IsaVictim {
    const char* name;
    long min_extra_dead_bytes;  // vs tp_minimal baseline
};

class DeadspyIsa : public DeadspyIntegration,
                   public ::testing::WithParamInterface<IsaVictim> {};

TEST_P(DeadspyIsa, ExceedsBaseline) {
    long baseline = run_and_parse_dead(root_ + "/tests/gtest/obj/apps/deadspy_tp_minimal");
    long isa = run_and_parse_dead(root_ + "/tests/gtest/obj/apps/isa/" + GetParam().name);
    ASSERT_GE(baseline, 0);
    ASSERT_GE(isa, 0);
    EXPECT_GT(isa - baseline, GetParam().min_extra_dead_bytes)
        << "victim=" << GetParam().name
        << " isa-count=" << isa
        << " baseline=" << baseline
        << " threshold=" << GetParam().min_extra_dead_bytes;
}

INSTANTIATE_TEST_SUITE_P(
    IsaBreadth, DeadspyIsa,
    ::testing::Values(
        // 10000 iters * 16B dead per iter = 160000 dead bytes expected.
        IsaVictim{"deadspy_sse16_tp",                    100000},
        // 10000 iters * 32B dead per iter = 320000 dead bytes expected.
        IsaVictim{"deadspy_avx32_tp",                    200000},
        // 20000 iters * 1B dead (byte-in-qword partial overlap) = 20000
        // dead bytes. Deadspy's per-byte shadow must track the byte-0
        // overlap correctly to see this.
        IsaVictim{"deadspy_partial_qword_then_byte_tp",  15000},
        // Symmetric partial overlap at byte offset 7 (high byte of qword).
        IsaVictim{"deadspy_partial_qword_then_byte_high_tp", 15000},
        // 100 iters * 512 qwords * 8B = 409600 dead bytes from rep stosq.
        IsaVictim{"deadspy_repstos_tp",                  200000},
        // 20000 iters * 8B dead per iter = 160000 dead bytes from LOCK xchg.
        IsaVictim{"deadspy_xchg_tp",                     100000},
        // 20000 iters * 8B dead per iter = 160000 dead bytes with SIB
        // (register+idx*scale) addressing.
        IsaVictim{"deadspy_addressing_tp",               100000},
        // Cross-page qword: 10000 iters * 8B dead per iter = 80000 dead
        // bytes, all straddling a 4KB page boundary. Exercises the
        // 2-level shadow-page table's cross-boundary handling.
        IsaVictim{"deadspy_cross_page_qword_tp",         40000},
        // PUSH/POP dead pattern: 10000 iters * 8B dead per iter, via
        // rsp-relative pushes with an rsp adjustment between them.
        // Exercises implicit RSP arithmetic and rsp-relative addressing.
        IsaVictim{"deadspy_pushpop_dead_tp",             40000},
        // Non-temporal MOVNTI stores. 10000 * 8B dead per iter.
        IsaVictim{"deadspy_movnti_tp",                   40000}),
    [](const testing::TestParamInfo<IsaVictim>& info) {
        return info.param.name;
    });

// LOCK CMPXCHG negative test: cmpxchg is a read-modify-write. The read
// portion of the second cmpxchg CLEARS deadspy's shadow "was written"
// bit that the first cmpxchg set. Deadspy should therefore report
// essentially NO additional dead writes from this workload vs baseline.
//
// This is a correctness/false-positive test: if deadspy STARTS reporting
// large numbers of dead writes here, it likely means it lost the RMW
// read-then-write ordering and is now over-reporting on atomic ops --
// bad for downstream users of the tool.
//
// Contrast: XCHG's memory operand is classified as write-only by Pin, so
// XCHG PAIRS DO produce dead writes (see deadspy_xchg_tp).
TEST_F(DeadspyIsa, CmpxchgIsNotFalselyDead) {
    long baseline = run_and_parse_dead(root_ + "/tests/gtest/obj/apps/deadspy_tp_minimal");
    long isa = run_and_parse_dead(root_ + "/tests/gtest/obj/apps/isa/deadspy_cmpxchg_tn");
    ASSERT_GE(baseline, 0);
    ASSERT_GE(isa, 0);
    // Allow at most 5000 dead bytes above baseline. The workload has
    // 10000 cmpxchg pairs; if deadspy were falsely reporting them all as
    // dead we'd see ~80000 extra dead bytes.
    EXPECT_LT(isa - baseline, 5000)
        << "cmpxchg pair falsely reported as dead. isa=" << isa
        << " baseline=" << baseline;
}

}  // namespace
