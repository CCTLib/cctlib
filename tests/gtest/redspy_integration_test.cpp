// GoogleTest-driven integration tests for redspy_client.
//
// Semantics: redspy reports "redundant writes" -- stores whose value is
// identical to the value already in memory at the target location. The
// output format is text; the primary summary line is
//    " Total redundant bytes = <pct> %"
// (leading space; note that the summary is emitted once per instrumented
// thread, and thread 0 is the process's main thread).
//
// Test design: build small victim programs that either (TP) write the same
// value twice to the same location or (TN) write different values, then
// compare the redundancy percentage. TP should be strictly higher than TN,
// with a margin well above the ~few percent noise from libc startup.

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

// Parses the FIRST "Total redundant bytes = <pct> %" line (thread 0's
// summary). Returns -1 if not present.
double parse_first_redundant_pct(const std::string& content) {
    std::regex re(R"(Total redundant bytes = ([\d.]+)\s*%)");
    std::smatch m;
    if (!std::regex_search(content, m, re)) return -1;
    return std::stod(m[1]);
}

class RedspyIntegration : public ::testing::Test {
  protected:
    std::string root_;
    std::string tool_;
    void SetUp() override {
        root_ = cctlib_root();
        ASSERT_FALSE(pin_root().empty()) << "PIN_ROOT required";
        tool_ = root_ + "/clients/obj-intel64/redspy_client.so";
        ASSERT_EQ(0, access(tool_.c_str(), F_OK)) << tool_ << " missing";
        ASSERT_EQ(0, chdir(root_.c_str())) << "chdir failed";
    }
    // Returns the redundant-bytes percentage from thread-0's summary.
    double run_and_parse_pct(const std::string& victim) {
        cleanup(root_, "redspy.out.");
        int rc = run_pin(tool_, {victim});
        EXPECT_EQ(0, rc) << "redspy on " << victim << " returned " << rc;
        std::string out = find_newest(root_, "redspy.out.");
        EXPECT_FALSE(out.empty()) << "no redspy.out.* file";
        return parse_first_redundant_pct(read_file(out));
    }
};

// Sanity: redspy runs cleanly on /bin/ls.
TEST_F(RedspyIntegration, RunsCleanlyOnLs) {
    double pct = run_and_parse_pct("/bin/ls");
    ASSERT_GE(pct, 0.0);      // format present -- may be 0 if nothing redundant
    EXPECT_LT(pct, 100.0);    // sanity
}

// TP vs TN: writes the same value vs writes different values.
// TP victim's workload alone is ~10K pair-writes of the same value; TN
// victim's workload has zero same-value pairs from its workload.
// Startup noise adds a few percent redundant bytes in both; the WORKLOAD
// difference should be clearly visible.
TEST_F(RedspyIntegration, TruePositiveHigherThanTrueNegative) {
    double tp = run_and_parse_pct(root_ + "/tests/gtest/obj/apps/redspy_tp_simple");
    double tn = run_and_parse_pct(root_ + "/tests/gtest/obj/apps/redspy_tn_simple");
    ASSERT_GE(tp, 0.0);
    ASSERT_GE(tn, 0.0);
    // TP: 10000 pairs of 8B same-value writes = 80000 redundant bytes.
    // Baseline libc redundancy is ~40% and each victim writes roughly the
    // same volume, so TP-pct should exceed TN-pct by at least a few
    // percentage points from workload alone.
    EXPECT_GT(tp, tn + 2.0)
        << "TP=" << tp << "% TN=" << tn << "% -- expected TP > TN + 2%";
}

// Multi-size TP should also exceed TN.
TEST_F(RedspyIntegration, MultiSizeTruePositiveExceedsTN) {
    double tp = run_and_parse_pct(root_ + "/tests/gtest/obj/apps/redspy_tp_sizes");
    double tn = run_and_parse_pct(root_ + "/tests/gtest/obj/apps/redspy_tn_simple");
    ASSERT_GE(tp, 0.0);
    ASSERT_GE(tn, 0.0);
    EXPECT_GT(tp, tn + 2.0) << "TP-sizes=" << tp << "% TN=" << tn << "%";
}

// Symbol attribution: the top redspy report contexts should reference the
// victim's store8 function for the TP victim.
TEST_F(RedspyIntegration, TPReportAttributesToStore8) {
    cleanup(root_, "redspy.out.");
    int rc = run_pin(tool_, {root_ + "/tests/gtest/obj/apps/redspy_tp_simple"});
    ASSERT_EQ(0, rc);
    std::string out = find_newest(root_, "redspy.out.");
    ASSERT_FALSE(out.empty());
    std::string cmd = "grep -c 'store8:.*redspy_tp_simple.c' " + out;
    FILE* p = popen(cmd.c_str(), "r");
    ASSERT_NE(p, nullptr);
    char buf[64]; std::string s;
    if (fgets(buf, sizeof(buf), p)) s = buf;
    pclose(p);
    long hits = s.empty() ? 0 : std::stol(s);
    EXPECT_GT(hits, 0)
        << "redspy report has no context mentioning store8 in redspy_tp_simple.c";
}

// ------------------------------------------------------------------
// ISA breadth tests. Each victim writes the SAME value TWICE to the same
// address via a different instruction class. Every second write is
// redundant. We assert each ISA victim's redundancy percentage exceeds
// the TN-simple baseline (which has zero workload-attributable
// redundancy) by a healthy margin.

struct RedspyIsaVictim { const char* name; double min_extra_pct; };

class RedspyIsa : public RedspyIntegration,
                  public ::testing::WithParamInterface<RedspyIsaVictim> {};

TEST_P(RedspyIsa, ExceedsBaseline) {
    double tn = run_and_parse_pct(root_ + "/tests/gtest/obj/apps/redspy_tn_simple");
    double isa = run_and_parse_pct(root_ + "/tests/gtest/obj/apps/isa/" + GetParam().name);
    ASSERT_GE(tn, 0.0);
    ASSERT_GE(isa, 0.0);
    EXPECT_GT(isa - tn, GetParam().min_extra_pct)
        << "victim=" << GetParam().name
        << " isa-pct=" << isa
        << "% tn-pct=" << tn
        << "% threshold=" << GetParam().min_extra_pct;
}

INSTANTIATE_TEST_SUITE_P(
    IsaBreadth, RedspyIsa,
    ::testing::Values(
        // 128-bit same-value stores (movdqa xmm, mem twice).
        RedspyIsaVictim{"redspy_sse16_tp",                    2.0},
        // 256-bit same-value stores (vmovdqu ymm, mem twice).
        RedspyIsaVictim{"redspy_avx32_tp",                    2.0},
        // 32-bit same-immediate stores.
        RedspyIsaVictim{"redspy_immediate_tp",                1.0},
        // Partial overlap where the byte value matches the qword's low byte.
        RedspyIsaVictim{"redspy_partial_qword_then_byte_tp",  0.3},
        // SIMD zero-fill of the same 16 bytes twice (pxor + movdqu twice).
        // Real-world memset-then-memset-again pattern.
        RedspyIsaVictim{"redspy_zero_fill_tp",                2.0},
        // Scalar SSE movsd (8B FP scalar move) same value twice.
        RedspyIsaVictim{"redspy_scalar_sse_tp",               1.0},
        // Cross-page same-value 8B write. Straddles a 4KB boundary --
        // exercises redspy's cross-boundary shadow bookkeeping.
        RedspyIsaVictim{"redspy_cross_page_tp",               0.5}),
    [](const testing::TestParamInfo<RedspyIsaVictim>& info) {
        return info.param.name;
    });

}  // namespace
