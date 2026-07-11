// GoogleTest-driven integration tests for loadspy_client.
//
// Semantics: loadspy reports "redundant loads" -- a load whose value was
// already present in memory (i.e., the same value was already loaded from
// or written to that address by the same-thread execution earlier, with
// no intervening store that could have changed it).
//
// Output format is text; primary summary line is
//     " Total redundant bytes = <pct> %"
// (one per thread; thread 0 first).

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

double parse_first_redundant_pct(const std::string& content) {
    std::regex re(R"(Total redundant bytes = ([\d.]+)\s*%)");
    std::smatch m;
    if (!std::regex_search(content, m, re)) return -1;
    return std::stod(m[1]);
}

class LoadspyIntegration : public ::testing::Test {
  protected:
    std::string root_, tool_;
    void SetUp() override {
        root_ = cctlib_root();
        ASSERT_FALSE(pin_root().empty()) << "PIN_ROOT required";
        tool_ = root_ + "/clients/obj-intel64/loadspy_client.so";
        ASSERT_EQ(0, access(tool_.c_str(), F_OK)) << tool_ << " missing";
        ASSERT_EQ(0, chdir(root_.c_str())) << "chdir failed";
    }
    // loadspy writes its output file with prefix "redLoad.out." (a
    // historical artefact from RedSpy's shared codebase).
    double run_and_parse_pct(const std::string& victim) {
        cleanup(root_, "redLoad.out.");
        int rc = run_pin(tool_, {victim});
        EXPECT_EQ(0, rc) << "loadspy on " << victim << " returned " << rc;
        std::string out = find_newest(root_, "redLoad.out.");
        EXPECT_FALSE(out.empty()) << "no redLoad.out.* file";
        return parse_first_redundant_pct(read_file(out));
    }
};

TEST_F(LoadspyIntegration, RunsCleanlyOnLs) {
    double pct = run_and_parse_pct("/bin/ls");
    ASSERT_GE(pct, 0.0);
    EXPECT_LT(pct, 100.0);
}

// TP has 100000 * 8 = 800KB of workload redundant loads; TN has zero
// (the intervening store kills the redundancy).
//
// Design note on the low threshold: loadspy's percentage is over the
// TOTAL load traffic, and libc's own load traffic dominates. Every extra
// workload load also grows the denominator, so bigger workload does not
// linearly raise the percentage. Empirically TP-TN sits around 0.7-1.5
// percentage points; +0.3% is a floor that clearly signals workload but
// leaves margin for system variance.
TEST_F(LoadspyIntegration, TruePositiveHigherThanTrueNegative) {
    double tp = run_and_parse_pct(root_ + "/tests/gtest/obj/apps/loadspy_tp_simple");
    double tn = run_and_parse_pct(root_ + "/tests/gtest/obj/apps/loadspy_tn_simple");
    ASSERT_GE(tp, 0.0);
    ASSERT_GE(tn, 0.0);
    EXPECT_GT(tp, tn + 0.3)
        << "TP=" << tp << "% TN=" << tn << "%";
}

// Symbol attribution: the top loadspy report contexts should reference the
// victim's load8 function for the TP victim.
TEST_F(LoadspyIntegration, TPReportAttributesToLoad8) {
    cleanup(root_, "redLoad.out.");
    int rc = run_pin(tool_, {root_ + "/tests/gtest/obj/apps/loadspy_tp_simple"});
    ASSERT_EQ(0, rc);
    std::string out = find_newest(root_, "redLoad.out.");
    ASSERT_FALSE(out.empty());
    std::string cmd = "grep -c 'load8:.*loadspy_tp_simple.c' " + out;
    FILE* p = popen(cmd.c_str(), "r");
    ASSERT_NE(p, nullptr);
    char buf[64]; std::string s;
    if (fgets(buf, sizeof(buf), p)) s = buf;
    pclose(p);
    long hits = s.empty() ? 0 : std::stol(s);
    EXPECT_GT(hits, 0);
}

// ------------------------------------------------------------------
// ISA breadth: SIMD loads and rep-movsq. Each victim's workload issues
// repeated identical loads from the same address; loadspy should classify
// the second (and subsequent) as redundant. Attribution test: the report
// mentions the victim's source file for the load context.

class LoadspyIsa : public LoadspyIntegration,
                   public ::testing::WithParamInterface<const char*> {};

// The workload's redundant-load contribution should elevate the report's
// percentage above the TN baseline. Threshold intentionally low because
// loadspy denominators include libc load traffic, which is large.
TEST_P(LoadspyIsa, ExceedsBaseline) {
    double tn = run_and_parse_pct(root_ + "/tests/gtest/obj/apps/loadspy_tn_simple");
    double isa = run_and_parse_pct(root_ + "/tests/gtest/obj/apps/isa/" + std::string(GetParam()));
    ASSERT_GE(tn, 0.0);
    ASSERT_GE(isa, 0.0);
    EXPECT_GT(isa, tn + 0.3)
        << "victim=" << GetParam() << " isa=" << isa << "% tn=" << tn << "%";
}

// Attribution: report should reference the victim's source file.
TEST_P(LoadspyIsa, AttributionInReport) {
    cleanup(root_, "redLoad.out.");
    int rc = run_pin(tool_, {root_ + "/tests/gtest/obj/apps/isa/" + std::string(GetParam())});
    ASSERT_EQ(0, rc);
    std::string out = find_newest(root_, "redLoad.out.");
    ASSERT_FALSE(out.empty());
    std::string cmd = std::string("grep -c '") + GetParam() + ".c' " + out;
    FILE* p = popen(cmd.c_str(), "r");
    ASSERT_NE(p, nullptr);
    char buf[64]; std::string s;
    if (fgets(buf, sizeof(buf), p)) s = buf;
    pclose(p);
    long hits = s.empty() ? 0 : std::stol(s);
    EXPECT_GT(hits, 0);
}

INSTANTIATE_TEST_SUITE_P(
    IsaBreadth, LoadspyIsa,
    ::testing::Values(
        "loadspy_sse16_tp",       // 128-bit SIMD load
        "loadspy_avx32_tp",       // 256-bit SIMD load
        "loadspy_repmovs_tp",     // rep movsq -- string load+store
        "loadspy_cross_page_tp",  // qword load straddling a 4KB page boundary
        "loadspy_mixed_widths_tp" // 8B load then 2x 4B load covering same 8B
        ),
    [](const testing::TestParamInfo<const char*>& info) {
        return std::string(info.param);
    });

}  // namespace
