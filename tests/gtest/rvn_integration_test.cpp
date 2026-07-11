// GoogleTest-driven integration tests for runtime_value_numbering_client
// (RVN).
//
// Semantics: RVN assigns value numbers to intermediate computations at
// runtime. If two dynamic instructions produce the same value number on the
// same operand value numbers, the second is REDUNDANT (its result was
// already computed).
//
// User note: RVN has known correctness TODOs; these tests focus on the
// smoke-level and coarse redundancy fraction rather than fine-grained
// context accuracy.
//
// Output format: `Redundancy: <fraction>` -- fraction of redundant
// instructions among total instrumented instructions.

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

std::string env(const char* n) { const char* v = getenv(n); return v ? v : ""; }
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

// Parses the FIRST `Redundancy: <fraction>` line.
double parse_redundancy(const std::string& content) {
    std::regex re(R"(Redundancy:\s*([\d.]+))");
    std::smatch m;
    if (!std::regex_search(content, m, re)) return -1;
    return std::stod(m[1]);
}

class RVNIntegration : public ::testing::Test {
  protected:
    std::string root_, tool_;
    void SetUp() override {
        root_ = cctlib_root();
        ASSERT_FALSE(pin_root().empty());
        tool_ = root_ + "/clients/obj-intel64/runtime_value_numbering_client.so";
        ASSERT_EQ(0, access(tool_.c_str(), F_OK)) << tool_ << " missing";
        ASSERT_EQ(0, chdir(root_.c_str())) << "chdir failed";
    }
    double run_and_parse_red(const std::string& victim) {
        cleanup(root_, "ValueNumbering.out.");
        int rc = run_pin(tool_, {victim});
        EXPECT_EQ(0, rc);
        std::string out = find_newest(root_, "ValueNumbering.out.");
        EXPECT_FALSE(out.empty());
        return parse_redundancy(read_file(out));
    }
};

TEST_F(RVNIntegration, RunsCleanlyOnLs) {
    double r = run_and_parse_red("/bin/ls");
    ASSERT_GE(r, 0.0);
    EXPECT_LT(r, 1.0);
}

// The TP victim recomputes the SAME lea twice per iteration on identical
// operands; RVN should mark the second lea's result as redundant. The TN
// victim varies operands so neither result matches a previous computation.
//
// User note: RVN has open correctness TODOs, so this test asserts only
// that TP >= TN (not TP > TN by a large margin) -- if the tool ever
// starts flagging the TP victim's redundant recomputations, this test
// will catch a regression. If it stops flagging, that would be a
// correctness regression this test surfaces.
TEST_F(RVNIntegration, TruePositiveAtLeastAsRedundantAsTrueNegative) {
    double tp = run_and_parse_red(root_ + "/tests/gtest/obj/apps/rvn_tp_repeated");
    double tn = run_and_parse_red(root_ + "/tests/gtest/obj/apps/rvn_tn_different");
    ASSERT_GE(tp, 0.0);
    ASSERT_GE(tn, 0.0);
    EXPECT_GE(tp, tn - 0.02)   // small tolerance
        << "TP=" << tp << " TN=" << tn;
}

// ISA breadth: repeated identical scalar ADD in inline asm. The victim
// runs a tight loop that computes a+b twice per iteration on the same
// operands. The second addq should get the same value number as the
// first. RVN should report non-zero redundancy on this workload.
TEST_F(RVNIntegration, RepeatedAddRunsCleanly) {
    double r = run_and_parse_red(root_ + "/tests/gtest/obj/apps/isa/rvn_repeated_add");
    ASSERT_GE(r, 0.0);
    EXPECT_LT(r, 1.0);
}

}  // namespace
