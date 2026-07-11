// GoogleTest-driven integration tests for footprint_client.
//
// Semantics: footprint_client measures how many DISTINCT memory addresses
// each context touches. A program that spins on a single address should
// report a small footprint; one that sweeps over N unique addresses should
// report a footprint proportional to N.
//
// Output format is text; the first "Footprint is <N>," line following the
// per-thread header is the top-of-stack context (ROOT), and its value is
// the whole-thread total.

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

// Parses the FIRST "Footprint is <N>" line -- that's the whole-thread root
// context total.
long parse_first_footprint(const std::string& content) {
    std::regex re(R"(Footprint is (\d+))");
    std::smatch m;
    if (!std::regex_search(content, m, re)) return -1;
    return std::stol(m[1]);
}

class FootprintIntegration : public ::testing::Test {
  protected:
    std::string root_, tool_;
    void SetUp() override {
        root_ = cctlib_root();
        ASSERT_FALSE(pin_root().empty());
        tool_ = root_ + "/clients/obj-intel64/footprint_client.so";
        ASSERT_EQ(0, access(tool_.c_str(), F_OK)) << tool_ << " missing";
        ASSERT_EQ(0, chdir(root_.c_str())) << "chdir failed";
    }
    long run_and_parse_footprint(const std::string& victim) {
        cleanup(root_, "client.out.");
        int rc = run_pin(tool_, {victim});
        EXPECT_EQ(0, rc) << "footprint on " << victim << " returned " << rc;
        std::string out = find_newest(root_, "client.out.");
        EXPECT_FALSE(out.empty()) << "no client.out.* file";
        return parse_first_footprint(read_file(out));
    }
};

TEST_F(FootprintIntegration, RunsCleanlyOnLs) {
    long fp = run_and_parse_footprint("/bin/ls");
    ASSERT_GE(fp, 0);
    EXPECT_GT(fp, 0);
}

// The large-footprint victim sweeps over 100000 unique 8-byte addresses;
// the small victim touches one 8-byte address 100000 times. The large
// victim's whole-thread footprint should be at least 50000 more distinct
// addresses than the small victim's.
TEST_F(FootprintIntegration, LargeFootprintExceedsSmall) {
    long large = run_and_parse_footprint(root_ + "/tests/gtest/obj/apps/footprint_large");
    long small = run_and_parse_footprint(root_ + "/tests/gtest/obj/apps/footprint_small");
    ASSERT_GE(large, 0);
    ASSERT_GE(small, 0);
    // Both share the same libc startup; the WORKLOAD contribution is
    // 100000 vs 1 unique addresses. Assert large > small + 50000 (leaves
    // headroom for startup variance).
    EXPECT_GT(large - small, 50000)
        << "large=" << large << " small=" << small;
}

// ISA breadth: AVX 32-byte store stride sweep. The victim writes 32 bytes
// per iteration to a fresh 32-byte cacheline; footprint should scale with
// 100000 unique cachelines touched * 32B each = 3.2 M distinct bytes.
// The footprint metric returned by the tool is byte-granular; assert the
// SIMD sweep's footprint materially exceeds the byte-granular small victim.
TEST_F(FootprintIntegration, AVX32SweepFootprintExceedsSmall) {
    long avx = run_and_parse_footprint(root_ + "/tests/gtest/obj/apps/isa/footprint_avx32_sweep");
    long small = run_and_parse_footprint(root_ + "/tests/gtest/obj/apps/footprint_small");
    ASSERT_GE(avx, 0);
    ASSERT_GE(small, 0);
    // 100000 iters * 32B distinct = 3.2M. Assert avx >= small + 1M
    // (large margin, tolerates footprint aggregation quirks).
    EXPECT_GT(avx - small, 1000000)
        << "avx=" << avx << " small=" << small;
}

}  // namespace
