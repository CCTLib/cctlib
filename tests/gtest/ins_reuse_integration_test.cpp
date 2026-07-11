// GoogleTest-driven integration tests for ins_reuse_client.
//
// Semantics: for each dynamic instruction execution, the tool measures
// the reuse distance -- how many other instructions executed since the
// LAST time this same instruction ran. The output is a per-thread
// histogram binned in log2 buckets.

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

// Extracts the ins_reuse histogram from the report as a bin->count map.
// Ignores per-cacheline sub-histograms, just returns the first "TID 0
// instruction-reuse histo" block.
std::vector<double> parse_histogram(const std::string& content) {
    std::vector<double> bins;
    std::regex header(R"(TID \d+ instruction-reuse histo)");
    std::smatch m;
    if (!std::regex_search(content, m, header)) return bins;
    std::string tail = content.substr(m.position() + m.length());
    // Match lines like "  3 3.089300e+04 (16.89%)"
    std::regex row(R"(\s*(\d+)\s+([\d.]+e[+\-]\d+))");
    auto begin = std::sregex_iterator(tail.begin(), tail.end(), row);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        size_t idx = std::stoul((*it)[1]);
        double val = std::stod((*it)[2]);
        if (bins.size() <= idx) bins.resize(idx + 1, 0.0);
        bins[idx] = val;
        // Stop after ~32 rows so we don't slurp the next histogram.
        if (bins.size() >= 32) break;
    }
    return bins;
}

class InsReuseIntegration : public ::testing::Test {
  protected:
    std::string root_, tool_;
    void SetUp() override {
        root_ = cctlib_root();
        ASSERT_FALSE(pin_root().empty());
        tool_ = root_ + "/clients/obj-intel64/ins_reuse_client.so";
        ASSERT_EQ(0, access(tool_.c_str(), F_OK)) << tool_ << " missing";
        ASSERT_EQ(0, chdir(root_.c_str())) << "chdir failed";
    }
    std::vector<double> run_and_parse(const std::string& victim) {
        cleanup(root_, "insReuse.out.");
        int rc = run_pin(tool_, {victim});
        EXPECT_EQ(0, rc);
        std::string out = find_newest(root_, "insReuse.out.");
        EXPECT_FALSE(out.empty());
        return parse_histogram(read_file(out));
    }
};

TEST_F(InsReuseIntegration, RunsCleanlyOnLs) {
    auto h = run_and_parse("/bin/ls");
    long total = 0;
    for (auto v : h) total += (long)v;
    EXPECT_GT(total, 0);
}

// The tight 3-instruction inline-asm loop (add / sub / jnz -- 3 real
// instructions per iteration) should have its dominant reuse-distance bin
// at a small distance. Every one of the 3 loop instructions is re-executed
// after distance 3, which falls in bin 2 ( covers [2,4) ) or bin 3
// ( covers [4,8) ) depending on how the tool counts.
//
// Assert that: the sum of low bins (0..4) accounts for the VAST majority
// of the histogram mass on this workload -- MUCH more than mid/high bins.
TEST_F(InsReuseIntegration, TightLoopFillsLowBins) {
    auto h = run_and_parse(root_ + "/tests/gtest/obj/apps/ins_reuse_tight_loop");
    ASSERT_FALSE(h.empty()) << "no histogram parsed";
    double low = 0.0, mid = 0.0;
    for (size_t i = 0; i < h.size(); ++i) {
        if (i <= 4) low += h[i];
        else if (i <= 12) mid += h[i];
    }
    EXPECT_GT(low, mid)
        << "low-bin mass=" << low << " mid-bin mass=" << mid;
    // And the total workload should be very large -- ~3 * 1e6 executions.
    double total = 0.0;
    for (auto v : h) total += v;
    EXPECT_GT(total, 1e6);
}

// ISA breadth: same tight-loop shape but with SIMD (vpaddq %ymm0, %ymm0,
// %ymm0) inside. Verifies ins_reuse correctly instruments and counts SIMD
// instructions in its reuse histogram (should also fill low bins).
TEST_F(InsReuseIntegration, SimdLoopFillsLowBins) {
    auto h = run_and_parse(root_ + "/tests/gtest/obj/apps/isa/ins_reuse_simd_loop");
    ASSERT_FALSE(h.empty()) << "no histogram parsed";
    double low = 0.0, mid = 0.0;
    for (size_t i = 0; i < h.size(); ++i) {
        if (i <= 4) low += h[i];
        else if (i <= 12) mid += h[i];
    }
    EXPECT_GT(low, mid)
        << "low-bin mass=" << low << " mid-bin mass=" << mid;
    double total = 0.0;
    for (auto v : h) total += v;
    EXPECT_GT(total, 1e6);
}

}  // namespace
