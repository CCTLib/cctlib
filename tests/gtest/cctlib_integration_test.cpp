// GoogleTest-driven integration tests for cctlib itself and the CCT-oriented
// test tools in tests/ (cct_client, cct_data_centric_client, cctlib_reader).
//
// These tests spawn Pin as a subprocess against the built tool .so files
// and the built victim executables, then parse the tool's output file.
// They complement the unit tests (which exercise data-structure invariants
// without Pin) with actual end-to-end runs.
//
// Environment:
//   PIN_ROOT  -- Pin install root (required)
//   CCTLIB_ROOT -- repo root (auto-derived from build directory if unset)

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>

namespace {

// Returns the value of env var `name` or empty string.
std::string env(const char* name) {
    const char* v = getenv(name);
    return v ? v : "";
}

// Resolve the CCTLib repo root. Set by the Makefile via CCTLIB_ROOT env var
// on the test invocation; falls back to walking up from CWD to find a
// characteristic file.
std::string cctlib_root() {
    std::string r = env("CCTLIB_ROOT");
    if (!r.empty()) return r;
    // Fallback: assume we're in tests/gtest and repo root is two levels up.
    return "../..";
}

std::string pin_root() {
    std::string r = env("PIN_ROOT");
    return r;
}

// Run Pin with (tool, argv...) and wait. Returns the child's exit code, or
// negative on spawn failure. stdout/stderr go to /dev/null unless
// CCTLIB_TEST_VERBOSE is set.
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
            if (devnull >= 0) {
                dup2(devnull, 1);
                dup2(devnull, 2);
                close(devnull);
            }
        }
        execv(pin.c_str(), argv.data());
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -2;
}

// Find the newest file whose name starts with `prefix` in `dir`. Empty
// string if none. Deterministic when only one such file exists (typical
// after `rm -f prefix*` before the test).
std::string find_newest(const std::string& dir, const std::string& prefix) {
    std::string cmd = "ls -t " + dir + "/" + prefix + "* 2>/dev/null | head -1";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return {};
    char buf[4096];
    std::string out;
    if (fgets(buf, sizeof(buf), p)) out = buf;
    pclose(p);
    if (!out.empty() && out.back() == '\n') out.pop_back();
    return out;
}

std::string read_file(const std::string& path) {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Cleans stale output files that the tools would otherwise pick up.
void cleanup(const std::string& dir, const std::string& prefix) {
    std::string cmd = "rm -f " + dir + "/" + prefix + "*";
    (void)system(cmd.c_str());
}

class CCTLibIntegration : public ::testing::Test {
  protected:
    std::string root_;
    void SetUp() override {
        root_ = cctlib_root();
        ASSERT_FALSE(pin_root().empty())
            << "PIN_ROOT environment variable required for integration tests";
        ASSERT_EQ(0, access((root_ + "/tests/obj-intel64/cct_client.so").c_str(), F_OK))
            << "tests/obj-intel64/cct_client.so missing; run `make` first";
        // Pin tools write their output file (client.out.*, deadspy.out.*)
        // to CWD. chdir to the repo root so cleanup() and find_newest()
        // agree with the tools on where to look.
        ASSERT_EQ(0, chdir(root_.c_str())) << "chdir(" << root_ << ") failed";
    }
};

// The vanilla cct_client should complete cleanly on a trivial target and
// produce a non-empty output file whose "Total call paths" line is > 0.
TEST_F(CCTLibIntegration, CctClientRunsCleanly) {
    cleanup(root_, "client.out.");
    int rc = run_pin(root_ + "/tests/obj-intel64/cct_client.so", {"/bin/echo", "hi"});
    ASSERT_EQ(0, rc) << "cct_client on /bin/echo returned " << rc;
    std::string outfile = find_newest(root_, "client.out.");
    ASSERT_FALSE(outfile.empty()) << "no client.out.* produced";
    std::string content = read_file(outfile);
    std::regex re(R"(Total call paths=(\d+))");
    std::smatch m;
    ASSERT_TRUE(std::regex_search(content, m, re))
        << "output missing Total call paths= line; content:\n" << content;
    long paths = std::stol(m[1]);
    EXPECT_GT(paths, 0);
}

// cct_client_mem_only: same expectation.
TEST_F(CCTLibIntegration, CctClientMemOnlyRunsCleanly) {
    cleanup(root_, "client.out.");
    int rc = run_pin(root_ + "/tests/obj-intel64/cct_client_mem_only.so",
                     {"/bin/echo", "hi"});
    ASSERT_EQ(0, rc);
    std::string outfile = find_newest(root_, "client.out.");
    ASSERT_FALSE(outfile.empty());
    EXPECT_NE(std::string::npos, read_file(outfile).find("Total call paths="));
}

// cct_data_centric_client: default USE_SHADOW_FOR_DATA_CENTRIC path. This is
// the client that exercised the shadow_memory `auto`->`auto&` fix from an
// earlier commit; the test's primary role now is regression coverage.
TEST_F(CCTLibIntegration, CctDataCentricClientRunsCleanly) {
    cleanup(root_, "client.out.");
    int rc = run_pin(root_ + "/tests/obj-intel64/cct_data_centric_client.so",
                     {"/bin/echo", "hi"});
    ASSERT_EQ(0, rc);
    std::string outfile = find_newest(root_, "client.out.");
    ASSERT_FALSE(outfile.empty());
}

// cct_data_centric_client_tree_based: USE_TREE_BASED_FOR_DATA_CENTRIC path.
TEST_F(CCTLibIntegration, CctDataCentricClientTreeBasedRunsCleanly) {
    cleanup(root_, "client.out.");
    int rc = run_pin(root_ + "/tests/obj-intel64/cct_data_centric_client_tree_based.so",
                     {"/bin/echo", "hi"});
    ASSERT_EQ(0, rc);
    std::string outfile = find_newest(root_, "client.out.");
    ASSERT_FALSE(outfile.empty());
}

// cctlib_reader is intentionally NOT tested here as an independent
// integration test. It expects to read a serialized CCT database
// (cctlib-database-*) that would normally be produced by a prior
// serialization run, and if the directory is missing the tool throws
// an uncaught std::string exception (a documented preexisting
// bug -- see the TODO in src/cctlib.cpp DeserializeMetadata). The
// existing top-level `make check` TEST7 exercises the tool loosely by
// running against `ls` and treating child-process exit-0 as pass; a
// proper end-to-end test would require a two-step
// (serialize-then-read) setup, which is left for a later phase.

}  // namespace
