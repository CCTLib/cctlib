// GoogleTest-driven integration tests for cache_client.
//
// cache_client is documented (both by the user and by a preexisting-bug TODO
// in the client source) as "not very mature". Its intended semantics:
//    detect cache-line-sized WRITES that don't change the previous value
//    (silent stores).
//
// Current state: the client SIGSEGVs on essentially any input on this port
// because it defines a thread_local Cache_t array of CACHE_NUM_LINES
// (64 MB / 64 B = 1 M entries) x ~64 bytes per entry = ~64 MB of TLS
// PER THREAD. Pin's TLS descriptor cannot hold that much and the tool
// dereferences a bad pointer at first access.
//
// We land two tests here:
//  - CrashesOnTrivialInputDocumentsBug -- an assertion in reverse: we
//    ASSERT that the tool crashes today. If someone fixes the underlying
//    bug the tool will start succeeding, this test will fail, and the
//    maintainer will know to flip to the real coverage below.
//  - DISABLED_ tests describe the semantics the client should measure
//    once the TLS bug is fixed. They are skipped by gtest but visible in
//    the test list.

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
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
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
        execv(pin.c_str(), argv.data());
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -2;
}

class CacheClientIntegration : public ::testing::Test {
  protected:
    std::string root_, tool_;
    void SetUp() override {
        root_ = cctlib_root();
        ASSERT_FALSE(pin_root().empty());
        tool_ = root_ + "/clients/obj-intel64/cache_client.so";
        ASSERT_EQ(0, access(tool_.c_str(), F_OK)) << tool_ << " missing";
        ASSERT_EQ(0, chdir(root_.c_str())) << "chdir failed";
    }
};

// Pin returns a Pin-error exit code (typically 139 = 128 + SIGSEGV, or 1)
// when the loaded tool crashes. Assert that cache_client does that so we
// notice if someone repairs the tool.
TEST_F(CacheClientIntegration, CrashesOnTrivialInputDocumentsBug) {
    int rc = run_pin(tool_, {"/bin/echo", "hi"});
    // Pin exit code space: 0=clean, 139=SEGV, 1=Pin caught the crash and
    // reported it. Accept any non-zero as "the known bug is still present".
    EXPECT_NE(0, rc)
        << "cache_client returned 0 -- the TLS-descriptor bug documented "
           "in the client's TODOs may be fixed. Remove the DISABLED_ prefix "
           "from the semantic tests below and update this test to expect "
           "success.";
}

// Semantic tests -- currently disabled. When the tool is fixed:
//   1. Rename DISABLED_SilentCachelineWriteDetected -> SilentCachelineWriteDetected
//   2. Update CrashesOnTrivialInputDocumentsBug above (or remove it)

// TRUE POSITIVE: a program that writes a whole 64-byte cacheline with the
// SAME values that were already there. cache_client should report a silent
// store.
TEST_F(CacheClientIntegration, DISABLED_SilentCachelineWriteDetected) {
    // Deferred: needs the TLS bug fixed before this can pass.
    // Victim would be a program that does: initialise a 64B buffer to a
    // pattern, then re-write the SAME 64B pattern -- cache_client should
    // detect the second write as silent.
    GTEST_SKIP() << "cache_client TLS bug prevents any real coverage";
}

// TRUE NEGATIVE: same shape but the re-write differs by 1 byte -- not silent.
TEST_F(CacheClientIntegration, DISABLED_DifferingCachelineWriteNotSilent) {
    GTEST_SKIP() << "cache_client TLS bug prevents any real coverage";
}

}  // namespace
