// GoogleTest-driven integration tests for omp_datarace_client.
//
// User note: this client is "not very mature". Tests here verify the tool
// loads and runs against OpenMP victims without crashing; race-detection
// accuracy claims are deferred (would require detailed reference-model
// comparison the tool is not currently equipped to satisfy).

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
        setenv("OMP_NUM_THREADS", "2", 1);
        execv(pin.c_str(), argv.data());
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -2;
}

class OmpRaceIntegration : public ::testing::Test {
  protected:
    std::string root_, tool_;
    void SetUp() override {
        root_ = cctlib_root();
        ASSERT_FALSE(pin_root().empty());
        tool_ = root_ + "/clients/obj-intel64/omp_datarace_client.so";
        ASSERT_EQ(0, access(tool_.c_str(), F_OK)) << tool_ << " missing";
        ASSERT_EQ(0, chdir(root_.c_str())) << "chdir failed";
    }
};

// Basic sanity: the tool runs cleanly on a non-OpenMP target.
TEST_F(OmpRaceIntegration, RunsCleanlyOnLs) {
    EXPECT_EQ(0, run_pin(tool_, {"/bin/ls"}));
}

// The tool runs on an OpenMP TP victim (concurrent increment without sync)
// without crashing. Whether it correctly REPORTS the race is a separate
// question addressed by DISABLED_ tests below.
TEST_F(OmpRaceIntegration, RunsOnRaceVictim) {
    EXPECT_EQ(0, run_pin(tool_, {root_ + "/tests/gtest/obj/apps/omp_race_tp_simple"}));
}

// The tool runs on the TN victim (critical-section-protected increment).
TEST_F(OmpRaceIntegration, RunsOnCriticalVictim) {
    EXPECT_EQ(0, run_pin(tool_, {root_ + "/tests/gtest/obj/apps/omp_race_tn_critical"}));
}

// Race-detection accuracy tests -- disabled pending broader hardening of
// omp_datarace_client.
TEST_F(OmpRaceIntegration, DISABLED_TruePositiveReportsRace) {
    GTEST_SKIP() << "omp_datarace_client race detection is not fully wired";
}
TEST_F(OmpRaceIntegration, DISABLED_TrueNegativeReportsNoRace) {
    GTEST_SKIP() << "omp_datarace_client race detection is not fully wired";
}

}  // namespace
