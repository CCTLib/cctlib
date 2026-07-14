// Integration tests for cctlib's direct-self-recursion collapse.
//
// Each test launches Pin with clients/obj-intel64/cct_shape_check.so
// against one recursion victim, passing -check <victim_name>. The
// check tool walks the CCT programmatically at ThreadFini time (while
// images are still loaded so IPs resolve), builds an in-memory
// inventory of every reached call-chain, and applies per-victim
// assertions coded IN the tool. Exit code 0 iff every assertion
// passed; on failure the tool writes a diagnostic to stderr with the
// assertion name, expected vs observed values, and the inventory
// summary. We surface that stderr in the gtest failure message.
//
// Correctness signal: assertions target chainCountForFn("<fn>") --
// the number of distinct root-to-leaf function-name chains ending in
// the recursive routine. After collapse this is O(1); without
// collapse it grows with recursion depth. Sensitivity was verified
// by temporarily disabling the collapse gate in cctlib.cpp and
// rerunning -- 5 of 8 assertions flipped from pass to fail with
// chain counts jumping from 1 to 15-20.

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>

namespace {

std::string env(const char* n) { const char* v = getenv(n); return v ? v : ""; }
std::string cctlib_root() {
    std::string r = env("CCTLIB_ROOT");
    return r.empty() ? "../.." : r;
}
std::string pin_root() { return env("PIN_ROOT"); }

// Run pin with the given tool + args against the victim; capture the
// tool's stderr into a temp file so we can attach it to a gtest
// failure message. Returns pin's exit code; if capture failed, *stderrOut
// is left empty.
int run_pin_capture(const std::string& tool,
                    const std::vector<std::string>& toolArgs,
                    const std::string& victim,
                    std::string* stderrOut) {
    std::string pin = pin_root() + "/pin";
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(pin.c_str()));
    argv.push_back(const_cast<char*>("-t"));
    argv.push_back(const_cast<char*>(tool.c_str()));
    for (auto& a : toolArgs) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(const_cast<char*>("--"));
    argv.push_back(const_cast<char*>(victim.c_str()));
    argv.push_back(nullptr);

    char errPath[] = "/tmp/cct_shape_stderr_XXXXXX";
    int errFd = mkstemp(errPath);
    if (errFd < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(errFd); return -1; }
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); close(devnull); }
        dup2(errFd, 2); close(errFd);
        execv(pin.c_str(), argv.data());
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) { close(errFd); unlink(errPath); return -1; }

    if (stderrOut) {
        lseek(errFd, 0, SEEK_SET);
        stderrOut->clear();
        char buf[4096];
        ssize_t n;
        while ((n = read(errFd, buf, sizeof(buf))) > 0) {
            stderrOut->append(buf, n);
        }
    }
    close(errFd);
    unlink(errPath);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -128 - WTERMSIG(status);
}

struct VictimSpec {
    const char* name;   // gtest label + binary basename + -check arg
};

const VictimSpec kVictims[] = {
    { "rec_fib_deep"              },
    { "rec_ackermann"             },
    { "rec_multi_direct"          },
    { "rec_indirect_only"         },
    { "rec_mixed_direct_indirect" },
    { "rec_stripped"              },
    { "rec_exception"             },
    { "rec_baseline_nonrec"       },
};

class RecursionShape : public ::testing::TestWithParam<VictimSpec> {
  protected:
    std::string root_;
    void SetUp() override {
        root_ = cctlib_root();
        ASSERT_FALSE(pin_root().empty()) << "PIN_ROOT required";
        ASSERT_EQ(0, chdir(root_.c_str())) << "chdir(" << root_ << ") failed";
    }
};

TEST_P(RecursionShape, CctShapeAssertionsPass) {
    const auto& v = GetParam();
    std::string tool = root_ + "/clients/obj-intel64/cct_shape_check.so";
    std::string victim = root_ + "/tests/gtest/obj/apps/recursion/" + v.name;
    ASSERT_EQ(0, access(tool.c_str(), F_OK)) << tool << " missing";
    ASSERT_EQ(0, access(victim.c_str(), F_OK)) << victim << " missing";

    std::string errText;
    int rc = run_pin_capture(tool, {"-check", v.name}, victim, &errText);
    EXPECT_EQ(0, rc)
        << "victim=" << v.name << " rc=" << rc
        << "\n---- cct_shape_check stderr ----\n" << errText
        << "---- end stderr ----";
}

INSTANTIATE_TEST_SUITE_P(
    Victims, RecursionShape,
    ::testing::ValuesIn(kVictims),
    [](const testing::TestParamInfo<RecursionShape::ParamType>& info) {
        return std::string(info.param.name);
    });

}  // namespace
