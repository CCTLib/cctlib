// Shape-based integration tests for cctlib's exception + signal
// handling. Each victim exercises a specific pattern (throw/catch,
// deep unwind, rethrow, catch-all, destructor cleanup, high-frequency
// loop, polymorphic catch, setjmp/longjmp, sigsegv-recovery), and we
// launch it under clients/obj-intel64/cct_shape_check.so with
// -check <victim_name>. The check tool walks the CCT programmatically
// at ThreadFini and asserts per-victim structural invariants -- the
// generic check is "main appears in some chain AND no HARD sentinels"
// (proving cctlib's unwind path left the CCT coherent); per-victim
// overrides tighten this where an unwind-specific shape is expected.
//
// This suite complements the existing exception_integration_test.cpp
// which drives deadspy/redspy/loadspy and catches tool-side SIGSEGVs
// in those clients' analysis routines. The shape suite catches the
// dual failure mode: cctlib silently corrupting the CCT during unwind
// (would show as sentinel frames -- BAD IP / CRASHED / etc.) or
// mis-anchoring post-catch code under a throwing frame (caught by
// the exc_catch_and_resume-specific check_exc_catch_and_resume).

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

    char errPath[] = "/tmp/cct_shape_exc_stderr_XXXXXX";
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

// All 13 exception victims are wired for shape checks. Each victim's
// per-shape assertion lives in clients/cct_shape_check.cpp
// (check_exc_*). The stress victims -- exc_simple_throw (N=5000),
// exc_rethrow (ITERS=2000), exc_stress_loop (ITERS=5000),
// exc_none_tn (ITERS=20000) -- are slow under Pin+cctlib (many
// minutes each) and are gated behind CCTLIB_EXPENSIVE_SHAPE=1 so
// they don't dominate the default `make test` runtime. The full
// suite runs in CI or when the env var is set. The compact suite
// still covers every distinct CCT-structural pattern (single
// throw, nested rethrow, catch-all, multi-phase dtor cleanup,
// polymorphic dispatch, uncaught path, ctor throw, catch+resume,
// setjmp/longjmp, signal recovery).
struct VictimSpec {
    const char* name;
    bool expensive;   // true = only run when CCTLIB_EXPENSIVE_SHAPE=1
};

const VictimSpec kVictims[] = {
    { "exc_simple_throw",     true  },  // N=5000 throws
    { "exc_deep_unwind",      false },  // ITERS=200
    { "exc_rethrow",          true  },  // ITERS=2000, 2x _Unwind_SetIP per iter
    { "exc_catchall",         false },  // ITERS=400
    { "exc_dtor_cleanup",     false },  // ITERS=500
    { "exc_stress_loop",      true  },  // ITERS=5000
    { "exc_polymorphic",      false },  // ITERS=1000
    { "exc_recurse_trycatch", false },  // D=8, ITERS=100 (rec+rethrow chain)
    { "exc_none_tn",          true  },  // ITERS=20000 (no throws)
    { "exc_uncaught_tn",      false },  // 1 uncaught throw + terminate
    { "exc_ctor_throw",       false },  // ITERS=200
    { "exc_catch_and_resume", false },  // ITERS=2000
    { "sig_longjmp",          false },  // ITERS=500
    { "sig_sigsegv_recover",  false },  // ITERS=200
};

class ExceptionShape : public ::testing::TestWithParam<VictimSpec> {
  protected:
    std::string root_;
    void SetUp() override {
        root_ = cctlib_root();
        ASSERT_FALSE(pin_root().empty()) << "PIN_ROOT required";
        ASSERT_EQ(0, chdir(root_.c_str())) << "chdir(" << root_ << ") failed";
    }
};

TEST_P(ExceptionShape, CctShapeSurvivesUnwind) {
    const auto& v = GetParam();
    if (v.expensive && env("CCTLIB_EXPENSIVE_SHAPE").empty()) {
        GTEST_SKIP() << v.name << " gated behind CCTLIB_EXPENSIVE_SHAPE=1 "
                     << "(slow under Pin+cctlib; runs in nightly / on-demand)";
    }
    std::string tool = root_ + "/clients/obj-intel64/cct_shape_check.so";
    std::string victim = root_ + "/tests/gtest/obj/apps/exceptions/" + v.name;
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
    Victims, ExceptionShape,
    ::testing::ValuesIn(kVictims),
    [](const testing::TestParamInfo<ExceptionShape::ParamType>& info) {
        return std::string(info.param.name);
    });

}  // namespace
