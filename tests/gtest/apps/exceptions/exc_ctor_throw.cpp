// Throw from a constructor mid-initialization. The already-constructed
// members and base subobjects must be destroyed in reverse order as the
// exception propagates. Every constructor and destructor writes to a
// per-instance byte in `buf`, so cctlib sees a clear pattern:
//   * Members constructed before the throw: 1 store from ctor + 1 store from dtor
//   * The throwing member: 1 store from ctor (then throws)
//   * Members never constructed: 0 stores
// If cctlib's CCT walking on the unwind through the partially-constructed
// object gets confused, dead-write attribution would silently misalign
// (the dtor stores would appear under the wrong CCT node). This is a
// tp-shape victim: the tool must not crash and the byte pattern in `buf`
// must match the expected shape at the end.
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#define ITERS 200
static volatile uint64_t sink;
static uint8_t buf[ITERS * 4];   // 4 bytes per iter: ctor+dtor for members A,B

struct A {
    uint8_t* slot;
    A(uint8_t* s) : slot(s) { *slot = 0x11; }
    ~A() { *slot ^= 0xEE; }
};

struct B {
    uint8_t* slot;
    B(uint8_t* s, bool doThrow) : slot(s) {
        *slot = 0x22;
        if (doThrow) throw std::runtime_error("boom");
    }
    ~B() { *slot ^= 0xDD; }   // never reached in this test
};

struct Wrap {
    A a;
    B b;   // if b's ctor throws, a's dtor is called but Wrap's dtor is not
    Wrap(uint8_t* baseSlot)
        : a(&baseSlot[0]),
          b(&baseSlot[2], true)    // throws
    {
        baseSlot[3] = 0xFF;    // unreachable
    }
    ~Wrap() { /* unreached */ }
};

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    int caught = 0;
    for (int i = 0; i < ITERS; ++i) {
        uint8_t* base = &buf[i * 4];
        try {
            Wrap w(base);
            (void)w;
        } catch (const std::exception&) {
            ++caught;
            base[1] = 0xCC;
        }
    }
    // Validate the write pattern:
    //   buf[i*4 + 0] = 0x11 ^ 0xEE  = 0xFF (A ctor then dtor)
    //   buf[i*4 + 1] = 0xCC          (post-catch marker)
    //   buf[i*4 + 2] = 0x22          (B ctor, B dtor never ran)
    //   buf[i*4 + 3] = 0             (unreached)
    int ok = 0;
    for (int i = 0; i < ITERS; ++i) {
        uint8_t* p = &buf[i * 4];
        if (p[0] == 0xFF && p[1] == 0xCC && p[2] == 0x22 && p[3] == 0) ++ok;
        sink ^= p[0]; sink ^= p[1]; sink ^= p[2]; sink ^= p[3];
    }
    fprintf(stderr, "exc_ctor_throw: caught=%d ok_pattern=%d/%d sink=%llx\n",
            caught, ok, ITERS, (unsigned long long)sink);
    return (caught == ITERS && ok == ITERS) ? 0 : 1;
}
