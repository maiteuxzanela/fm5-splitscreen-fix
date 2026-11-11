/*
 * test_fm5_patch_bytes.c — testes reais da matemática de patch do detour.
 *
 * Exercita a MESMA implementação (src/fm5_patch_bytes.h) usada pela DLL
 * Windows, sem Windows e sem mocks: só aritmética de bytes/deslocamentos.
 */
#include "fm5_patch_bytes.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_checks;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_checks++;                                                          \
        if (!(cond)) {                                                       \
            g_failures++;                                                    \
            fprintf(stderr, "FALHA %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                    \
    } while (0)

static void test_abs_jmp(void)
{
    uint8_t buf[16];
    uint64_t target = 0x1122334455667788ULL;
    static const uint8_t expect[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
    };
    memset(buf, 0xAA, sizeof(buf));
    fm5_encode_abs_jmp(buf, target);
    CHECK(memcmp(buf, expect, sizeof(expect)) == 0);
}

static void test_tail(void)
{
    uint8_t buf[16];
    uint64_t resume = 0x1122334455667788ULL;
    static const uint8_t expect[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
    };
    CHECK(FM5_TAIL_LEN == 14);
    CHECK(FM5_TAIL_LEN == FM5_ABS_JMP_LEN);
    memset(buf, 0xAA, sizeof(buf));
    fm5_encode_tail(buf, resume);
    CHECK(memcmp(buf, expect, sizeof(expect)) == 0);
    /* Regressao do crash 0x19a4eb: a cauda NAO pode comecar com `mov rax,
     * imm64` (48 B8), que destruiria o %rax devolvido por um `call`. */
    CHECK(!(buf[0] == 0x48 && buf[1] == 0xB8));
    CHECK(buf[0] == 0xFF && buf[1] == 0x25);
}

#if defined(__x86_64__) && !defined(_WIN32)
#include <sys/mman.h>
#include <unistd.h>

static volatile uint64_t g_tail_seen_rax;
static volatile uint64_t g_tail_calls;

/* Alvo do salto: captura o %rax na ENTRADA, antes de qualquer prologue. */
__attribute__((naked, noinline)) static void tail_capture(void)
{
    __asm__ __volatile__("movq %rax, g_tail_seen_rax(%rip)\n\t"
                         "incq g_tail_calls(%rip)\n\t"
                         "ret\n\t");
}

/* Executa a cauda gerada de verdade: prova que o salto indireto rip-relative
 * preserva %rax, reproduzindo a sequencia `call; mov 0x18(%rax),%rcx` do
 * Controller::get_User original (0x14019a4c9..0x14019a4cf). */
static void test_tail_preserves_rax_exec(void)
{
    long page = sysconf(_SC_PAGESIZE);
    uint8_t *mem;
    uint64_t magic = 0xDEADBEEFCAFEF00DULL;
    uint64_t after = 0;

    if (page <= 0) {
        page = 4096;
    }
    mem = (uint8_t *)mmap(NULL, (size_t)page,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        CHECK(0 && "mmap RWX falhou");
        return;
    }
    g_tail_seen_rax = 0;
    g_tail_calls = 0;
    fm5_encode_tail(mem, (uint64_t)(uintptr_t)&tail_capture);
    __builtin___clear_cache((char *)mem, (char *)mem + FM5_TAIL_LEN);

    __asm__ __volatile__("movq %1, %%rax\n\t"
                         "call *%2\n\t"
                         "movq %%rax, %0\n\t"
                         : "=r"(after)
                         : "r"(magic), "r"(mem)
                         : "rax", "cc", "memory");

    CHECK(g_tail_calls == 1);
    CHECK(g_tail_seen_rax == magic);
    CHECK(after == magic);

    munmap(mem, (size_t)page);
}
#endif

static void test_nops(void)
{
    uint8_t buf[20];
    memset(buf, 0xCC, sizeof(buf));
    fm5_fill_nops(buf, 14, 18);
    CHECK(buf[13] == 0xCC);
    CHECK(buf[14] == 0x90);
    CHECK(buf[15] == 0x90);
    CHECK(buf[16] == 0x90);
    CHECK(buf[17] == 0x90);
    CHECK(buf[18] == 0xCC);
}

static void test_rel32_roundtrip(void)
{
    uint8_t buf[4];
    int32_t vals[] = {0, 1, -1, 0x7FFFFFFF, (int32_t)0x80000000, 0x00ABCDEF,
                      (int32_t)0xFF543210};
    size_t i;
    for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        fm5_write_rel32(buf, vals[i]);
        CHECK(fm5_read_rel32(buf) == vals[i]);
    }
}

/* Reproduz o get_User real: E8 em offset 9, patch de 14 bytes, alvo do call
 * 0x140042980. Prova que o deslocamento relocado continua mirando o MESMO
 * destino absoluto a partir de um trampolim próximo. */
static void test_relocate_get_user_real(void)
{
    uint8_t src[14];
    const uint64_t src_start = 0x14019A4C0ULL;
    const uint64_t call_target = 0x140042980ULL;
    const uint64_t dst_start = 0x140200000ULL;
    int32_t old_disp;
    int32_t new_disp = 0;
    int rc;

    memset(src, 0x90, sizeof(src));
    src[9] = 0xE8;
    old_disp = (int32_t)(call_target - (src_start + 14));
    CHECK(old_disp == (int32_t)0xFFEA84B2);
    fm5_write_rel32(src + 10, old_disp);

    rc = fm5_relocate_rel32_checked(src, sizeof(src), 9, src_start, dst_start,
                                    &new_disp);
    CHECK(rc == 1);
    /* dst_start + 14 + new_disp == call_target */
    CHECK((int64_t)dst_start + 14 + (int64_t)new_disp ==
          (int64_t)call_target);
    CHECK(new_disp == (int32_t)((int64_t)call_target -
                                ((int64_t)dst_start + 14)));

    /* A variante unchecked devolve o mesmo valor. */
    CHECK(fm5_relocate_rel32(src, sizeof(src), 9, src_start, dst_start) ==
          new_disp);
}

static void test_relocate_out_of_range(void)
{
    uint8_t src[14];
    int32_t out = 0;
    memset(src, 0x90, sizeof(src));
    src[9] = 0xE8;
    fm5_write_rel32(src + 10, 0);
    /* 0x20000000 está a >2 GB de 0x14019a4c0: deve recusar (fail-closed). */
    CHECK(fm5_relocate_rel32_checked(src, sizeof(src), 9, 0x14019A4C0ULL,
                                     0x20000000ULL, &out) == -1);
}

static void test_relocate_not_applicable(void)
{
    uint8_t src[14];
    int32_t out = 0;
    memset(src, 0x90, sizeof(src));
    /* Sem rel32. */
    CHECK(fm5_relocate_rel32_checked(src, sizeof(src), -1, 0x1000ULL,
                                     0x2000ULL, &out) == 0);
    /* Offset do rel32 ultrapassa o trecho copiado. */
    CHECK(fm5_relocate_rel32_checked(src, sizeof(src), 12, 0x1000ULL,
                                     0x2000ULL, &out) == 0);
}

static void test_relocate_negative(void)
{
    uint8_t src[14];
    const uint64_t src_start = 0x140000000ULL;
    const uint64_t dst_start = 0x140100000ULL;
    const uint64_t target = 0x13FFFF000ULL; /* 0x1000 abaixo de src */
    int32_t disp = 0;
    int rc;

    memset(src, 0x90, sizeof(src));
    src[9] = 0xE8;
    fm5_write_rel32(src + 10, (int32_t)(target - (src_start + 14)));

    rc = fm5_relocate_rel32_checked(src, sizeof(src), 9, src_start, dst_start,
                                    &disp);
    CHECK(rc == 1);
    CHECK(disp < 0);
    CHECK((int64_t)dst_start + 14 + (int64_t)disp == (int64_t)target);
}

static void test_compose_entry_patch(void)
{
    uint8_t patch[16];
    uint64_t handler = 0x1407A0000ULL;
    memset(patch, 0xCC, sizeof(patch));
    fm5_encode_abs_jmp(patch, handler);
    fm5_fill_nops(patch, FM5_ABS_JMP_LEN, 16);
    /* FF 25 00 00 00 00 <addr8> */
    CHECK(patch[0] == 0xFF);
    CHECK(patch[1] == 0x25);
    CHECK(patch[2] == 0x00);
    CHECK(patch[3] == 0x00);
    CHECK(patch[4] == 0x00);
    CHECK(patch[5] == 0x00);
    {
        uint64_t decoded = 0;
        int i;
        for (i = 0; i < 8; i++) {
            decoded |= (uint64_t)patch[6 + i] << (8 * i);
        }
        CHECK(decoded == handler);
    }
    CHECK(patch[14] == 0x90);
    CHECK(patch[15] == 0x90);
}

int main(void)
{
    CHECK(sizeof(void *) == 8); /* alvo x86-64 */

    test_abs_jmp();
    test_tail();
#if defined(__x86_64__) && !defined(_WIN32)
    test_tail_preserves_rax_exec();
#endif
    test_nops();
    test_rel32_roundtrip();
    test_relocate_get_user_real();
    test_relocate_out_of_range();
    test_relocate_not_applicable();
    test_relocate_negative();
    test_compose_entry_patch();

    if (g_failures) {
        fprintf(stderr, "\n%d/%d verificacoes de patch FALHARAM\n", g_failures,
                g_checks);
        return 1;
    }
    printf("OK: %d verificacoes da matematica de patch passaram\n", g_checks);
    return 0;
}
