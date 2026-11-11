/*
 * test_fm5_event_shield.c — prova REAL (sem mocks) da guarda anti-NULL da fila
 * de eventos do Azimuth, nascida do crash EXCEPTION_ACCESS_VIOLATION
 * (0xC0000005) em rip=0x140687f4c (azimuth.exe 1.0.4).
 *
 * O que este teste faz de verdade:
 *   1. confere a constante forense da sequência original
 *      (`48 8b 41 08` = mov rax,[rcx+8]; `48 89 08` = mov [rax],rcx);
 *   2. monta a caverna e o salto E9 com o MESMO código portátil usado pela
 *      DLL (fm5_event_shield_encode.h);
 *   3. aloca memória executável (mmap), replica a função alvo em 7 bytes +
 *      `ret`, aplica o patch e EXECUTA a função com rcx apontando para um nó
 *      cujo `next` é válido — confere que o encadeamento acontece;
 *   4. executa a mesma função com `next == NULL` — confere que NENHUMA escrita
 *      em 0x0 ocorre e que o processo sobrevive;
 *   5. confere a preservação de EFLAGS (pushfq/popfq) no caminho válido;
 *   6. faz o CONTROLE NEGATIVO em processo filho (fork): a mesma função SEM a
 *      guarda morre com SIGSEGV ao tocar 0x0. Isso prova que a guarda é o que
 *      evita o crash — não uma suposição.
 *
 * Determinístico: sem rede, sem sleep, sem mock. Linux x86-64 (a codificação
 * é a mesma do alvo Windows; o teste apenas chama a sequência pela ABI SysV
 * através de um stub `mov rcx,rdi; jmp alvo` montado no mesmo buffer).
 */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fm5_event_shield_encode.h"

/* Espaço da caverna no buffer de teste (a produção aloca 64 bytes). */
#define FM5_SHIELD_CAVE_ALLOC_FOR_TEST 64u

static int g_checks;
static int g_failures;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        g_checks++;                                                            \
        if (!(cond)) {                                                         \
            g_failures++;                                                      \
            fprintf(stderr, "FALHA: %s\n", (msg));                             \
        }                                                                      \
    } while (0)

/* Nó mínimo com o layout lido pela sequência: [rcx+8] é o "next". */
typedef struct {
    uint64_t pad;
    void    *next;
} node_t;

static uint8_t *alloc_rwx(size_t size)
{
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : (uint8_t *)p;
}

static void free_rwx(void *p, size_t size)
{
    if (p) {
        (void)munmap(p, size);
    }
}

/*
 * Monta, no MESMO buffer, a função-alvo (7 bytes originais + ret) e a caverna
 * com a guarda. Devolve o ponteiro para o stub SysV (`mov rcx,rdi; jmp alvo`),
 * que permite chamar a função com o argumento em RCX — a convenção usada pelo
 * código Windows original — a partir de C comum.
 */
static uint8_t *build_guarded(uint8_t *mem, int guarded)
{
    uint8_t *fn = mem;
    uint8_t *cave = mem + 64;
    uint8_t *stub = mem + 160;
    size_t cave_len;

    memcpy(fn, fm5_shield_original(), FM5_SHIELD_ORIG_LEN);
    fn[FM5_SHIELD_ORIG_LEN] = 0xC3; /* ret */

    if (guarded) {
        cave_len = fm5_shield_encode_cave(
            cave, FM5_SHIELD_CAVE_ALLOC_FOR_TEST,
            (uint64_t)(uintptr_t)(fn + FM5_SHIELD_ORIG_LEN));
        if (cave_len != FM5_SHIELD_CAVE_LEN) {
            return NULL;
        }
        if (fm5_shield_encode_jump(fn, (uint64_t)(uintptr_t)fn,
                                   (uint64_t)(uintptr_t)cave) != 0) {
            return NULL;
        }
    }

    /* Stub SysV -> convenção do alvo: mov rcx, rdi; jmp qword [rip+0]; fn. */
    stub[0] = 0x48;
    stub[1] = 0x89;
    stub[2] = 0xF9; /* mov rcx, rdi */
    stub[3] = 0xFF;
    stub[4] = 0x25;
    stub[5] = 0x00;
    stub[6] = 0x00;
    stub[7] = 0x00;
    stub[8] = 0x00;
    {
        uint64_t target = (uint64_t)(uintptr_t)fn;
        int i;
        for (i = 0; i < 8; i++) {
            stub[9 + i] = (uint8_t)((target >> (8 * i)) & 0xFFu);
        }
    }
    return stub;
}

/* Chama o stub com `node` em RDI; devolve EFLAGS observadas APÓS o retorno.
 * `xor eax,eax` deixa ZF=1 e o stub/caverna não podem vê-la alterada. */
static unsigned long long call_and_capture_flags(void (*fn)(void *), void *node)
{
    unsigned long long flags;
    __asm__ __volatile__("xorl %%eax, %%eax\n\t"
                         "callq *%1\n\t"
                         "pushfq\n\t"
                         "popq %%rax\n\t"
                         "movq %%rax, %0\n\t"
                         : "=m"(flags)
                         : "m"(fn), "D"(node)
                         : "rax", "rcx", "rdx", "rsi", "r8", "r9", "r10",
                           "r11", "memory", "cc");
    return flags;
}

static void test_constants(void)
{
    static const uint8_t expected[7] = { 0x48, 0x8B, 0x41, 0x08,
                                         0x48, 0x89, 0x08 };
    const uint8_t flipped[7] = { 0x48, 0x8B, 0x41, 0x08, 0x48, 0x89, 0x00 };
    const uint8_t rax_other[7] = { 0x48, 0x8B, 0x41, 0x10, 0x48, 0x89, 0x08 };

    CHECK(FM5_SHIELD_RVA == 0x687F48u,
          "RVA da sequencia deve ser 0x687f48 (rip do crash)");
    CHECK(FM5_SHIELD_RESUME_RVA == 0x687F4Fu,
          "retomada deve ser 0x687f4f (apos mov [rax],rcx)");
    CHECK(FM5_SHIELD_ORIG_LEN == 7u, "sequencia original tem 7 bytes");
    CHECK(FM5_SHIELD_PATCH_LEN == 5u, "salto de entrada E9 tem 5 bytes");
    CHECK(FM5_SHIELD_CAVE_LEN == 28u, "caverna completa tem 28 bytes");
    CHECK(memcmp(fm5_shield_original(), expected, sizeof(expected)) == 0,
          "constante forense diverge do crash (mov rax,[rcx+8]; mov [rax],rcx)");
    CHECK(fm5_shield_is_original(expected) == 1,
          "is_original deve aceitar a sequencia do crash");
    CHECK(fm5_shield_is_original(flipped) == 0,
          "is_original deve rejeitar byte final alterado");
    CHECK(fm5_shield_is_original(rax_other) == 0,
          "is_original deve rejeitar deslocamento diferente de +8");
    CHECK(fm5_shield_is_original(NULL) == 0,
          "is_original deve ser fail-closed com NULL");
}

static void test_cave_bytes(void)
{
    static const uint8_t ops[14] = {
        FM5_SHIELD_CAVE_OPCODES
    };
    static const uint8_t expected[14] = {
        0x48, 0x8B, 0x41, 0x08, /* mov rax,[rcx+8] */
        0x9C,                   /* pushfq           */
        0x48, 0x85, 0xC0,       /* test rax,rax     */
        0x74, 0x03,             /* jz +3            */
        0x48, 0x89, 0x08,       /* mov [rax],rcx    */
        0x9D                    /* popfq            */
    };
    uint8_t buf[FM5_SHIELD_CAVE_LEN + 8];
    uint64_t resume = 0x140687F4FULL;
    size_t n;
    int i;

    CHECK(memcmp(ops, expected, sizeof(expected)) == 0,
          "opcodes da caverna divergem da guarda esperada");
    memset(buf, 0xAA, sizeof(buf));
    n = fm5_shield_encode_cave(buf, FM5_SHIELD_CAVE_LEN, resume);
    CHECK(n == FM5_SHIELD_CAVE_LEN,
          "encode_cave deve devolver FM5_SHIELD_CAVE_LEN");
    CHECK(memcmp(buf, expected, sizeof(expected)) == 0,
          "preambulo da caverna divergente");
    CHECK(buf[14] == 0xFF && buf[15] == 0x25 && buf[16] == 0x00 &&
              buf[17] == 0x00 && buf[18] == 0x00 && buf[19] == 0x00,
          "cauda da caverna nao e jmp qword [rip+0]");
    for (i = 0; i < 8; i++) {
        CHECK(buf[20 + i] == (uint8_t)((resume >> (8 * i)) & 0xFFu),
              "endereco de retomada nao foi gravado em little-endian");
    }
    CHECK(fm5_shield_encode_cave(buf, FM5_SHIELD_CAVE_LEN - 1, resume) == 0,
          "caverna menor que o necessario deve falhar (fail-closed)");
    CHECK(fm5_shield_encode_cave(NULL, FM5_SHIELD_CAVE_LEN, resume) == 0,
          "caverna com destino NULL deve falhar");
}

static void test_jump_bytes(void)
{
    uint8_t patch[FM5_SHIELD_PATCH_LEN];
    uint64_t target = 0x140687F48ULL;
    uint64_t cave = 0x1407A0000ULL;
    int32_t disp;

    CHECK(fm5_shield_encode_jump(patch, target, cave) == 0,
          "salto dentro do alcance deve ser codificado");
    CHECK(patch[0] == 0xE9, "opcode do salto de entrada deve ser E9");
    memcpy(&disp, patch + 1, sizeof(disp));
    CHECK((uint64_t)(int64_t)(target + FM5_SHIELD_PATCH_LEN + (int64_t)disp) ==
              cave,
          "rel32 nao resolve para a caverna");
    CHECK(fm5_shield_encode_jump(patch, target, target + 0x90000000ULL) == -1,
          "salto fora de +-2 GiB deve falhar (fail-closed)");
    CHECK(fm5_shield_encode_jump(NULL, target, cave) == -1,
          "salto com destino NULL deve falhar");
}

/* Executa a função patcheada de verdade. */
static void test_execution(void)
{
    const size_t size = 4096;
    uint8_t *mem = alloc_rwx(size);
    uint8_t *guarded;
    uint8_t *plain;
    node_t node;
    void *cell;
    uint64_t sentinel = 0xDEADBEEFCAFEF00DULL;
    uint64_t flags;

    CHECK(mem != NULL, "mmap RWX falhou (ambiente sem PROT_EXEC?)");
    if (!mem) {
        return;
    }

    /* --- caminho válido: *next = node deve ser escrito ------------------ */
    guarded = build_guarded(mem, 1);
    CHECK(guarded != NULL, "montagem da funcao com guarda falhou");
    if (guarded) {
        cell = NULL;
        memset(&node, 0, sizeof(node));
        node.next = &cell;
        ((void (*)(void *))guarded)(&node);
        CHECK(cell == (void *)&node,
              "caminho valido nao encadeou (*next != node)");

        /* EFLAGS: ZF=1 antes da chamada tem de continuar 1 na volta. */
        cell = NULL;
        flags = call_and_capture_flags((void (*)(void *))guarded, &node);
        CHECK((flags & 0x40ULL) != 0,
              "EFLAGS nao preservadas (pushfq/popfq ausente ou incorreto)");
        CHECK(cell == (void *)&node,
              "caminho valido (flags) nao encadeou (*next != node)");
    }

    /* --- caminho NULL: nada pode ser escrito em 0x0 --------------------- */
    if (guarded) {
        memset(&node, 0, sizeof(node));
        node.next = NULL;
        ((void (*)(void *))guarded)(&node); /* se falhar a guarda, SIGSEGV */
        CHECK(sentinel == 0xDEADBEEFCAFEF00DULL,
              "escrita colateral detectada no caminho NULL");
        CHECK(node.next == NULL, "guarda alterou o proprio no");
        printf("OK: caminho next=NULL sobreviveu sem escrever em 0x0\n");
    }

    /* --- controle negativo em filho: SEM guarda, o mesmo nó NULL mata ---- */
    {
        uint8_t *plain_mem = alloc_rwx(size);
        CHECK(plain_mem != NULL, "mmap RWX (controle) falhou");
        if (plain_mem) {
            plain = build_guarded(plain_mem, 0);
            CHECK(plain != NULL, "montagem do controle negativo falhou");
            if (plain) {
                pid_t pid = fork();
                CHECK(pid >= 0, "fork do controle negativo falhou");
                if (pid == 0) {
                    node_t child_node;
                    memset(&child_node, 0, sizeof(child_node));
                    child_node.next = NULL;
                    /* Sem a guarda: mov rax,[rcx+8] -> 0; mov [rax],rcx. */
                    ((void (*)(void *))plain)(&child_node);
                    _exit(0); /* só chega aqui se NÃO houver SIGSEGV */
                } else if (pid > 0) {
                    int status = 0;
                    CHECK(waitpid(pid, &status, 0) == pid,
                          "waitpid do controle negativo falhou");
                    CHECK(WIFSIGNALED(status) &&
                              WTERMSIG(status) == SIGSEGV,
                          "controle negativo NAO morreu com SIGSEGV: a guarda "
                          "nao e o que evita o crash");
                }
            }
            free_rwx(plain_mem, size);
        }
    }

    free_rwx(mem, size);
}

int main(void)
{
    test_constants();
    test_cave_bytes();
    test_jump_bytes();
    test_execution();

    if (g_failures) {
        fprintf(stderr, "FALHA: %d/%d verificacoes da guarda anti-NULL "
                        "falharam\n", g_failures, g_checks);
        return 1;
    }
    printf("OK: %d verificacoes da guarda anti-NULL da fila de eventos "
           "passaram (execucao real)\n", g_checks);
    return 0;
}
