/*
 * test_fm5_visibility_shield.c — prova REAL (sem mocks) da blindagem da
 * Visibility Thread do título (crashes EXCEPTION_ACCESS_VIOLATION em
 * rip=0x1408595e0 e rip=0x14085b77a, Thread 0344).
 *
 * O que este teste faz de verdade:
 *   1. ANCORA FORENSE: lê o executável real do título
 *      (Game/Mount/forza_durango_release_final.exe), mapeia RVA->offset pelo
 *      cabeçalho PE e confere byte-a-byte a sequência do crash em 0x859500,
 *      o `jae +0x8d` em 0x859516, o caminho de inserção no fim em 0x85951c, o
 *      caminho de shift em 0x8595a9, o laço de cópia para trás em 0x8595e0,
 *      o helper `48 3b ca 74 26` em 0x85b770 (word 0x74ca, ret em 0x85b79e),
 *      os 5 call sites E8 do helper, a sequência `4d 8b c3 48 89 44 24 20`
 *      da fonte em 0x8580e0 e o call E8 -> 0x859390 em 0x8580e8;
 *   2. executa a DECISÃO real (sub/sar/cmp + opcode lido do encoder de
 *      produção) numa MATRIZ de distâncias where-_Mylast: prova que o JGE só
 *      muda o caso _Mylast-where < 0 (todo d=1..64 exaustivo + potências +
 *      delta forense) e que d <= 0 mantém o comportamento original;
 *   3. CONTROLE NEGATIVO em processo filho: com o JAE original, o laço de
 *      cópia para trás desce até a página-guarda e morre com SIGSEGV em
 *      VÁRIAS distâncias where > _Mylast (não só no delta de ~1 MB);
 *   4. executa a CAVERNA de trava montada pelo MESMO encoder usado pela DLL:
 *      where > _Mylast é travado em _Mylast com count 0 nas TRÊS cópias
 *      (r8, rbp e o spill [rsp+0x90]) — mesmo com o JAE original intacto —
 *      e where <= _Mylast segue intocado (sentinelas preservadas);
 *   5. executa o helper REAL copiado do executável: com `74` (JE) e
 *      rcx > rdx o laço desgovernado morre com SIGSEGV (controle negativo);
 *      com `73` (JAE) retorna imediato com r8 intacto; nos casos legítimos
 *      (rcx <= rdx) os DOIS comportamentos copiam idêntico;
 *   6. executa a CAVERNA DA FONTE (camada [4]) montada pelo encoder de
 *      produção: where > *global _Mylast é clamped ANTES do "call insert"
 *      e where <= _Mylast passa intacto.
 *
 * Determinístico: sem rede, sem sleeps, sem mocks. Linux x86-64 (a codificação
 * é a mesma do alvo Windows; o stub SysV->ABI do alvo passa os argumentos em
 * r8/rdx como o jogo).
 */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fm5_visibility_shield_encode.h"

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

static void clear_icache(void *p, size_t n)
{
    __builtin___clear_cache((char *)p, (char *)p + n);
}

/* ------------------------------------------------------------------------- */
/* Leitor PE mínimo: RVA -> bytes do arquivo (a âncora forense)               */
/* ------------------------------------------------------------------------- */
static uint32_t rd_u16(const uint8_t *b, size_t o)
{
    return (uint32_t)b[o] | ((uint32_t)b[o + 1] << 8);
}

static uint32_t rd_u32(const uint8_t *b, size_t o)
{
    return (uint32_t)b[o] | ((uint32_t)b[o + 1] << 8) |
           ((uint32_t)b[o + 2] << 16) | ((uint32_t)b[o + 3] << 24);
}

/* Lê `n` bytes da RVA `rva` do PE em `path`. Retorna 1 em sucesso. */
static int read_pe_rva(const char *path, uint32_t rva, uint8_t *out, size_t n)
{
    FILE *f;
    long size;
    uint8_t *data;
    uint32_t pe;
    uint32_t nsec;
    uint32_t optsz;
    uint32_t opt;
    uint32_t sec;
    uint32_t i;
    int found = 0;

    f = fopen(path, "rb");
    if (!f) {
        return 0;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }
    size = ftell(f);
    if (size <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }
    data = (uint8_t *)malloc((size_t)size);
    if (!data) {
        fclose(f);
        return 0;
    }
    if (fread(data, 1, (size_t)size, f) != (size_t)size) {
        free(data);
        fclose(f);
        return 0;
    }
    fclose(f);

    if (size < 0x40 || data[0] != 'M' || data[1] != 'Z') {
        free(data);
        return 0;
    }
    pe = rd_u32(data, 0x3C);
    if (pe + 24 > (uint32_t)size || data[pe] != 'P' || data[pe + 1] != 'E') {
        free(data);
        return 0;
    }
    nsec = rd_u16(data, pe + 6);
    optsz = rd_u16(data, pe + 20);
    opt = pe + 24;
    sec = opt + optsz;
    for (i = 0; i < nsec; i++) {
        uint32_t base = sec + i * 40;
        uint32_t vsize;
        uint32_t vaddr;
        uint32_t rawsize;
        uint32_t rawptr;
        if (base + 40 > (uint32_t)size) {
            break;
        }
        vsize = rd_u32(data, base + 8);
        vaddr = rd_u32(data, base + 12);
        rawsize = rd_u32(data, base + 16);
        rawptr = rd_u32(data, base + 20);
        if (rva >= vaddr && rva < vaddr + (vsize > rawsize ? vsize : rawsize)) {
            uint32_t delta = rva - vaddr;
            if (delta < rawsize && (size_t)rawptr + delta + n <= (size_t)size) {
                memcpy(out, data + rawptr + delta, n);
                found = 1;
            }
            break;
        }
    }
    free(data);
    return found;
}

static const char *find_title_exe(void)
{
    static const char *candidates[] = {
        "Game/Mount/forza_durango_release_final.exe",
        "../Game/Mount/forza_durango_release_final.exe",
        "../../Game/Mount/forza_durango_release_final.exe",
        "../../../Game/Mount/forza_durango_release_final.exe",
        "../Games/ForzaMotorsport5/Game/Mount/forza_durango_release_final.exe"
    };
    const char *env = getenv("FM5_TITLE_EXE");
    size_t i;

    if (env && env[0] != '\0' && access(env, R_OK) == 0) {
        return env;
    }
    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (access(candidates[i], R_OK) == 0) {
            return candidates[i];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Stub de execução: SysV (rdi=where, rsi=_Mylast, rdx=&out) -> alvo           */
/* O alvo recebe r8=where, r11=where (a cópia da camada [4] reemite           */
/* `mov r8,r11`), rdx=_Mylast (a convenção do Windows); r10 carrega o         */
/* endereço do alvo para o call (r11 é reservado ao where). O thunk grava:     */
/*   out[0] = r8 após o alvo   out[1] = eax após o alvo                       */
/*   out[2] = [rsp+0x88] (o spill [rsp+0x90] do ALVO = endereço da caverna)   */
/*   out[3] = rbp salvo do caller   out[4] = rbp após o alvo                  */
/* O frame fica em rbx (a caverna [2] clobbers rbp) e o scratch é 0x108        */
/* (>= 0x90+8: a caverna escreve [rsp+0x90] do alvo). Com sub rsp,0x108 o     */
/* rsp do alvo fica 16-byte aligned na entrada (vmovaps [rsp+0x40] exige).    */
/* Sentinelas pré-semeadas: [rsp+0x88] = 0x7A17A17A, rbp = 0x5A5A5A5A...      */
/* ------------------------------------------------------------------------- */
#define FM5_SPILL_SENTINEL 0x7A17A17AULL
#define FM5_RBP_SENTINEL   0x5A5A5A5A5A5A5A5AULL

typedef void (*run_thunk_fn)(uint64_t where, uint64_t mylast, uint64_t *out);

static uint8_t *build_thunk(uint8_t *mem, uint8_t *target)
{
    static const uint8_t pre[] = {
        0x53,                                     /* push rbx            */
        0x55,                                     /* push rbp            */
        0x48, 0x89, 0xE3,                         /* mov  rbx, rsp       */
        0x48, 0x83, 0xE4, 0xF0,                   /* and  rsp, -16       */
        0x48, 0x81, 0xEC, 0x08, 0x01, 0x00, 0x00, /* sub  rsp, 0x108     */
        0x49, 0x89, 0xD1,                         /* mov  r9, rdx (&out) */
        0x49, 0x89, 0xF8,                         /* mov  r8, rdi (where)*/
        0x49, 0x89, 0xFB,                         /* mov  r11, rdi       */
        0x48, 0x89, 0xF2,                         /* mov  rdx, rsi       */
        0x48, 0x89, 0xF0,                         /* mov  rax, rsi       */
        0x48, 0xBD,                               /* mov  rbp, sentinel  */
        0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
        0x48, 0xC7, 0x84, 0x24,                   /* mov [rsp+0x88],     */
        0x88, 0x00, 0x00, 0x00,                   /*  (disp32: 0x88 e    */
        0x7A, 0xA1, 0x17, 0x7A                    /*  0x7a17a17a LE)     */
    };
    uint64_t t = (uint64_t)(uintptr_t)target;
    size_t o = sizeof(pre);
    int i;

    memcpy(mem, pre, sizeof(pre));
    mem[o++] = 0x49; /* mov r10, imm64 (call target; preserva r11=where) */
    mem[o++] = 0xBA;
    for (i = 0; i < 8; i++) {
        mem[o++] = (uint8_t)((t >> (8 * i)) & 0xFFu);
    }
    mem[o++] = 0x41; /* call r10 */
    mem[o++] = 0xFF;
    mem[o++] = 0xD2;
    mem[o++] = 0x4D; /* mov [r9], r8        -> out[0] */
    mem[o++] = 0x89;
    mem[o++] = 0x01;
    mem[o++] = 0x41; /* mov [r9+8], eax     -> out[1] */
    mem[o++] = 0x89;
    mem[o++] = 0x41;
    mem[o++] = 0x08;
    mem[o++] = 0x48; /* mov rax, [rsp+0x88] (spill do alvo; disp32!) */
    mem[o++] = 0x8B;
    mem[o++] = 0x84;
    mem[o++] = 0x24;
    mem[o++] = 0x88;
    mem[o++] = 0x00;
    mem[o++] = 0x00;
    mem[o++] = 0x00;
    mem[o++] = 0x49; /* mov [r9+16], rax    -> out[2] */
    mem[o++] = 0x89;
    mem[o++] = 0x41;
    mem[o++] = 0x10;
    mem[o++] = 0x48; /* mov rax, [rbx]      (rbp salvo do caller) */
    mem[o++] = 0x8B;
    mem[o++] = 0x03;
    mem[o++] = 0x49; /* mov [r9+24], rax    -> out[3] */
    mem[o++] = 0x89;
    mem[o++] = 0x41;
    mem[o++] = 0x18;
    mem[o++] = 0x48; /* mov rax, rbp        (rbp após o alvo) */
    mem[o++] = 0x89;
    mem[o++] = 0xE8;
    mem[o++] = 0x49; /* mov [r9+32], rax    -> out[4] */
    mem[o++] = 0x89;
    mem[o++] = 0x41;
    mem[o++] = 0x20;
    mem[o++] = 0x48; /* mov rsp, rbx */
    mem[o++] = 0x89;
    mem[o++] = 0xDC;
    mem[o++] = 0x5D; /* pop rbp */
    mem[o++] = 0x5B; /* pop rbx */
    mem[o++] = 0xC3; /* ret */
    clear_icache(mem, (size_t)o + 32);
    return mem;
}

/* ------------------------------------------------------------------------- */
/* (1) Âncora forense no executável real do título                            */
/* ------------------------------------------------------------------------- */
static void test_forensic_anchor(void)
{
    const char *path = find_title_exe();
    uint8_t guard_seq[FM5_VIS_GUARD_SEQ_LEN];
    uint8_t branch[FM5_VIS_BRANCH_ORIG_LEN];
    uint8_t append_path[2];
    uint8_t shift_path[2];
    uint8_t loop_head[3];
    uint8_t loop_cmp[3];
    uint8_t loop_jne[2];
    static const uint8_t want_loop_head[3] = { 0x8B, 0x47, 0xF0 };
    static const uint8_t want_loop_cmp[3] = { 0x48, 0x3B, 0xCF };
    static const uint8_t want_loop_jne[2] = { 0x75, 0xD8 };

    CHECK(path != NULL,
          "executavel do titulo ausente (Game/Mount/forza_durango_release_final.exe)");
    if (path == NULL) {
        return;
    }
    CHECK(read_pe_rva(path, FM5_VIS_GUARD_RVA, guard_seq,
                      sizeof(guard_seq)) == 1,
          "nao foi possivel ler 0x859500 do executavel do titulo");
    CHECK(memcmp(guard_seq, fm5_vis_guard_sequence(),
                 FM5_VIS_GUARD_SEQ_LEN) == 0,
          "sequencia viva em 0x859500 diverge da constante forense "
          "(vmovaps; sub rax,r8; sar rax,4)");

    CHECK(read_pe_rva(path, FM5_VIS_BRANCH_RVA, branch, sizeof(branch)) == 1,
          "nao foi possivel ler 0x859516 do executavel do titulo");
    CHECK(memcmp(branch, fm5_vis_branch_original(),
                 FM5_VIS_BRANCH_ORIG_LEN) == 0,
          "0x859516 nao e `0f 83 8d 00 00 00` (JAE +0x8d) do build 1.0.0.20");
    CHECK(branch[2] == 0x8D && branch[3] == 0x00 && branch[4] == 0x00 &&
              branch[5] == 0x00,
          "deslocamento do branch nao e +0x8d (destino do laco de copia)");

    CHECK(read_pe_rva(path, FM5_VIS_BRANCH_FALLTHROUGH_RVA, append_path,
                      sizeof(append_path)) == 1,
          "nao foi possivel ler 0x85951c (caminho de insercao no fim)");
    CHECK(append_path[0] == 0x8B && append_path[1] == 0x3B,
          "0x85951c nao e o caminho de insercao no fim (mov edi,[rbx])");
    CHECK(read_pe_rva(path, FM5_VIS_BRANCH_SHIFT_RVA, shift_path,
                      sizeof(shift_path)) == 1,
          "nao foi possivel ler 0x8595a9 (caminho de shift)");
    CHECK(shift_path[0] == 0x8B && shift_path[1] == 0x2B,
          "0x8595a9 nao e o caminho de shift (mov ebp,[rbx])");

    CHECK(read_pe_rva(path, 0x8595E0u, loop_head, sizeof(loop_head)) == 1,
          "nao foi possivel ler 0x8595e0 (rip do crash)");
    CHECK(memcmp(loop_head, want_loop_head, sizeof(loop_head)) == 0,
          "0x8595e0 nao e `mov eax,[rdi-0x10]` (laco de copia para tras)");
    CHECK(read_pe_rva(path, 0x859603u, loop_cmp, sizeof(loop_cmp)) == 1,
          "nao foi possivel ler 0x859603");
    CHECK(memcmp(loop_cmp, want_loop_cmp, sizeof(loop_cmp)) == 0,
          "0x859603 nao e `cmp rdi,rcx` (a comparacao que nunca fecha)");
    CHECK(read_pe_rva(path, 0x859606u, loop_jne, sizeof(loop_jne)) == 1,
          "nao foi possivel ler 0x859606");
    CHECK(memcmp(loop_jne, want_loop_jne, sizeof(loop_jne)) == 0,
          "0x859606 nao e `jne 0x8595e0` (o laco desgovernado)");

    /* Camada [3]: helper de cópia 0x85b770 (crash rip=0x14085b77a). */
    {
        uint8_t helper[FM5_VIS_HELPER_SEQ_LEN];
        uint8_t wordb[2];
        uint8_t site[5];
        uint8_t endb[3];
        static const uint32_t call_sites[FM5_VIS_HELPER_CALL_SITES] = {
            0x859294u, 0x859480u, 0x85949Fu, 0x859538u, 0x8595B9u
        };
        size_t si;

        CHECK(read_pe_rva(path, FM5_VIS_HELPER_RVA, helper,
                          sizeof(helper)) == 1,
              "nao foi possivel ler 0x85b770 do executavel do titulo");
        CHECK(memcmp(helper, fm5_vis_helper_original(),
                     FM5_VIS_HELPER_SEQ_LEN) == 0,
              "0x85b770 nao e `48 3b ca 74 26` (cmp rcx,rdx; je +0x26)");
        CHECK(fm5_vis_is_helper_original(helper) == 1 &&
                  fm5_vis_is_helper_fixed(helper) == 0,
              "classificacao forense do helper divergente");
        CHECK(read_pe_rva(path, FM5_VIS_HELPER_STORE_RVA, wordb,
                          sizeof(wordb)) == 1 &&
                  (uint16_t)(wordb[0] | ((uint16_t)wordb[1] << 8)) ==
                      FM5_VIS_HELPER_ORIG_WORD,
              "word em 0x85b772 nao e 0x74ca (byte do je em 0x85b773)");
        CHECK(read_pe_rva(path, 0x85b79Bu, endb, sizeof(endb)) == 1 &&
                  endb[0] == 0x49 && endb[1] == 0x8B && endb[2] == 0xC0,
              "destino do je/0x85b79b nao e `mov rax,r8`");
        CHECK(read_pe_rva(path, 0x85b79Eu, endb, 1) == 1 && endb[0] == 0xC3,
              "0x85b79e nao e o `ret` do helper");
        {
            uint8_t fixedb[FM5_VIS_HELPER_SEQ_LEN];
            memcpy(fixedb, helper, sizeof(fixedb));
            fm5_vis_encode_helper_fix(fixedb);
            CHECK(fixedb[3] == 0x73 && fixedb[4] == 0x26 &&
                      fm5_vis_is_helper_fixed(fixedb) == 1,
                  "encode_helper_fix nao gravou `73 26` (JAE)");
        }
        /* Os 5 call sites reais têm de apontar para 0x85b770. */
        for (si = 0; si < FM5_VIS_HELPER_CALL_SITES; si++) {
            int32_t rel;
            uint64_t dest;
            CHECK(read_pe_rva(path, call_sites[si], site, sizeof(site)) == 1,
                  "nao foi possivel ler um call site do helper");
            rel = (int32_t)((uint32_t)site[1] | ((uint32_t)site[2] << 8) |
                            ((uint32_t)site[3] << 16) |
                            ((uint32_t)site[4] << 24));
            dest = (uint64_t)((int64_t)call_sites[si] + 5 + (int64_t)rel);
            CHECK(site[0] == 0xE8 && dest == FM5_VIS_HELPER_RVA,
                  "call site do helper nao aponta para 0x85b770");
        }
    }

    /* Camada [4]: fonte do insert 0x8580e0 (o call em 0x8580e8). */
    {
        uint8_t src[FM5_VIS_SRC_SEQ_LEN];
        uint8_t callb[5];
        int32_t rel;
        uint64_t dest;

        CHECK(read_pe_rva(path, FM5_VIS_SRC_RVA, src, sizeof(src)) == 1,
              "nao foi possivel ler 0x8580e0 do executavel do titulo");
        CHECK(memcmp(src, fm5_vis_src_sequence(), FM5_VIS_SRC_SEQ_LEN) == 0,
              "0x8580e0 nao e `4d 8b c3 48 89 44 24 20`");
        CHECK(read_pe_rva(path, FM5_VIS_SRC_RESUME_RVA, callb,
                          sizeof(callb)) == 1,
              "nao foi possivel ler 0x8580e8 (call do insert)");
        rel = (int32_t)((uint32_t)callb[1] | ((uint32_t)callb[2] << 8) |
                        ((uint32_t)callb[3] << 16) |
                        ((uint32_t)callb[4] << 24));
        dest = (uint64_t)((int64_t)FM5_VIS_SRC_RESUME_RVA + 5 + (int64_t)rel);
        CHECK(callb[0] == 0xE8 && dest == 0x859390u,
              "0x8580e8 nao e `call vector::insert` (0x859390)");
    }
}

/* ------------------------------------------------------------------------- */
/* (2) Codificação pura do patch e da caverna                                 */
/* ------------------------------------------------------------------------- */
static void test_encoding(void)
{
    uint8_t branch[FM5_VIS_BRANCH_ORIG_LEN];
    uint8_t cave[FM5_VIS_GUARD_CAVE_LEN + 8];
    uint8_t jump[FM5_VIS_JUMP_LEN];
    uint64_t resume = 0x14085950DULL;
    uint64_t target = 0x140859500ULL;
    uint64_t cave_addr = 0x1407A0000ULL;
    size_t n;

    CHECK(FM5_VIS_BRANCH_RVA == 0x859516u, "RVA do branch deve ser 0x859516");
    CHECK(FM5_VIS_GUARD_RVA == 0x859500u,
          "RVA da trava deve ser 0x859500 (fronteira da funcao)");
    CHECK(FM5_VIS_GUARD_RESUME_RVA == 0x85950Du,
          "retomada deve ser 0x85950d (apos o sar)");
    CHECK(FM5_VIS_GUARD_CAVE_OPCODES_LEN == 35u,
          "opcodes da caverna de trava tem 35 bytes");
    CHECK(FM5_VIS_GUARD_CAVE_LEN == 49u,
          "caverna completa (35 opcodes + 14 de cauda) tem 49 bytes");
    CHECK(FM5_VIS_HELPER_RVA == 0x85B770u, "RVA do helper deve ser 0x85b770");
    CHECK(FM5_VIS_HELPER_JCC_RVA == 0x85B773u,
          "byte do jcc do helper deve ser 0x85b773");
    CHECK(FM5_VIS_HELPER_STORE_RVA == 0x85B772u,
          "word do helper deve ser 0x85b772 (par)");
    CHECK(FM5_VIS_HELPER_ORIG_WORD == 0x74CAu &&
              FM5_VIS_HELPER_FIXED_WORD == 0x73CAu,
          "words do helper devem ser 0x74ca/0x73ca (little-endian)");
    CHECK(FM5_VIS_SRC_RVA == 0x8580E0u, "RVA da fonte deve ser 0x8580e0");
    CHECK(FM5_VIS_SRC_RESUME_RVA == 0x8580E8u,
          "retomada da fonte deve ser 0x8580e8 (call do insert)");
    CHECK(FM5_VIS_MYLAST_RVA == 0x24717D8u,
          "RVA do global _Mylast deve ser 0x24717d8");

    memcpy(branch, fm5_vis_branch_original(), sizeof(branch));
    CHECK(fm5_vis_is_branch_original(branch) == 1,
          "is_branch_original deve aceitar o JAE do crash");
    fm5_vis_encode_branch_fix(branch);
    CHECK(branch[0] == 0x0F && branch[1] == 0x8D,
          "encode_branch_fix nao gravou `0f 8d` (JGE)");
    CHECK(memcmp(branch, fm5_vis_branch_fixed(), sizeof(branch)) == 0,
          "patch nao preservou o deslocamento rel32 +0x8d");
    CHECK(fm5_vis_is_branch_fixed(branch) == 1,
          "is_branch_fixed deve aceitar o JGE corrigido");
    CHECK(fm5_vis_is_branch_original(branch) == 0,
          "is_branch_original nao deve aceitar o JGE");
    branch[2] ^= 0x01;
    CHECK(fm5_vis_is_branch_original(branch) == 0 &&
              fm5_vis_is_branch_fixed(branch) == 0,
          "assinatura corrompida deve ser rejeitada (fail-closed)");
    CHECK(fm5_vis_is_branch_original(NULL) == 0 &&
              fm5_vis_is_branch_fixed(NULL) == 0,
          "assinatura NULL deve ser fail-closed");

    memset(cave, 0xAA, sizeof(cave));
    n = fm5_vis_encode_guard_cave(cave, sizeof(cave), resume);
    CHECK(n == FM5_VIS_GUARD_CAVE_LEN,
          "encode_guard_cave deve devolver FM5_VIS_GUARD_CAVE_LEN");
    CHECK(memcmp(cave, fm5_vis_guard_sequence(),
                 FM5_VIS_GUARD_SEQ_LEN) == 0,
          "preambulo da caverna nao reemite vmovaps/sub/sar");
    CHECK(cave[13] == 0x4C && cave[14] == 0x39 && cave[15] == 0xC2,
          "caverna nao compara _Mylast (rdx) com where (r8)");
    CHECK(cave[16] == 0x7D && cave[17] == 0x11,
          "caverna nao salta (jge +0x11) por cima das travas");
    CHECK(18 + (int8_t)cave[17] == (int)FM5_VIS_GUARD_CAVE_OPCODES_LEN,
          "alvo do jge nao e o inicio da cauda (off 35)");
    CHECK(cave[18] == 0x49 && cave[19] == 0x89 && cave[20] == 0xD0,
          "caverna nao trava copia 1 (mov r8,rdx)");
    CHECK(cave[21] == 0x48 && cave[22] == 0x89 && cave[23] == 0xD5,
          "caverna nao trava copia 2 (mov rbp,rdx)");
    CHECK(cave[24] == 0x48 && cave[25] == 0x89 && cave[26] == 0x94 &&
              cave[27] == 0x24 && cave[28] == 0x90 && cave[29] == 0x00 &&
              cave[30] == 0x00 && cave[31] == 0x00,
          "caverna nao trava copia 3 (mov [rsp+0x90],rdx)");
    CHECK(cave[32] == 0x48 && cave[33] == 0x31 && cave[34] == 0xC0,
          "caverna nao zera o count (xor eax,eax)");
    CHECK(cave[35] == 0xFF && cave[36] == 0x25 && cave[37] == 0x00 &&
              cave[38] == 0x00 && cave[39] == 0x00 && cave[40] == 0x00,
          "cauda da caverna nao e jmp qword [rip+0]");
    CHECK(memcmp(cave + 41, &resume, 8) == 0,
          "endereco de retomada nao foi gravado em little-endian");
    CHECK(fm5_vis_encode_guard_cave(cave, FM5_VIS_GUARD_CAVE_LEN - 1,
                                    resume) == 0,
          "capacidade insuficiente deve falhar (fail-closed)");
    CHECK(fm5_vis_encode_guard_cave(NULL, sizeof(cave), resume) == 0,
          "caverna com destino NULL deve falhar");

    /* Camada [3]: fix do helper. */
    {
        uint8_t h[FM5_VIS_HELPER_SEQ_LEN];
        memcpy(h, fm5_vis_helper_original(), sizeof(h));
        CHECK(h[0] == 0x48 && h[1] == 0x3B && h[2] == 0xCA &&
                  h[3] == 0x74 && h[4] == 0x26,
              "helper original nao e `48 3b ca 74 26`");
        CHECK(fm5_vis_is_helper_original(h) == 1,
              "is_helper_original nao aceita o JE do titulo");
        fm5_vis_encode_helper_fix(h);
        CHECK(h[3] == 0x73 && h[4] == 0x26,
              "encode_helper_fix nao gravou `73 26` (JAE)");
        CHECK(fm5_vis_is_helper_fixed(h) == 1 &&
                  fm5_vis_is_helper_original(h) == 0,
              "classificacao do helper pos-fix divergente");
        h[4] ^= 0x01;
        CHECK(fm5_vis_is_helper_fixed(h) == 0,
              "helper corrompido deve ser rejeitado (fail-closed)");
        CHECK(fm5_vis_is_helper_original(NULL) == 0 &&
                  fm5_vis_is_helper_fixed(NULL) == 0,
              "helper NULL deve ser fail-closed");
    }

    /* Camada [4]: caverna da fonte (clamp de where em _Mylast). */
    {
        uint8_t src[FM5_VIS_SRC_CAVE_LEN + 8];
        uint64_t cave_addr = 0x1407A0040ULL;
        uint64_t mylast_addr = 0x1424717D8ULL; /* imagebase 0x140000000 + */
        uint64_t src_resume = 0x1408580E8ULL;
        int32_t disp;
        uint64_t got;

        CHECK(FM5_VIS_SRC_CAVE_OPCODES_LEN == 23u &&
                  FM5_VIS_SRC_CAVE_LEN == 37u,
              "caverna da fonte deve ter 23 opcodes + 14 de cauda (37)");
        memset(src, 0xAA, sizeof(src));
        n = fm5_vis_encode_src_cave(src, sizeof(src), cave_addr,
                                    mylast_addr, src_resume);
        CHECK(n == FM5_VIS_SRC_CAVE_LEN,
              "encode_src_cave deve devolver FM5_VIS_SRC_CAVE_LEN");
        CHECK(memcmp(src, fm5_vis_src_sequence(), FM5_VIS_SRC_SEQ_LEN) == 0,
              "preambulo da caverna da fonte nao reemite mov r8,r11; "
              "mov [rsp+0x20],rax");
        CHECK(src[8] == 0x48 && src[9] == 0x8B && src[10] == 0x0D,
              "caverna da fonte nao le o global _Mylast (mov rcx,[rip])");
        memcpy(&disp, src + FM5_VIS_SRC_CAVE_DISP_OFF, 4);
        CHECK((uint64_t)((int64_t)cave_addr + FM5_VIS_SRC_CAVE_DISP_RIP +
                         (int64_t)disp) == mylast_addr,
              "disp32 rip-relative da fonte nao resolve para _Mylast");
        CHECK(src[15] == 0x49 && src[16] == 0x39 && src[17] == 0xC8,
              "caverna da fonte nao compara where (r8) com _Mylast (rcx)");
        CHECK(src[18] == 0x76 && src[19] == 0x03,
              "caverna da fonte nao salta (jbe +3) por cima da trava");
        CHECK(20 + (int8_t)src[19] == (int)FM5_VIS_SRC_CAVE_OPCODES_LEN,
              "alvo do jbe da fonte nao e o inicio da cauda (off 23)");
        CHECK(src[20] == 0x49 && src[21] == 0x89 && src[22] == 0xC8,
              "caverna da fonte nao trava where = _Mylast (mov r8,rcx)");
        CHECK(src[23] == 0xFF && src[24] == 0x25,
              "cauda da caverna da fonte nao e jmp qword [rip+0]");
        memcpy(&got, src + 29, 8);
        CHECK(got == src_resume,
              "retomada da caverna da fonte nao e 0x8580e8");
        CHECK(fm5_vis_encode_src_cave(src, FM5_VIS_SRC_CAVE_LEN - 1,
                                      cave_addr, mylast_addr,
                                      src_resume) == 0,
              "capacidade insuficiente da fonte deve falhar");
        CHECK(fm5_vis_encode_src_cave(NULL, sizeof(src), cave_addr,
                                      mylast_addr, src_resume) == 0,
              "caverna da fonte NULL deve falhar");
        CHECK(fm5_vis_encode_src_cave(src, sizeof(src), cave_addr,
                                      cave_addr + 0x90000000ULL,
                                      src_resume) == 0,
              "disp32 fora de +-2 GiB deve falhar (fail-closed)");
        CHECK(fm5_vis_is_src_sequence(NULL) == 0,
              "sequencia da fonte NULL deve ser fail-closed");
    }

    CHECK(fm5_vis_encode_jump(jump, target, cave_addr) == 0,
          "salto dentro do alcance deve ser codificado");
    CHECK(jump[0] == 0xE9, "opcode do salto de entrada deve ser E9");
    {
        /* decode_jump resolve relativo ao ENDEREÇO da instrução: publicamos o
         * E9 num buffer executável real e conferimos o destino absoluto. */
        uint8_t *slot = alloc_rwx(64);
        CHECK(slot != NULL, "mmap do slot do salto falhou");
        if (slot != NULL) {
            uint64_t near_cave = (uint64_t)(uintptr_t)slot + 0x10000ULL;
            CHECK(fm5_vis_encode_jump(slot, (uint64_t)(uintptr_t)slot,
                                      near_cave) == 0,
                  "encode no slot real falhou");
            CHECK(fm5_vis_decode_jump(slot) == near_cave,
                  "decode_jump nao devolve a caverna de destino");
            free_rwx(slot, 64);
        }
    }
    CHECK(fm5_vis_encode_jump(jump, target, target + 0x90000000ULL) == -1,
          "salto fora de +-2 GiB deve falhar (fail-closed)");
    CHECK(fm5_vis_encode_jump(NULL, target, cave_addr) == -1,
          "salto com destino NULL deve falhar");
}

/* ------------------------------------------------------------------------- */
/* (3) Decisão real: os mesmos opcodes de 0x859506..0x859516                  */
/* ------------------------------------------------------------------------- */
/*
 * Entrada = exatamente 0x859506 do jogo (o thunk já deixou r8=where,
 * rdx=_Mylast e rax=_Mylast, como o prólogo original):
 *   49 2b c0          sub rax, r8           ; _Mylast - where
 *   48 c1 f8 04       sar rax, 4            ; count
 *   48 83 f8 01       cmp rax, 1
 *   0f 8? 03 00 00 00 jcc shift              ; JAE (original) ou JGE (fix)
 *   safe:  xor eax,eax ; ret                ; inserção no fim
 *   shift: mov eax,1 ; ret                  ; caminho de shift
 */
static uint8_t *build_decision_wrapper(uint8_t *mem, int fixed)
{
    static const uint8_t head[] = {
        0x49, 0x2B, 0xC0,
        0x48, 0xC1, 0xF8, 0x04,
        0x48, 0x83, 0xF8, 0x01
    };
    size_t o = sizeof(head);

    memcpy(mem, head, sizeof(head));
    mem[o++] = 0x0F;
    /* Opcode lido do ENCODER DE PRODUÇÃO (não um literal do teste): uma
     * regressão em FM5_VIS_BRANCH_FIXED_BYTES reprova aqui também. */
    mem[o++] = fixed ? fm5_vis_branch_fixed()[1]
                     : fm5_vis_branch_original()[1];
    mem[o++] = 0x03;
    mem[o++] = 0x00;
    mem[o++] = 0x00;
    mem[o++] = 0x00;
    mem[o++] = 0x31;
    mem[o++] = 0xC0;
    mem[o++] = 0xC3;
    mem[o++] = 0xB8;
    mem[o++] = 0x01;
    mem[o++] = 0x00;
    mem[o++] = 0x00;
    mem[o++] = 0x00;
    mem[o++] = 0xC3;
    clear_icache(mem, o);
    return mem;
}

/* ------------------------------------------------------------------------- */
/* (4) Controle negativo real: laço de cópia para trás morre com SIGSEGV      */
/* ------------------------------------------------------------------------- */
static uint8_t *build_runaway(uint8_t *mem)
{
    static const uint8_t head[] = {
        0x49, 0x2B, 0xC0,       /* sub rax, r8  (0x859506) */
        0x48, 0xC1, 0xF8, 0x04, /* sar rax, 4   (0x859509) */
        0x48, 0x83, 0xF8, 0x01  /* cmp rax, 1   (0x859512) */
    };
    size_t o = sizeof(head);

    memcpy(mem, head, sizeof(head));
    mem[o++] = 0x0F; /* jae +1 -> shift (logo após o ret do caminho seguro) */
    mem[o++] = fm5_vis_branch_original()[1]; /* 0x83: JAE do crash */
    mem[o++] = 0x01;
    mem[o++] = 0x00;
    mem[o++] = 0x00;
    mem[o++] = 0x00;
    mem[o++] = 0xC3;       /* safe: ret */
    mem[o++] = 0x4C;       /* shift: mov rcx,r8 (where) */
    mem[o++] = 0x89;
    mem[o++] = 0xC1;
    mem[o++] = 0x48;       /* lea rdi,[rdx-0x10] (_Mylast-16) */
    mem[o++] = 0x8D;
    mem[o++] = 0x7A;
    mem[o++] = 0xF0;
    mem[o++] = 0x8B;       /* L: mov eax,[rdi-16] */
    mem[o++] = 0x47;
    mem[o++] = 0xF0;
    mem[o++] = 0x89;       /* mov [rdi-16],eax (escrita descendente) */
    mem[o++] = 0x47;
    mem[o++] = 0xF0;
    mem[o++] = 0x48;       /* sub rdi,16 */
    mem[o++] = 0x83;
    mem[o++] = 0xEF;
    mem[o++] = 0x10;
    mem[o++] = 0x48;       /* cmp rdi,rcx */
    mem[o++] = 0x3B;
    mem[o++] = 0xCF;
    mem[o++] = 0x75;       /* jne L  (next=o+2; disp = L-(o+2) = -15) */
    mem[o++] = 0xF1;
    mem[o++] = 0xC3;       /* ret (inalcançável quando há runaway) */
    clear_icache(mem, o);
    return mem;
}

static void test_runaway_crash_control(void)
{
    /* where fica DEPOIS de _Mylast em todas as distâncias: é exatamente o
     * universo de _Mylast - where < 0 (count negativo). O laço do JAE tem de
     * desgovernar em TODAS, não só no delta forense de ~1 MB. */
    static const uint64_t dists[] = {
        1ULL, 0x10ULL, 0x1000ULL, 0x1013F8ULL, 0x7FFFFFFFULL
    };
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *region;
    uint8_t *buf;
    uint8_t *code_mem;
    uint8_t *thunk;
    uint64_t mylast;
    size_t di;

    region = (uint8_t *)mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(region != NULL && region != MAP_FAILED,
          "mmap do buffer de dados falhou");
    if (region == NULL || region == MAP_FAILED) {
        return;
    }
    CHECK(mprotect(region, page, PROT_NONE) == 0,
          "mprotect da pagina-guarda falhou");
    buf = region + page;

    code_mem = alloc_rwx(4096);
    CHECK(code_mem != NULL, "mmap RWX do controle negativo falhou");
    if (code_mem == NULL) {
        munmap(region, page * 2);
        return;
    }
    thunk = build_thunk(code_mem + 2048, build_runaway(code_mem));

    mylast = (uint64_t)(uintptr_t)(buf + 0x100);
    for (di = 0; di < sizeof(dists) / sizeof(dists[0]); di++) {
        uint64_t where = mylast + dists[di];
        pid_t pid;
        int status = 0;

        pid = fork();
        CHECK(pid >= 0, "fork do controle negativo falhou");
        if (pid == 0) {
            uint64_t res[5] = { 0, 0 };
            ((run_thunk_fn)thunk)(where, mylast, res);
            _exit(0); /* só chega aqui se o laço NÃO desgovernou */
        } else if (pid > 0) {
            CHECK(waitpid(pid, &status, 0) == pid,
                  "waitpid do controle negativo falhou");
            CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV,
                  "controle negativo NAO morreu com SIGSEGV: o JAE unsigned "
                  "nao reproduziu o laco de copia para tras");
        }
    }
    printf("OK: controle negativo (JAE unsigned) morreu com SIGSEGV no laco "
           "de copia para tras em %zu distancias where > _Mylast\n",
           sizeof(dists) / sizeof(dists[0]));

    free_rwx(code_mem, 4096);
    munmap(region, page * 2);
}

/* ------------------------------------------------------------------------- */
/* (5) Execução da trava real (caverna) com JAE e com JGE                     */
/* ------------------------------------------------------------------------- */
/*
 * Réplica fiel do alvo a partir de 0x859500:
 *   fn+0..12 : os 13 bytes REAIS copiados do executável do título
 *   fn+13    : cmp rax,1
 *   fn+17    : jae/jge +rel32 -> shift
 *   fn+23    : safe (xor eax,eax; ret)
 *   fn+26    : shift (mov eax,1; ret)
 * A caverna é montada pelo encoder de produção e o E9 é publicado no entry
 * com um único store de 64 bits (fn é 8-byte aligned).
 */
static uint8_t *build_guarded_insert(uint8_t *mem, uint8_t *cave_mem,
                                     int fixed)
{
    static const uint8_t tail[] = {
        0x48, 0x83, 0xF8, 0x01, /* cmp rax,1             (fn+13) */
        0x0F, 0x00, 0x03, 0x00, 0x00, 0x00, /* jcc +3 (fn+17) */
        0x31, 0xC0, 0xC3,       /* safe: xor eax,eax;ret (fn+23) */
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 /* shift: mov eax,1;ret */
    };
    uint8_t patch[8];
    uint64_t word = 0;
    size_t cave_len;

    memcpy(mem, fm5_vis_guard_sequence(), FM5_VIS_GUARD_SEQ_LEN);
    memcpy(mem + FM5_VIS_GUARD_SEQ_LEN, tail, sizeof(tail));
    /* Opcode do jcc vindo do encoder de produção (JAE original ou JGE fix). */
    mem[FM5_VIS_GUARD_SEQ_LEN + 5] = fixed ? fm5_vis_branch_fixed()[1]
                                           : fm5_vis_branch_original()[1];

    cave_len = fm5_vis_encode_guard_cave(cave_mem, 64,
                                         (uint64_t)(uintptr_t)(
                                             mem + FM5_VIS_GUARD_SEQ_LEN));
    CHECK(cave_len == FM5_VIS_GUARD_CAVE_LEN,
          "montagem da caverna de trava falhou");
    if (cave_len != FM5_VIS_GUARD_CAVE_LEN) {
        return NULL;
    }
    CHECK(fm5_vis_encode_jump(patch, (uint64_t)(uintptr_t)mem,
                              (uint64_t)(uintptr_t)cave_mem) == 0,
          "E9 de entrada da trava fora de alcance");
    patch[5] = 0x90;
    patch[6] = 0x90;
    patch[7] = 0x90;
    memcpy(&word, patch, 8);
    CHECK(((uintptr_t)mem & 7u) == 0,
          "entry da trava nao esta 8-byte aligned (store atomico impossivel)");
    *(volatile uint64_t *)(void *)mem = word;
    clear_icache(mem, 64);
    return mem;
}

static void run_clamp_cases(const char *label, int fixed)
{
    uint8_t *mem = alloc_rwx(4096);
    uint8_t *thunk;
    uint64_t mylast = 0x0000040000000018ULL;
    uint64_t res[5];

    CHECK(mem != NULL, "mmap RWX da trava falhou");
    if (mem == NULL) {
        return;
    }
    if (build_guarded_insert(mem, mem + 512, fixed) == NULL) {
        free_rwx(mem, 4096);
        return;
    }
    thunk = build_thunk(mem + 2048, mem);

    /* where > _Mylast (1 MB depois, delta do crash real): TRAVA em _Mylast
     * nas TRÊS cópias (r8, rbp e o spill [rsp+0x90]) + count 0 -> caminho de
     * inserção no fim (eax == 0), sem laço. */
    res[0] = 0;
    res[1] = 0xFFFFu;
    ((run_thunk_fn)thunk)(mylast + 0x1013F8ULL, mylast, res);
    CHECK(res[0] == mylast,
          "trava nao fixou where = _Mylast para where >> _Mylast");
    CHECK(res[1] == 0,
          "trava nao zerou o count: fluxo nao caiu no caminho de fim");
    CHECK(res[2] == mylast,
          "trava nao fixou o spill [rsp+0x90] = _Mylast (copia 3)");
    CHECK(res[4] == mylast,
          "trava nao fixou rbp = _Mylast (copia 2)");
    printf("OK: %s where > _Mylast travado nas 3 copias (out=0x%llx)\n",
           label, (unsigned long long)res[0]);

    /* Matriz de distâncias positivas: a trava tem de fechar TODAS, não só o
     * delta forense (~1 MB). where = _Mylast + d para d > 0 é exatamente o
     * caso em que _Mylast - where é negativo. */
    {
        static const uint64_t dists[] = {
            1ULL, 0x10ULL, 0x100ULL, 0x1000ULL, 0x1013F8ULL,
            0x7FFFFFFFULL, 0x123456789ULL
        };
        size_t di;
        for (di = 0; di < sizeof(dists) / sizeof(dists[0]); di++) {
            res[0] = 0;
            res[1] = 0xFFFFu;
            ((run_thunk_fn)thunk)(mylast + dists[di], mylast, res);
            CHECK(res[0] == mylast,
                  "trava nao fixou where = _Mylast para distancia positiva "
                  "da matriz");
            CHECK(res[1] == 0,
                  "trava nao zerou o count para distancia positiva da matriz");
            CHECK(res[2] == mylast && res[4] == mylast,
                  "trava nao fixou spill/rbp para distancia positiva");
        }
    }

    /* where == _Mylast: caminho de fim normal, sem tocar em nada (jge
     * tomado: as três cópias e as sentinelas ficam intactas). */
    res[0] = 0;
    res[1] = 0xFFFFu;
    ((run_thunk_fn)thunk)(mylast, mylast, res);
    CHECK(res[0] == mylast, "caso where == _Mylast alterou where");
    CHECK(res[1] == 0, "caso where == _Mylast nao caiu no caminho de fim");
    CHECK(res[2] == FM5_SPILL_SENTINEL,
          "caso where == _Mylast tocou no spill (trava nao devia rodar)");
    CHECK(res[4] == FM5_RBP_SENTINEL,
          "caso where == _Mylast tocou no rbp (trava nao devia rodar)");

    /* where = _Mylast - 16 (count 1): caminho de shift preservado. */
    res[0] = 0;
    res[1] = 0xFFFFu;
    ((run_thunk_fn)thunk)(mylast - 0x10ULL, mylast, res);
    CHECK(res[0] == mylast - 0x10ULL,
          "trava alterou where no caminho de shift (count == 1)");
    CHECK(res[1] == 1,
          "trava suprimiu o caminho de shift (count == 1)");
    CHECK(res[2] == FM5_SPILL_SENTINEL,
          "caminho de shift tocou no spill (trava nao devia rodar)");
    CHECK(res[4] == FM5_RBP_SENTINEL,
          "caminho de shift tocou no rbp (trava nao devia rodar)");

    free_rwx(mem, 4096);
}

static void test_clamp_execution(void)
{
    /* (a) com o JAE ORIGINAL intacto: a trava sozinha já fecha o crash. */
    run_clamp_cases("JAE original + trava", 0);
    /* (b) com o JGE já aplicado (produção): caminho idêntico. */
    run_clamp_cases("JGE corrigido + trava", 1);
}

static void test_decision_with_fix(void)
{
    uint8_t *mem_plain = alloc_rwx(4096);
    uint8_t *mem_fixed = alloc_rwx(4096);
    uint8_t *thunk_plain;
    uint8_t *thunk_fixed;
    uint64_t mylast = 0x1000ULL;
    uint64_t res[5];

    CHECK(mem_plain != NULL && mem_fixed != NULL,
          "mmap RWX da decisao falhou");
    if (mem_plain == NULL || mem_fixed == NULL) {
        free_rwx(mem_plain, 4096);
        free_rwx(mem_fixed, 4096);
        return;
    }
    thunk_plain = build_thunk(mem_plain + 2048,
                              build_decision_wrapper(mem_plain, 0));
    thunk_fixed = build_thunk(mem_fixed + 2048,
                              build_decision_wrapper(mem_fixed, 1));

    /* JAE (unsigned) com where > _Mylast: COUNT negativo -> salta para o
     * caminho de shift (eax == 1), que no jogo é o laço de cópia para trás. */
    res[0] = 0;
    res[1] = 0xFFFFu;
    ((run_thunk_fn)thunk_plain)(mylast + 0x1013F8ULL, mylast, res);
    CHECK(res[1] == 1,
          "JAE original nao tomou o caminho de shift para where > _Mylast "
          "(o bug nao seria reproduzido)");
    CHECK(res[0] == mylast + 0x1013F8ULL,
          "decisao alterou where (nao deveria nesta camada)");

    /* JGE (signed) com o mesmo where > _Mylast: NAO salta -> caminho de fim. */
    res[0] = 0;
    res[1] = 0xFFFFu;
    ((run_thunk_fn)thunk_fixed)(mylast + 0x1013F8ULL, mylast, res);
    CHECK(res[1] == 0,
          "JGE corrigido ainda saltou para o shift com where > _Mylast");
    printf("OK: JAE original -> shift (bug); JGE corrigido -> insercao no fim\n");

    /* where == _Mylast: os DOIS opcodes caem no caminho de fim (count 0). */
    res[0] = 0;
    res[1] = 0xFFFFu;
    ((run_thunk_fn)thunk_plain)(mylast, mylast, res);
    CHECK(res[1] == 0, "JAE: where == _Mylast deveria inserir no fim");
    res[0] = 0;
    res[1] = 0xFFFFu;
    ((run_thunk_fn)thunk_fixed)(mylast, mylast, res);
    CHECK(res[1] == 0, "JGE: where == _Mylast deveria inserir no fim");

    /* where = _Mylast - 16 (count 1): os DOIS tomam o shift (sem regressao). */
    res[0] = 0;
    res[1] = 0xFFFFu;
    ((run_thunk_fn)thunk_plain)(mylast - 0x10ULL, mylast, res);
    CHECK(res[1] == 1, "JAE: count == 1 deveria tomar o shift");
    res[0] = 0;
    res[1] = 0xFFFFu;
    ((run_thunk_fn)thunk_fixed)(mylast - 0x10ULL, mylast, res);
    CHECK(res[1] == 1, "JGE: count == 1 deveria tomar o shift");
    CHECK(res[0] == mylast - 0x10ULL, "JGE alterou where no caso count == 1");

    free_rwx(mem_plain, 4096);
    free_rwx(mem_fixed, 4096);
}

/* ------------------------------------------------------------------------- */
/* (3c) Matriz: TODO _Mylast - where negativo                                */
/* ------------------------------------------------------------------------- */
/*
 * O crash exige count = sar(_Mylast - where, 4) < 1 COM SINAL. Esta matriz
 * executa os opcodes reais (sub/sar/cmp + opcode lido do encoder de produção)
 * para distâncias d = where - _Mylast:
 *
 *   d > 0   => _Mylast - where NEGATIVO. O JAE (unsigned) toma o shift (laço
 *              de cópia para trás); o JGE (signed) NÃO toma e cai no caminho
 *              de inserção no fim. É o universo inteiro do crash.
 *   d <= 0  => count >= 0: os dois opcodes têm de concordar (sem regressão do
 *              caminho legítimo de shift).
 *
 * d = 1..64 é exaustivo sobre os quatro primeiros valores de count (o sar só
 * muda de valor a cada 16); acima disso cobrimos potências e o delta forense
 * de ~1 MB do log. A camada [1] não pode tocar r8 em nenhum caso.
 */
static void test_negative_count_matrix(void)
{
    const uint64_t mylast = 0x0000040000000018ULL; /* valor real do crash */
    uint8_t *mem_plain = alloc_rwx(4096);
    uint8_t *mem_fixed = alloc_rwx(4096);
    uint8_t *thunk_plain;
    uint8_t *thunk_fixed;
    int64_t d;

    CHECK(mem_plain != NULL && mem_fixed != NULL,
          "mmap RWX da matriz de counts falhou");
    if (mem_plain == NULL || mem_fixed == NULL) {
        free_rwx(mem_plain, 4096);
        free_rwx(mem_fixed, 4096);
        return;
    }
    thunk_plain = build_thunk(mem_plain + 2048,
                              build_decision_wrapper(mem_plain, 0));
    thunk_fixed = build_thunk(mem_fixed + 2048,
                              build_decision_wrapper(mem_fixed, 1));

    for (d = 1; d <= 64; d++) {
        uint64_t where = mylast + (uint64_t)d;
        uint64_t res_plain[5] = { 0, 0xFFFFu };
        uint64_t res_fixed[5] = { 0, 0xFFFFu };

        ((run_thunk_fn)thunk_plain)(where, mylast, res_plain);
        ((run_thunk_fn)thunk_fixed)(where, mylast, res_fixed);
        CHECK(res_plain[1] == 1,
              "JAE: distance positiva deveria tomar o shift/runaway");
        CHECK(res_fixed[1] == 0,
              "JGE: distance positiva ainda tomou o shift/runaway");
    }

    {
        static const int64_t dists[] = {
            0x1000, 0x1013F8, 0x7FFFFFFF, 0x123456789LL,
            0, -1, -15, -16, -17, -0x1000
        };
        size_t i;
        for (i = 0; i < sizeof(dists) / sizeof(dists[0]); i++) {
            uint64_t where = (uint64_t)((int64_t)mylast + dists[i]);
            uint64_t res_plain[5] = { 0, 0xFFFFu };
            uint64_t res_fixed[5] = { 0, 0xFFFFu };
            int expected_jae = (dists[i] > 0 || dists[i] <= -16) ? 1 : 0;
            int expected_jge = (dists[i] > 0) ? 0 : expected_jae;

            ((run_thunk_fn)thunk_plain)(where, mylast, res_plain);
            ((run_thunk_fn)thunk_fixed)(where, mylast, res_fixed);
            CHECK(res_plain[1] == (uint64_t)expected_jae,
                  "JAE: decisao divergente na matriz de distancias");
            CHECK(res_fixed[1] == (uint64_t)expected_jge,
                  "JGE: decisao divergente na matriz de distancias");
            CHECK(res_plain[0] == where && res_fixed[0] == where,
                  "decisao da camada [1] alterou r8/where");
        }
    }
    printf("OK: matriz de counts negativos (d=1..64 exaustivo + potencias + "
           "delta forense): JGE nunca toma o laco de copia para tras\n");

    free_rwx(mem_plain, 4096);
    free_rwx(mem_fixed, 4096);
}

/* ------------------------------------------------------------------------- */
/* (6) Execução do helper REAL (0x85b770): JE desgovernado vs JAE imediato     */
/* ------------------------------------------------------------------------- */
typedef uint64_t (*helper_thunk_fn)(uint64_t start, uint64_t end,
                                     uint8_t *dest);

/*
 * SysV (rdi=start, rsi=end, rdx=dest) -> helper do jogo (Windows: rcx, rdx,
 * r8). Devolve rax = r8 (dest) como o helper real faz no `mov rax,r8; ret`.
 */
static uint8_t *build_helper_thunk(uint8_t *mem, uint8_t *helper)
{
    static const uint8_t head[] = {
        0x49, 0x89, 0xD0, /* mov r8, rdx   (dest)   */
        0x48, 0x89, 0xF9, /* mov rcx, rdi  (start)  */
        0x48, 0x89, 0xF2  /* mov rdx, rsi  (end)    */
    };
    uint64_t h = (uint64_t)(uintptr_t)helper;
    size_t o = sizeof(head);
    int i;

    memcpy(mem, head, sizeof(head));
    mem[o++] = 0x49; /* mov r10, imm64 */
    mem[o++] = 0xBA;
    for (i = 0; i < 8; i++) {
        mem[o++] = (uint8_t)((h >> (8 * i)) & 0xFFu);
    }
    mem[o++] = 0x41; /* call r10 */
    mem[o++] = 0xFF;
    mem[o++] = 0xD2;
    mem[o++] = 0xC3; /* ret */
    clear_icache(mem, o + 16);
    return mem;
}

static void test_helper_execution(void)
{
    const char *path = find_title_exe();
    uint8_t raw[FM5_VIS_HELPER_CODE_LEN];
    uint8_t fixed_raw[FM5_VIS_HELPER_CODE_LEN];
    uint8_t pat[64];
    uint8_t *code_mem = NULL;
    uint8_t *dest = NULL;
    uint8_t *region = NULL;
    uint8_t *buf = NULL;
    uint8_t *thunk_o;
    uint8_t *thunk_f;
    helper_thunk_fn fn_o;
    helper_thunk_fn fn_f;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t i;
    int variant;

    CHECK(path != NULL,
          "executavel do titulo ausente para a prova do helper");
    if (path == NULL) {
        return;
    }
    {
        int rd = read_pe_rva(path, FM5_VIS_HELPER_RVA, raw, sizeof(raw));
        CHECK(rd == 1, "nao foi possivel ler os 47 bytes vivos de 0x85b770");
        if (rd != 1) {
            return;
        }
    }
    CHECK(raw[0] == 0x48 && raw[1] == 0x3B && raw[2] == 0xCA &&
              raw[3] == 0x74 && raw[4] == 0x26,
          "helper lido do PE nao e `48 3b ca 74 26`");
    CHECK(raw[FM5_VIS_HELPER_CODE_LEN - 1] == 0xC3,
          "ultimo byte do helper (0x85b79e) nao e `ret`");
    memcpy(fixed_raw, raw, sizeof(fixed_raw));
    fm5_vis_encode_helper_fix(fixed_raw);

    for (i = 0; i < sizeof(pat); i++) {
        pat[i] = (uint8_t)(i ^ 0x5A);
    }

    code_mem = alloc_rwx(4096);
    dest = alloc_rwx(page * 2);
    region = (uint8_t *)mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(code_mem != NULL && dest != NULL &&
              region != NULL && region != MAP_FAILED,
          "alocacao de memoria para a prova do helper falhou");
    if (code_mem == NULL || dest == NULL ||
        region == NULL || region == MAP_FAILED) {
        free_rwx(code_mem, 4096);
        free_rwx(dest, page * 2);
        if (region != NULL && region != MAP_FAILED) {
            munmap(region, page * 2);
        }
        return;
    }
    CHECK(mprotect(region + page, page, PROT_NONE) == 0,
          "mprotect da pagina-guarda do helper falhou");
    buf = region;

    /* Os DOIS variantes executam os bytes REAIS do executável do título. */
    memcpy(code_mem, raw, sizeof(raw));
    memcpy(code_mem + 256, fixed_raw, sizeof(fixed_raw));
    thunk_o = build_helper_thunk(code_mem + 512, code_mem);
    thunk_f = build_helper_thunk(code_mem + 768, code_mem + 256);
    fn_o = (helper_thunk_fn)thunk_o;
    fn_f = (helper_thunk_fn)thunk_f;
    clear_icache(code_mem, 4096);

    /* (a) cópia legítima (rcx < rdx): os DOIS têm de copiar idêntico.
     * O helper devolve r8 AVANÇADO (dest + 64), como um memmove. */
    for (variant = 0; variant < 2; variant++) {
        helper_thunk_fn fn = variant ? fn_f : fn_o;
        uint64_t r;
        memset(dest, 0xBB, 64);
        r = fn((uint64_t)(uintptr_t)pat, (uint64_t)(uintptr_t)(pat + 64),
               dest);
        CHECK(r == (uint64_t)(uintptr_t)dest + 64,
              "helper legito nao devolveu r8 avancado (dest + 64)");
        CHECK(memcmp(dest, pat, 64) == 0,
              "helper legito nao copiou os 64 bytes (JE e JAE divergem!)");
    }

    /* (b) rcx == rdx: sem cópia, dest intacto (os DOIS). */
    for (variant = 0; variant < 2; variant++) {
        helper_thunk_fn fn = variant ? fn_f : fn_o;
        uint64_t r;
        memset(dest, 0xBB, 16);
        r = fn((uint64_t)(uintptr_t)pat, (uint64_t)(uintptr_t)pat, dest);
        CHECK(r == (uint64_t)(uintptr_t)dest && dest[0] == 0xBB,
              "helper com rcx == rdx nao retornou sem copiar");
    }

    /* (c) rcx > rdx (o crash): o FIXADO retorna imediato, sem tocar dest. */
    memset(dest, 0xBB, 64);
    {
        uint64_t r = fn_f((uint64_t)(uintptr_t)(buf + 0x40),
                          (uint64_t)(uintptr_t)(buf + 0x20), dest);
        CHECK(r == (uint64_t)(uintptr_t)dest,
              "helper corrigido (JAE) nao retornou para rcx > rdx");
        CHECK(dest[0] == 0xBB,
              "helper corrigido copiou algo com rcx > rdx");
    }

    /* (c2) o ORIGINAL com rcx > rdx desgovernado: filho morre com SIGSEGV
     * ao varrer a página-guarda (é exatamente o crash rip=0x14085b77a). */
    {
        pid_t pid = fork();
        CHECK(pid >= 0, "fork do controle negativo do helper falhou");
        if (pid == 0) {
            (void)fn_o((uint64_t)(uintptr_t)(buf + 0x40),
                       (uint64_t)(uintptr_t)(buf + 0x20), dest);
            _exit(0); /* só chega aqui se o laço NÃO desgovernou */
        } else if (pid > 0) {
            int status = 0;
            CHECK(waitpid(pid, &status, 0) == pid,
                  "waitpid do helper falhou");
            CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV,
                  "helper ORIGINAL (JE) NAO morreu com SIGSEGV para "
                  "rcx > rdx: o laco de copia nao foi reproduzido");
        }
    }

    printf("OK: helper real 0x85b770: JE desgovernado morre com SIGSEGV; "
           "JAE retorna imediato; copia legitima identica nos dois\n");

    free_rwx(code_mem, 4096);
    free_rwx(dest, page * 2);
    munmap(region, page * 2);
}

/* ------------------------------------------------------------------------- */
/* (7) Execução da caverna DA FONTE (camada [4]: clamp antes do insert)        */
/* ------------------------------------------------------------------------- */
/*
 * Réplica do call site 0x8580e0: o entry (8-byte aligned) recebe o E9
 * publicado por um único store de 64 bits; a caverna reemite as duas
 * instruções originais, lê o "global" _Mylast de um slot real no próprio
 * buffer, clampa r8 e cai no resume (0x8580e8) — aqui um `mov eax,0x5A; ret`
 * que prova que o call insert foi alcançado.
 */
static void test_src_clamp_execution(void)
{
    uint8_t *mem = alloc_rwx(4096);
    uint8_t *fn;
    uint8_t *cave;
    uint64_t *mylast_slot;
    uint8_t *thunk;
    uint8_t patch[8];
    uint64_t word;
    uint64_t mylast = 0x0000040000000018ULL;
    uint64_t res[5];
    size_t n;

    CHECK(mem != NULL, "mmap RWX da caverna da fonte falhou");
    if (mem == NULL) {
        return;
    }
    fn = mem;                         /* 0x8580e0 (page-aligned => 8-ok) */
    cave = mem + 0x40;                /* caverna da fonte                */
    mylast_slot = (uint64_t *)(void *)(mem + 0x100);
    *mylast_slot = mylast;
    /* resume (0x8580e8): marker de que o call insert foi alcançado. */
    mem[8] = 0xB8;                    /* mov eax, 0x5A */
    mem[9] = 0x5A;
    mem[10] = 0x00;
    mem[11] = 0x00;
    mem[12] = 0x00;
    mem[13] = 0xC3;                   /* ret */

    n = fm5_vis_encode_src_cave(cave, 64, (uint64_t)(uintptr_t)cave,
                                (uint64_t)(uintptr_t)mylast_slot,
                                (uint64_t)(uintptr_t)(mem + 8));
    CHECK(n == FM5_VIS_SRC_CAVE_LEN, "montagem da caverna da fonte falhou");
    if (n != FM5_VIS_SRC_CAVE_LEN) {
        free_rwx(mem, 4096);
        return;
    }
    CHECK(fm5_vis_encode_jump(patch, (uint64_t)(uintptr_t)fn,
                              (uint64_t)(uintptr_t)cave) == 0,
          "E9 da fonte fora de alcance");
    patch[5] = 0x90;
    patch[6] = 0x90;
    patch[7] = 0x90;
    memcpy(&word, patch, 8);
    CHECK(((uintptr_t)fn & 7u) == 0,
          "entry da fonte nao esta 8-byte aligned");
    *(volatile uint64_t *)(void *)fn = word;
    clear_icache(mem, 4096);
    thunk = build_thunk(mem + 2048, fn);

    /* where > *_Mylast: clamped para _Mylast; resume alcançado; spill e rbp
     * intocados (a caverna da fonte só mexe em r8/rcx). */
    res[0] = 0;
    res[1] = 0;
    ((run_thunk_fn)thunk)(mylast + 0x1013F8ULL, mylast, res);
    CHECK(res[0] == mylast,
          "fonte nao clamped where = _Mylast para where >> _Mylast");
    CHECK(res[1] == 0x5A,
          "fonte nao reach resume (call 0x8580e8) apos o clamp");
    CHECK(res[2] == FM5_SPILL_SENTINEL && res[4] == FM5_RBP_SENTINEL,
          "caverna da fonte tocou em spill/rbp (nao devia)");

    /* Matriz de distâncias > 0. */
    {
        static const uint64_t dists[] = {
            1ULL, 0x10ULL, 0x1000ULL, 0x1013F8ULL, 0x7FFFFFFFULL
        };
        size_t di;
        for (di = 0; di < sizeof(dists) / sizeof(dists[0]); di++) {
            res[0] = 0;
            res[1] = 0;
            ((run_thunk_fn)thunk)(mylast + dists[di], mylast, res);
            CHECK(res[0] == mylast,
                  "fonte nao clamped where na matriz de distancias");
            CHECK(res[1] == 0x5A,
                  "fonte nao reach resume na matriz de distancias");
        }
    }

    /* where == _Mylast e where < _Mylast: passam intactos. */
    res[0] = 0;
    res[1] = 0;
    ((run_thunk_fn)thunk)(mylast, mylast, res);
    CHECK(res[0] == mylast, "caso where == _Mylast foi alterado");
    CHECK(res[1] == 0x5A, "caso where == _Mylast nao reach resume");

    res[0] = 0;
    res[1] = 0;
    ((run_thunk_fn)thunk)(mylast - 0x10ULL, mylast, res);
    CHECK(res[0] == mylast - 0x10ULL,
          "fonte alterou where no caminho legitimo (count == 1)");
    CHECK(res[1] == 0x5A,
          "caminho legitimo nao reach resume (regressao na fonte)");

    printf("OK: caverna da fonte clampa where > _Mylast antes do insert e "
           "deixa where <= _Mylast intacto\n");

    free_rwx(mem, 4096);
}

int main(void)
{
    test_forensic_anchor();
    test_encoding();
    test_decision_with_fix();
    test_negative_count_matrix();
    test_runaway_crash_control();
    test_clamp_execution();
    test_helper_execution();
    test_src_clamp_execution();

    if (g_failures) {
        fprintf(stderr, "FALHA: %d/%d verificacoes da blindagem de "
                        "visibilidade falharam\n", g_failures, g_checks);
        return 1;
    }
    printf("OK: %d verificacoes da blindagem da Visibility Thread passaram "
           "(execucao real, ancora no executavel do titulo)\n", g_checks);
    return 0;
}
