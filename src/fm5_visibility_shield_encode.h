/*
 * fm5_visibility_shield_encode.h — codificação pura da blindagem da Visibility
 * Thread do título (crash 0xC0000005: rip=0x1408595e0, Thread 0344; e o
 * crash remanescente rip=0x14085b77a, Thread 0354).
 *
 * EVIDÊNCIA FORENSE (logs/steam-0.log, 2026-11-10, título 1.0.0.20):
 *
 *   28122.039:0154:0344:trace:seh:dispatch_exception
 *       code=c0000005 (EXCEPTION_ACCESS_VIOLATION) flags=0 addr=00000001408595E0
 *   28122.040:0154:0344:  info[1]=000003FFFFFFFFF0
 *       rax=0000000000002c7a rdx=0000040000000018 r8=0000040000101410
 *       rcx=00000400001014b0 rdi=0000040000000000
 *   28122.041:0154:0344:trace:unwind:dump_unwind_info
 *       **** func 859500-859637
 *
 * CRASH 1 (fechado pelas camadas [1]+[2]) — laço de cópia PARA TRÁS:
 *   where (r8) > _Mylast (rdx)          -> em split-screen o vetor global de
 *                                          visibilidade (0x1424717d0) satura e
 *                                          a nova malha cai depois do fim
 *   0x859506: 49 2b c0        sub  rax, r8       ; rax = _Mylast - where
 *   0x859509: 48 c1 f8 04     sar  rax, 4        ; rax = COUNT (NEGATIVO)
 *   0x859512: 48 83 f8 01     cmp  rax, 1
 *   0x859516: 0f 83 8d 00 00 00  jae 0x1408595a9 ; BUG: JAE é UNSIGNED; o
 *                                               ; count negativo vira
 *                                               ; ~0xFFFFFFFFFFFFFFF5 >= 1
 *   ... o salto entra no laço de cópia para trás
 *   0x8595e0: 8b 47 f0        mov  eax,[rdi-0x10]
 *   0x8595e7: 48 83 ef 10     sub  rdi, 0x10
 *   0x859603: 48 3b cf        cmp  rdi, rcx
 *   0x859606: 75 d8           jne  0x1408595e0
 *
 * Como rdi começa ATRÁS de rcx (where), a comparação nunca é igual: o laço
 * copia memória para trás indefinidamente e só para no piso canônico
 * 0x0000040000000000 - 0x10 (0x000003FFFFFFFFF0) com ACCESS_VIOLATION.
 *
 * CRASH 2 (remanescente, fechado pelas camadas [2]+[3]) — laço PARA FRENTE no
 * helper 0x14085b770 (Thread 0354, rip=0x14085b77a lendo 0x40000360000):
 *
 *   a busca binária 0x858070..0x8580d4 roda ANTES de 0x85805c decrementar
 *   _Mylast (descarte do pior item), então devolve where = old_Mylast =
 *   _Mylast + 0x10. vector::insert (0x859390, ÚNICO call site 0x8580e8)
 *   guarda where em TRÊS cópias:
 *     - r8   (arg, 0x8593c3)      — já travada pela caverna [2];
 *     - rbp  (0x8593c6 `49 8b e8`), lido em 0x85952c `48 8b cd mov rcx,rbp`
 *       como ORIGEM do helper: `mov rcx,rbp; call 0x85b770` (0x859538);
 *     - spill [rsp+0x90] (prólogo 0x85939a `4c 89 44 24 18`), lido em
 *       0x859551 (contagem) e 0x85957b (início do laço de ESCRITA para
 *       frente 0x859590 `89 38 / 75 ec`).
 *   O patch anterior só travava r8: %rbp e o spill seguiam > _Mylast.
 *   Em 0x14085b770: `cmp rcx,rdx; je +0x26` — com rcx (where) > rdx
 *   (_Mylast) o je NUNCA toma e o laço `add rcx,0x10` varre a memória para
 *   a frente até estourar a página em 0x40000360000.
 *
 * BLINDAGEM EM QUATRO CAMADAS (defesa em profundidade):
 *
 *   [1] Branch assinado (RVA 0x859516): troca o opcode `0f 83` (JAE, unsigned)
 *       por `0f 8d` (JGE, signed). O deslocamento `8d 00 00 00` (+0x8d) é
 *       preservado: para count < 0 o salto NÃO é tomado e o fluxo cai em
 *       0x85951c, o caminho de inserção no fim (o mesmo de count == 0).
 *       Patch de 2 bytes em endereço par => store atômico de 16 bits.
 *
 *   [2] Trava de `where` (RVA 0x859500, fronteira de função e 8-byte aligned):
 *       um E9 rel32 de entrada para uma caverna que reemite o prologue
 *       `vmovaps xmm6,[rsp+0x40]` + `sub`/`sar` e então, se
 *       where > _Mylast, trava as TRÊS cópias em _Mylast (r8, rbp e o spill
 *       [rsp+0x90]) e zera o count — semântica exata do caso where == _Mylast.
 *       Com tudo travado, o helper recebe rcx == rdx (je imediato) e o laço
 *       0x859590 nasce com rax == rcx (nem entra). A trava protege mesmo que
 *       o patch [1] seja revertido/sobrescrito pelo mapeador.
 *
 *   [3] Helper de cópia (RVA 0x85b773): `74 26` (JE) -> `73 26` (JAE). Se o
 *       ponteiro de início rcx já é >= rdx, a cópia termina imediatamente
 *       (retorna r8 intacto) em vez de varrer para a frente. Seguro para os
 *       5 call sites reais (todos com rcx <= rdx). Store atômico de 16 bits
 *       no word PAR 0x85b772 (byte-alinhado 0x85b773 fica dentro dele).
 *
 *   [4] Trava na FONTE (RVA 0x8580e0): logo na saída da busca binária,
 *       `mov r8, r11` é substituído por uma caverna que reemite
 *       `mov r8,r11` + `mov [rsp+0x20],rax` e trava r11 onde > _Mylast ao
 *       _Mylast global (0x24717d8) ANTES do call 0x8580e8. Com a fonte
 *       travada, insert nem vê where > _Mylast (todas as três cópias nascem
 *       corretas) — fecha o caso mesmo se a caverna [2] falhar em instalar.
 *
 * As publicações [2] e [4] são UM ÚNICO store de 8 bytes alinhado (0x859500 e
 * 0x8580e0 são múltiplos de 8), portanto nunca existe patch "rasgado" para
 * outra thread: o fluxo observado é ou o original inteiro, ou o E9 inteiro.
 *
 * Este header é portátil (<stdint.h>/<stddef.h>/<string.h>) e é exercitado de
 * verdade pelos testes nativos Linux: eles copiam a sequência REAL do
 * executável, montam as cavernas em memória executável e EXECUTAM o código,
 * inclusive os controles negativos que morrem com SIGSEGV sem a blindagem.
 */
#ifndef FM5_VISIBILITY_SHIELD_ENCODE_H
#define FM5_VISIBILITY_SHIELD_ENCODE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Camada 1 — branch assinado (JAE -> JGE) em 0x859516                        */
/* ------------------------------------------------------------------------- */
#define FM5_VIS_BRANCH_RVA             0x859516u
#define FM5_VIS_BRANCH_FALLTHROUGH_RVA 0x85951Cu
#define FM5_VIS_BRANCH_SHIFT_RVA       0x8595A9u
#define FM5_VIS_BRANCH_ORIG_LEN        6u
#define FM5_VIS_BRANCH_PATCH_LEN       2u  /* só o opcode: 0f 83 -> 0f 8d */

/* `jae +0x8d` — salto UNSIGNED que transforma count negativo em ~0xFFFF...F5. */
#define FM5_VIS_BRANCH_ORIG_BYTES 0x0F, 0x83, 0x8D, 0x00, 0x00, 0x00
/* `jge +0x8d` — mesmo destino, comparação SIGNED. */
#define FM5_VIS_BRANCH_FIXED_BYTES 0x0F, 0x8D, 0x8D, 0x00, 0x00, 0x00

/* ------------------------------------------------------------------------- */
/* Camada 2 — trava de where/_Mylast em 0x859500 (fronteira da função)        */
/* ------------------------------------------------------------------------- */
#define FM5_VIS_GUARD_RVA        0x859500u  /* vmovaps xmm6,0x40(rsp) — 8B aligned  */
#define FM5_VIS_GUARD_RESUME_RVA 0x85950Du  /* após sub/sar: vmovss 0x4(rbx),xmm6  */
#define FM5_VIS_GUARD_SEQ_LEN    13u
#define FM5_VIS_GUARD_PATCH_LEN  8u         /* store atômico alinhado E9+3 NOPs    */

/* Sequência viva esperada no build 1.0.0.20 (fail-closed se divergir):
 *   c5 f8 29 74 24 40   vmovaps [rsp+0x40], xmm6
 *   49 2b c0            sub     rax, r8        ; _Mylast - where
 *   48 c1 f8 04         sar     rax, 4         ; count
 */
#define FM5_VIS_GUARD_SEQ_BYTES \
    0xC5, 0xF8, 0x29, 0x74, 0x24, 0x40, \
    0x49, 0x2B, 0xC0, \
    0x48, 0xC1, 0xF8, 0x04

/*
 * Opcodes da caverna (35 bytes) antes da cauda `jmp [rip+0]` + retomada:
 *
 *   off  bytes                              instrução
 *   0    c5 f8 29 74 24 40                  vmovaps [rsp+0x40], xmm6 (orig.)
 *   6    49 2b c0                           sub  rax, r8     ; _Mylast - where
 *   9    48 c1 f8 04                        sar  rax, 4      ; count
 *   13   4c 39 c2                           cmp  rdx, r8     ; _Mylast vs where
 *   16   7d 11                              jge  +0x11       ; intacto -> off 35
 *   18   49 89 d0                           mov  r8, rdx     ; trava copia 1 (r8)
 *   21   48 89 d5                           mov  rbp, rdx    ; trava copia 2 (rbp)
 *   24   48 89 94 24 90 00 00 00            mov  [rsp+0x90], rdx ; copia 3 (spill)
 *   32   48 31 c0                           xor  rax, rax    ; count = 0
 *   35   ff 25 00 00 00 00 | <resume: u64>  cauda (jmp absoluto indireto)
 *
 * Por que as TRÊS cópias (r8, rbp e o spill [rsp+0x90]): vector::insert
 * (0x859390) guarda `where` em r8 (arg, 0x8593c3), em rbp (0x8593c6
 * `49 8b e8`, lido como origem do helper em 0x85952c `48 8b cd`) e no spill
 * [rsp+0x90] do prólogo (lido em 0x859551 para o count do caminho de fim e
 * em 0x85957b para o início do laço de escrita 0x859590). Travar só r8
 * deixava as outras duas > _Mylast e o helper/laço seguiam desgovernados
 * (crash rip=0x14085b77a). O deslocamento do jge é +0x11: alvo = 18 + 17
 * = 35, o início da cauda — logo, no caso intacto NENHUMA trava e NENHUM
 * xor são executados (count legítimo é preservado).
 *
 * EFLAGS não precisam de pushfq/popfq: a instrução seguinte em 0x85950d
 * (vmovss) não lê flags e 0x859512 (`cmp rax,1`) as sobrescreve. O epílogo
 * de insert recarrega rbp do slot salvo em [rsp+0x88] (home do prólogo),
 * portanto travar rbp aqui é seguro; o rbp lido em 0x85952c é a ÚNICA leitura
 * do valor travado.
 */
#define FM5_VIS_GUARD_CAVE_OPCODES \
    0xC5, 0xF8, 0x29, 0x74, 0x24, 0x40, \
    0x49, 0x2B, 0xC0, \
    0x48, 0xC1, 0xF8, 0x04, \
    0x4C, 0x39, 0xC2, \
    0x7D, 0x11, \
    0x49, 0x89, 0xD0, \
    0x48, 0x89, 0xD5, \
    0x48, 0x89, 0x94, 0x24, 0x90, 0x00, 0x00, 0x00, \
    0x48, 0x31, 0xC0

#define FM5_VIS_GUARD_CAVE_OPCODES_LEN 35u
/* 35 (opcodes) + 14 (jmp absoluto indireto rip-relative + alvo u64). */
#define FM5_VIS_GUARD_CAVE_LEN \
    (FM5_VIS_GUARD_CAVE_OPCODES_LEN + 14u) /* = 49 */

/* Tamanho do salto de entrada E9 rel32 (5 bytes). */
#define FM5_VIS_JUMP_LEN 5u

static inline const uint8_t *fm5_vis_branch_original(void)
{
    static const uint8_t orig[FM5_VIS_BRANCH_ORIG_LEN] = {
        FM5_VIS_BRANCH_ORIG_BYTES
    };
    return orig;
}

static inline const uint8_t *fm5_vis_branch_fixed(void)
{
    static const uint8_t fixed[FM5_VIS_BRANCH_ORIG_LEN] = {
        FM5_VIS_BRANCH_FIXED_BYTES
    };
    return fixed;
}

/* 1 se os 6 bytes vivos são `jae +0x8d` (build ainda não blindado). */
static inline int fm5_vis_is_branch_original(const uint8_t *bytes)
{
    return (bytes != NULL) &&
           (memcmp(bytes, fm5_vis_branch_original(),
                   FM5_VIS_BRANCH_ORIG_LEN) == 0);
}

/* 1 se os 6 bytes vivos são `jge +0x8d` (blindagem [1] publicada). */
static inline int fm5_vis_is_branch_fixed(const uint8_t *bytes)
{
    return (bytes != NULL) &&
           (memcmp(bytes, fm5_vis_branch_fixed(),
                   FM5_VIS_BRANCH_ORIG_LEN) == 0);
}

/* Escreve o patch da camada [1] em `dst` (2 bytes no início). O deslocamento
 * rel32 seguinte é preservado pelo chamador. */
static inline void fm5_vis_encode_branch_fix(uint8_t *dst)
{
    dst[0] = 0x0F;
    dst[1] = 0x8D;
}

static inline const uint8_t *fm5_vis_guard_sequence(void)
{
    static const uint8_t seq[FM5_VIS_GUARD_SEQ_LEN] = {
        FM5_VIS_GUARD_SEQ_BYTES
    };
    return seq;
}

/* 1 se os 13 bytes vivos casam com a sequência forense (fail-closed). */
static inline int fm5_vis_is_guard_sequence(const uint8_t *bytes)
{
    return (bytes != NULL) &&
           (memcmp(bytes, fm5_vis_guard_sequence(),
                   FM5_VIS_GUARD_SEQ_LEN) == 0);
}

/*
 * Monta a caverna em `dst` (cap >= FM5_VIS_GUARD_CAVE_LEN) e devolve o
 * tamanho escrito, ou 0 em erro de capacidade/argumento. A cauda salta de
 * volta para `resume_addr` (no jogo: base + FM5_VIS_GUARD_RESUME_RVA) sem
 * clobber de registradores de uso geral (`jmp qword ptr [rip+0]`).
 */
static inline size_t fm5_vis_encode_guard_cave(uint8_t *dst, size_t cap,
                                               uint64_t resume_addr)
{
    static const uint8_t ops[FM5_VIS_GUARD_CAVE_OPCODES_LEN] = {
        FM5_VIS_GUARD_CAVE_OPCODES
    };
    size_t i;

    if (dst == NULL || cap < FM5_VIS_GUARD_CAVE_LEN) {
        return 0;
    }
    for (i = 0; i < FM5_VIS_GUARD_CAVE_OPCODES_LEN; i++) {
        dst[i] = ops[i];
    }
    /* Cauda: ff 25 00 00 00 00 | <resume_addr: u64 LE>. */
    dst[FM5_VIS_GUARD_CAVE_OPCODES_LEN + 0] = 0xFF;
    dst[FM5_VIS_GUARD_CAVE_OPCODES_LEN + 1] = 0x25;
    dst[FM5_VIS_GUARD_CAVE_OPCODES_LEN + 2] = 0x00;
    dst[FM5_VIS_GUARD_CAVE_OPCODES_LEN + 3] = 0x00;
    dst[FM5_VIS_GUARD_CAVE_OPCODES_LEN + 4] = 0x00;
    dst[FM5_VIS_GUARD_CAVE_OPCODES_LEN + 5] = 0x00;
    for (i = 0; i < 8; i++) {
        dst[FM5_VIS_GUARD_CAVE_OPCODES_LEN + 6 + i] =
            (uint8_t)((resume_addr >> (8u * i)) & 0xFFu);
    }
    return FM5_VIS_GUARD_CAVE_LEN;
}

/* ------------------------------------------------------------------------- */
/* Camada 3 — helper de cópia 0x85b770: `74 26` (JE) -> `73 26` (JAE)         */
/* ------------------------------------------------------------------------- */
/*
 * O helper é `memmove` de [rcx, rdx) para r8:
 *   0x85b770: 48 3b ca   cmp rcx, rdx
 *   0x85b773: 74 26      je  0x85b79b      ; SÓ toma para rcx == rdx
 *   ... laço: mov eax,[rcx] ... add rcx,0x10 ; add r8,0x10 ;
 *             cmp rcx,rdx ; jne -> 0x85b775
 *   0x85b79b: 49 8b c0   mov rax, r8 ; ret
 * Com rcx (where) > rdx (_Mylast) o je nunca toma e o laço `add rcx,0x10`
 * varre para a frente até ACCESS_VIOLATION (crash rip=0x14085b77a lendo
 * [rcx] no início do laço). Trocar por JAE (>=, unsigned) faz a cópia
 * terminar imediatamente quando o ponteiro de início já passou do fim —
 * para os 5 call sites reais (todos com rcx <= rdx: _Myfirst/where/end-0x10
 * como início, _Mylast/end como fim) o comportamento é IDÊNTICO ao JE.
 *
 * O byte do jcc (0x85b773) é ímpar: o patch é um store atômico de 16 bits
 * no word PAR 0x85b772 (bytes `ca 74` -> `ca 73`).
 */
#define FM5_VIS_HELPER_RVA        0x85B770u  /* cmp rcx,rdx; je +0x26 ...      */
#define FM5_VIS_HELPER_STORE_RVA  0x85B772u  /* word PAR que contém o jcc       */
#define FM5_VIS_HELPER_JCC_RVA    0x85B773u  /* byte do jcc (ímpar, dentro do word) */
#define FM5_VIS_HELPER_SEQ_LEN    5u
#define FM5_VIS_HELPER_PATCH_LEN  2u         /* store atômico de 16 bits alinhado */
#define FM5_VIS_HELPER_CODE_LEN   47u        /* 0x85b770..0x85b79e (até o ret)  */
#define FM5_VIS_HELPER_CALL_SITES 5u         /* call sites E8 reais -> 0x85b770 */

/* `cmp rcx,rdx ; je +0x26` — só empata; rcx > rdx deixa o laço correr. */
#define FM5_VIS_HELPER_ORIG_BYTES  0x48, 0x3B, 0xCA, 0x74, 0x26
/* `cmp rcx,rdx ; jae +0x26` — rcx >= rdx termina sem copiar (r8 intacto). */
#define FM5_VIS_HELPER_FIXED_BYTES 0x48, 0x3B, 0xCA, 0x73, 0x26
/* word little-endian lido em 0x85b772 (bytes `ca 74` / `ca 73`). */
#define FM5_VIS_HELPER_ORIG_WORD   0x74CAu
#define FM5_VIS_HELPER_FIXED_WORD  0x73CAu

static inline const uint8_t *fm5_vis_helper_original(void)
{
    static const uint8_t orig[FM5_VIS_HELPER_SEQ_LEN] = {
        FM5_VIS_HELPER_ORIG_BYTES
    };
    return orig;
}

static inline const uint8_t *fm5_vis_helper_fixed(void)
{
    static const uint8_t fixed[FM5_VIS_HELPER_SEQ_LEN] = {
        FM5_VIS_HELPER_FIXED_BYTES
    };
    return fixed;
}

/* 1 se os 5 bytes vivos de 0x85b770 são `cmp; je` (build sem blindagem). */
static inline int fm5_vis_is_helper_original(const uint8_t *bytes)
{
    return (bytes != NULL) &&
           (memcmp(bytes, fm5_vis_helper_original(),
                   FM5_VIS_HELPER_SEQ_LEN) == 0);
}

/* 1 se os 5 bytes vivos são `cmp; jae` (camada [3] publicada). */
static inline int fm5_vis_is_helper_fixed(const uint8_t *bytes)
{
    return (bytes != NULL) &&
           (memcmp(bytes, fm5_vis_helper_fixed(),
                   FM5_VIS_HELPER_SEQ_LEN) == 0);
}

/* Escreve os 5 bytes corrigidos em `dst` (>= 5 bytes): prova nativa usa isto
 * sobre UMA CÓPIA dos bytes reais do executável para executar o helper
 * corrigido contra o original (controle negativo com SIGSEGV). */
static inline void fm5_vis_encode_helper_fix(uint8_t *dst)
{
    const uint8_t *fixed = fm5_vis_helper_fixed();
    size_t i;

    if (dst == NULL) {
        return;
    }
    for (i = 0; i < FM5_VIS_HELPER_SEQ_LEN; i++) {
        dst[i] = fixed[i];
    }
}

/*
 * Codifica o salto de entrada `E9 rel32` em `dst` (5 bytes) do endereço
 * `target_addr` para `cave_addr`. Retorna 0 em sucesso e -1 quando o destino
 * está fora do alcance de ±2 GiB (fail-closed: o alvo NÃO deve ser tocado).
 */
static inline int fm5_vis_encode_jump(uint8_t *dst, uint64_t target_addr,
                                      uint64_t cave_addr)
{
    int64_t disp;
    uint64_t u;
    int i;

    if (dst == NULL) {
        return -1;
    }
    disp = (int64_t)cave_addr - (int64_t)(target_addr + FM5_VIS_JUMP_LEN);
    if (disp < (int64_t)INT32_MIN || disp > (int64_t)INT32_MAX) {
        return -1;
    }
    u = (uint64_t)disp & 0xFFFFFFFFu;
    dst[0] = 0xE9;
    for (i = 0; i < 4; i++) {
        dst[1 + i] = (uint8_t)((u >> (8u * i)) & 0xFFu);
    }
    return 0;
}

/* Resolve o destino absoluto de um `E9 rel32` em `p`. */
static inline uint64_t fm5_vis_decode_jump(const uint8_t *p)
{
    int32_t disp = (int32_t)((uint32_t)p[1] | ((uint32_t)p[2] << 8) |
                             ((uint32_t)p[3] << 16) | ((uint32_t)p[4] << 24));
    return (uint64_t)((int64_t)(uintptr_t)(p + 5) + (int64_t)disp);
}

/* ------------------------------------------------------------------------- */
/* Camada 4 — trava na FONTE 0x8580e0: clampa `where` antes do insert         */
/* ------------------------------------------------------------------------- */
/*
 * Logo após a busca binária (0x858070..0x8580d4), o único chamador de
 * vector::insert faz (RVA 0x8580e0):
 *   4d 8b c3            mov  r8, r11          ; where = resultado da busca
 *   48 89 44 24 20      mov  [rsp+0x20], rax  ; 5o argumento (elemento)
 *   e8 a3 12 00 00      call 0x859390         ; vector::insert (ÚNICO call site)
 * A caverna substitui os 8 bytes de 0x8580e0..0x8580e7 por E9 rel32 + NOPs e,
 * DENTRO da caverna, reemite essas duas instruções e então clampa r8 ao
 * global _Mylast (RVA 0x24717d8) quando where > _Mylast, ANTES do call:
 *   48 8b 0d <disp32>   mov  rcx, [_Mylast]   ; disp = mylast - (cave + 15)
 *   49 39 c8            cmp  r8, rcx          ; where vs _Mylast (unsigned)
 *   76 03               jbe  +3               ; where <= _Mylast: intacto
 *   49 89 c8            mov  r8, rcx          ; where = _Mylast   (trava)
 * Com a fonte travada, insert NUNCA vê where > _Mylast: as três cópias
 * (r8, rbp e spill) nascem corretas — fecha o crash mesmo se a caverna [2]
 * falhar em instalar. rcx é scratch seguro: insert não lê o rcx recebido
 * (o home slot é sobrescrito no prólogo e os dois caminhos escrevem rcx
 * antes de ler) e o epílogo do chamador não lê rcx depois do call.
 */
#define FM5_VIS_SRC_RVA           0x8580E0u /* mov r8,r11 ; mov [rsp+0x20],rax */
#define FM5_VIS_SRC_RESUME_RVA    0x8580E8u /* call vector::insert (0x859390)   */
#define FM5_VIS_SRC_SEQ_LEN       8u
#define FM5_VIS_SRC_PATCH_LEN     8u        /* store atômico de 64 bits alinhado */
#define FM5_VIS_MYLAST_RVA        0x24717D8u /* global _Mylast do vetor de vis.  */

/* Sequência viva em 0x8580e0 (fail-closed se divergir). */
#define FM5_VIS_SRC_SEQ_BYTES \
    0x4D, 0x8B, 0xC3, \
    0x48, 0x89, 0x44, 0x24, 0x20

/*
 * Opcodes da caverna (23 bytes) antes da cauda `jmp [rip+0]` + retomada:
 *   off  bytes                              instrução
 *   0    4d 8b c3                           mov  r8, r11        (reemissao)
 *   3    48 89 44 24 20                     mov  [rsp+0x20],rax (reemissao)
 *   8    48 8b 0d <disp32 LE>               mov  rcx, [_Mylast]
 *   15   49 39 c8                           cmp  r8, rcx
 *   18   76 03                              jbe  +3 -> off 23
 *   20   49 89 c8                           mov  r8, rcx         (trava)
 *   23   ff 25 00 00 00 00 | <resume: u64>  cauda
 */
#define FM5_VIS_SRC_CAVE_OPCODES \
    0x4D, 0x8B, 0xC3, \
    0x48, 0x89, 0x44, 0x24, 0x20, \
    0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, \
    0x49, 0x39, 0xC8, \
    0x76, 0x03, \
    0x49, 0x89, 0xC8

#define FM5_VIS_SRC_CAVE_OPCODES_LEN 23u
#define FM5_VIS_SRC_CAVE_DISP_OFF    11u /* posição do disp32 dentro da caverna */
#define FM5_VIS_SRC_CAVE_DISP_RIP    15u /* cave_addr + 15 = fim do mov rcx,[rip] */
/* 23 (opcodes) + 14 (jmp absoluto indireto rip-relative + alvo u64). */
#define FM5_VIS_SRC_CAVE_LEN \
    (FM5_VIS_SRC_CAVE_OPCODES_LEN + 14u) /* = 37 */

static inline const uint8_t *fm5_vis_src_sequence(void)
{
    static const uint8_t seq[FM5_VIS_SRC_SEQ_LEN] = {
        FM5_VIS_SRC_SEQ_BYTES
    };
    return seq;
}

/* 1 se os 8 bytes vivos de 0x8580e0 casam com a sequência forense. */
static inline int fm5_vis_is_src_sequence(const uint8_t *bytes)
{
    return (bytes != NULL) &&
           (memcmp(bytes, fm5_vis_src_sequence(), FM5_VIS_SRC_SEQ_LEN) == 0);
}

/*
 * Monta a caverna da camada [4] em `dst` (cap >= FM5_VIS_SRC_CAVE_LEN).
 * `cave_addr` é o endereço onde a caverna VAI VIVER (o disp32 rip-relative
 * do `mov rcx,[_Mylast]` depende dele), `mylast_addr` = base + 0x24717d8 e
 * `resume_addr` = base + 0x8580e8 (o call do insert). Devolve o tamanho
 * escrito ou 0 (argumento nulo, capacidade insuficiente ou disp32 fora de
 * ±2 GiB — fail-closed: a caverna NÃO deve ser publicada).
 */
static inline size_t fm5_vis_encode_src_cave(uint8_t *dst, size_t cap,
                                             uint64_t cave_addr,
                                             uint64_t mylast_addr,
                                             uint64_t resume_addr)
{
    static const uint8_t ops[FM5_VIS_SRC_CAVE_OPCODES_LEN] = {
        FM5_VIS_SRC_CAVE_OPCODES
    };
    int64_t disp;
    uint32_t u;
    size_t i;

    if (dst == NULL || cap < FM5_VIS_SRC_CAVE_LEN) {
        return 0;
    }
    disp = (int64_t)mylast_addr -
           (int64_t)(cave_addr + (uint64_t)FM5_VIS_SRC_CAVE_DISP_RIP);
    if (disp < (int64_t)INT32_MIN || disp > (int64_t)INT32_MAX) {
        return 0;
    }
    for (i = 0; i < FM5_VIS_SRC_CAVE_OPCODES_LEN; i++) {
        dst[i] = ops[i];
    }
    u = (uint32_t)(int32_t)disp;
    for (i = 0; i < 4; i++) {
        dst[FM5_VIS_SRC_CAVE_DISP_OFF + i] = (uint8_t)((u >> (8u * i)) & 0xFFu);
    }
    /* Cauda: ff 25 00 00 00 00 | <resume_addr: u64 LE>. */
    dst[FM5_VIS_SRC_CAVE_OPCODES_LEN + 0] = 0xFF;
    dst[FM5_VIS_SRC_CAVE_OPCODES_LEN + 1] = 0x25;
    dst[FM5_VIS_SRC_CAVE_OPCODES_LEN + 2] = 0x00;
    dst[FM5_VIS_SRC_CAVE_OPCODES_LEN + 3] = 0x00;
    dst[FM5_VIS_SRC_CAVE_OPCODES_LEN + 4] = 0x00;
    dst[FM5_VIS_SRC_CAVE_OPCODES_LEN + 5] = 0x00;
    for (i = 0; i < 8; i++) {
        dst[FM5_VIS_SRC_CAVE_OPCODES_LEN + 6 + i] =
            (uint8_t)((resume_addr >> (8u * i)) & 0xFFu);
    }
    return FM5_VIS_SRC_CAVE_LEN;
}

#endif /* FM5_VISIBILITY_SHIELD_ENCODE_H */
