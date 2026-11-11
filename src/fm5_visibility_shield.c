/*
 * fm5_visibility_shield.c — instalação Windows da blindagem da Visibility
 * Thread do executável do TÍTULO (crash 0xC0000005 em rip=0x1408595e0 e o
 * crash remanescente rip=0x14085b77a).
 *
 * Estratégia (quatro camadas independentes, defesa em profundidade):
 *   1. valida os bytes VIVOS em base+0x859516 contra `0f 83 8d 00 00 00`
 *      (ou o já corrigido `0f 8d 8d 00 00 00`); divergiu => NADA é escrito
 *      (fail-closed: base errada, página ilegível ou build diferente);
 *   2. publica `0f 8d` (JGE, signed) com um ÚNICO store atômico de 16 bits
 *      (0x859516 é par) — o deslocamento +0x8d é preservado, então count < 0
 *      não toma o salto e cai no caminho de inserção no fim (0x85951c);
 *   3. publica a trava de `where`: um E9 rel32 em base+0x859500 (fronteira da
 *      função, 8-byte aligned) para uma caverna dentro de ±2 GiB que reemite
 *      `vmovaps xmm6,[rsp+0x40]` + `sub`/`sar` e trava as TRÊS cópias de
 *      where (r8, rbp e o spill [rsp+0x90]) em _Mylast + count = 0 quando
 *      where > _Mylast. O E9 é publicado por um ÚNICO store de 8 bytes
 *      alinhado: outra thread vê o original inteiro ou o salto inteiro,
 *      nunca um patch rasgado;
 *   4. camada [3] no helper de cópia 0x85b770: store atômico de 16 bits no
 *      word par 0x85b772 troca `74 26` (JE) por `73 26` (JAE) — com rcx
 *      (where) > rdx (_Mylast) a cópia termina imediatamente em vez de
 *      varrer memória para a frente (crash rip=0x14085b77a);
 *   5. camada [4] na FONTE: E9 rel32 em base+0x8580e0 (8-byte aligned) para
 *      uma caverna que reemite `mov r8,r11` + `mov [rsp+0x20],rax` e clampa
 *      r8 ao global _Mylast (0x24717d8) antes do call 0x8580e8 — insert nem
 *      vê where > _Mylast (todas as três cópias nascem corretas).
 *
 * As camadas [3] e [4] são melhor esforço, como a [2]: a falha de QUALQUER
 * uma delas nunca invalida as demais nem a camada [1].
 *
 * RE-DETECÇÃO: fm5_visibility_shield_intact() confere os bytes publicados de
 * todas as camadas ativas. Se o mapeador/decifrador reescrever a região e
 * devolver a sequência original, install() reaplica o patch (reusando as
 * cavernas); se os bytes forem outros, falha fechado e o jogo segue intacto.
 */
#include "fm5_visibility_shield.h"

#ifndef _WIN32
#error "fm5_visibility_shield.c e apenas para o build Windows (mingw-w64)."
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

#include "fm5_log.h"
#include "fm5_visibility_shield_encode.h"

#define FM5_VIS_CAVE_ALLOC 64u

static void           *g_vis_cave;        /* caverna da camada [2] */
static void           *g_vis_src_cave;    /* caverna da camada [4] */
static uint8_t        *g_vis_branch_target;
static uint8_t        *g_vis_guard_target;
static uint8_t        *g_vis_helper_target;
static uint8_t        *g_vis_src_target;
static uint8_t         g_vis_guard_saved[FM5_VIS_GUARD_PATCH_LEN];
static uint8_t         g_vis_helper_saved[FM5_VIS_HELPER_PATCH_LEN];
static uint8_t         g_vis_src_saved[FM5_VIS_SRC_PATCH_LEN];
static volatile LONG   g_vis_state;        /* 0 = inativa, 1 = ativa          */
static volatile LONG   g_vis_guard_active; /* 0 = sem camada [2], 1 = [2]     */
static volatile LONG   g_vis_helper_active;/* 0 = sem camada [3], 1 = [3]     */
static volatile LONG   g_vis_src_active;   /* 0 = sem camada [4], 1 = [4]     */
static SRWLOCK         g_vis_lock = SRWLOCK_INIT;

/* Página legível? A base do título é um mapa manual: nunca leia às cegas. */
static int vis_page_readable(const void *addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    DWORD prot;

    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) {
        return 0;
    }
    if (mbi.State != MEM_COMMIT) {
        return 0;
    }
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
        return 0;
    }
    prot = mbi.Protect & 0xFFu;
    return prot == PAGE_READONLY || prot == PAGE_READWRITE ||
           prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
           prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
}

static void *vis_alloc_near(void *target, size_t size)
{
    SYSTEM_INFO si;
    uintptr_t t = (uintptr_t)target;
    uintptr_t gran;
    uintptr_t step;
    int i;

    GetSystemInfo(&si);
    gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000u;
    step = gran * 16u; /* passos de 1 MB */
    for (i = 1; i <= 2048; i++) {
        uintptr_t delta = (uintptr_t)i * step;
        void *p;
        if (delta > 0x70000000ULL) {
            break;
        }
        if (t > delta) {
            p = VirtualAlloc((void *)((t - delta) & ~(gran - 1u)), size,
                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) {
                return p;
            }
        }
        p = VirtualAlloc((void *)((t + delta) & ~(gran - 1u)), size,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p) {
            return p;
        }
    }
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
}

/* Camada [1]: store atômico de 16 bits (0x859516 é par). */
static int publish_branch_fix(uint8_t *target)
{
    uint16_t store = 0x8D0Fu; /* little-endian: 0F 8D */
    DWORD old_protect = 0;

    if (((uintptr_t)target & 1u) != 0) {
        return -1; /* alinhamento inesperado: não faz patch rasgado */
    }
    if (!VirtualProtect(target, FM5_VIS_BRANCH_PATCH_LEN,
                        PAGE_EXECUTE_READWRITE, &old_protect)) {
        return -2;
    }
    *(volatile uint16_t *)(void *)target = store;
    FlushInstructionCache(GetCurrentProcess(), target,
                          FM5_VIS_BRANCH_PATCH_LEN);
    VirtualProtect(target, FM5_VIS_BRANCH_PATCH_LEN, old_protect, &old_protect);
    return 0;
}

/* 1 se o E9 publicado em `target` ainda resolve para a nossa caverna. */
static int guard_jump_is_ours(const uint8_t *target)
{
    if (target == NULL || g_vis_cave == NULL) {
        return 0;
    }
    if (target[0] != 0xE9) {
        return 0;
    }
    return fm5_vis_decode_jump(target) == (uint64_t)(uintptr_t)g_vis_cave;
}

/* Camada [2]: store atômico de 64 bits em endereço 8-byte aligned. */
static int publish_guard_jump(uint8_t *target, void *cave)
{
    uint8_t patch[FM5_VIS_GUARD_PATCH_LEN];
    uint64_t word = 0;
    DWORD old_protect = 0;
    int i;

    if (((uintptr_t)target & (FM5_VIS_GUARD_PATCH_LEN - 1u)) != 0) {
        return -1; /* alinhamento inesperado: não faz patch rasgado */
    }
    if (fm5_vis_encode_jump(patch, (uint64_t)(uintptr_t)target,
                            (uint64_t)(uintptr_t)cave) != 0) {
        return -2; /* caverna fora de ±2 GiB (fail-closed) */
    }
    patch[5] = 0x90;
    patch[6] = 0x90;
    patch[7] = 0x90;
    for (i = 0; i < (int)FM5_VIS_GUARD_PATCH_LEN; i++) {
        word |= (uint64_t)patch[i] << (8 * i);
    }
    if (!VirtualProtect(target, FM5_VIS_GUARD_PATCH_LEN,
                        PAGE_EXECUTE_READWRITE, &old_protect)) {
        return -3;
    }
    *(volatile uint64_t *)(void *)target = word;
    FlushInstructionCache(GetCurrentProcess(), target,
                          FM5_VIS_GUARD_PATCH_LEN);
    VirtualProtect(target, FM5_VIS_GUARD_PATCH_LEN, old_protect, &old_protect);
    return 0;
}

/*
 * Instala (ou revalida) a camada [2]. Retorna 0 em sucesso e <0 em falha.
 * A falha é NÃO fatal: a camada [1] sozinha já fecha o crash.
 */
static int install_guard(uint8_t *base)
{
    uint8_t *target = base + FM5_VIS_GUARD_RVA;
    uint8_t *cave;
    size_t len;
    int rc;

    if (!vis_page_readable(target)) {
        return -3;
    }
    if (g_vis_cave == NULL) {
        cave = vis_alloc_near(target, FM5_VIS_CAVE_ALLOC);
        if (cave == NULL) {
            return -4;
        }
        len = fm5_vis_encode_guard_cave(cave, FM5_VIS_CAVE_ALLOC,
                                        (uint64_t)(uintptr_t)(
                                            base + FM5_VIS_GUARD_RESUME_RVA));
        if (len != FM5_VIS_GUARD_CAVE_LEN) {
            VirtualFree(cave, 0, MEM_RELEASE);
            return -5;
        }
        g_vis_cave = cave;
    }
    if (guard_jump_is_ours(target)) {
        g_vis_guard_target = target;
        return 0; /* rearme: E9 já aponta para a nossa caverna */
    }
    if (!fm5_vis_is_guard_sequence(target)) {
        return -6; /* build divergente: não sobrescreve o prologue */
    }
    memcpy(g_vis_guard_saved, target, FM5_VIS_GUARD_PATCH_LEN);
    rc = publish_guard_jump(target, g_vis_cave);
    if (rc != 0) {
        return -7;
    }
    g_vis_guard_target = target;
    return 0;
}

/* 1 se o E9 publicado em `target` ainda resolve para a caverna da [4]. */
static int src_jump_is_ours(const uint8_t *target)
{
    if (target == NULL || g_vis_src_cave == NULL) {
        return 0;
    }
    if (target[0] != 0xE9) {
        return 0;
    }
    return fm5_vis_decode_jump(target) == (uint64_t)(uintptr_t)g_vis_src_cave;
}

/*
 * Instala (ou revalida) a camada [3]: troca `74 26` (JE) por `73 26` (JAE)
 * no helper de cópia 0x85b770 via store atômico de 16 bits no word par
 * 0x85b772. Falha é NÃO fatal: as camadas [1]/[2] seguem válidas.
 */
static int install_helper(uint8_t *base)
{
    uint8_t *target = base + FM5_VIS_HELPER_RVA;       /* 5 bytes vivos    */
    uint8_t *store = base + FM5_VIS_HELPER_STORE_RVA;  /* word PAR do jcc  */
    DWORD old_protect = 0;
    uint16_t word;

    if (!vis_page_readable(target)) {
        return -3;
    }
    if (((uintptr_t)store & 1u) != 0) {
        return -1; /* word não par: não faz patch rasgado */
    }
    if (fm5_vis_is_helper_fixed(target)) {
        if (g_vis_helper_target == NULL) {
            /* Fix veio de fora (instância anterior): guarda o word atual
             * para o uninstall não escrever o zero-init por cima. */
            memcpy(g_vis_helper_saved, store, FM5_VIS_HELPER_PATCH_LEN);
        }
        g_vis_helper_target = target;
        return 0; /* rearme: fix já publicado */
    }
    if (!fm5_vis_is_helper_original(target)) {
        return -6; /* build divergente: não toca no word (fail-closed) */
    }
    memcpy(g_vis_helper_saved, store, FM5_VIS_HELPER_PATCH_LEN);
    word = FM5_VIS_HELPER_FIXED_WORD;
    if (!VirtualProtect(store, FM5_VIS_HELPER_PATCH_LEN,
                        PAGE_EXECUTE_READWRITE, &old_protect)) {
        return -7;
    }
    *(volatile uint16_t *)(void *)store = word;
    FlushInstructionCache(GetCurrentProcess(), store,
                          FM5_VIS_HELPER_PATCH_LEN);
    VirtualProtect(store, FM5_VIS_HELPER_PATCH_LEN, old_protect, &old_protect);
    if (!fm5_vis_is_helper_fixed(target)) {
        return -8; /* escrita não pegou: rearme tentado na próxima */
    }
    g_vis_helper_target = target;
    return 0;
}

/*
 * Instala (ou revalida) a camada [4]: E9 rel32 em 0x8580e0 para uma caverna
 * que reemite as duas instruções originais e clampa r8 (where) em _Mylast
 * antes do call 0x8580e8. Falha é NÃO fatal (melhor esforço).
 */
static int install_src(uint8_t *base)
{
    uint8_t *target = base + FM5_VIS_SRC_RVA;
    uint8_t *cave;
    size_t len;
    int rc;

    if (!vis_page_readable(target)) {
        return -3;
    }
    if (g_vis_src_cave == NULL) {
        cave = vis_alloc_near(target, FM5_VIS_CAVE_ALLOC);
        if (cave == NULL) {
            return -4;
        }
        len = fm5_vis_encode_src_cave(
            cave, FM5_VIS_CAVE_ALLOC,
            (uint64_t)(uintptr_t)cave,
            (uint64_t)(uintptr_t)(base + FM5_VIS_MYLAST_RVA),
            (uint64_t)(uintptr_t)(base + FM5_VIS_SRC_RESUME_RVA));
        if (len != FM5_VIS_SRC_CAVE_LEN) {
            VirtualFree(cave, 0, MEM_RELEASE);
            return -5;
        }
        g_vis_src_cave = cave;
    }
    if (src_jump_is_ours(target)) {
        g_vis_src_target = target;
        return 0; /* rearme: E9 já aponta para a nossa caverna */
    }
    if (!fm5_vis_is_src_sequence(target)) {
        return -6; /* build divergente: não sobrescreve o call site */
    }
    memcpy(g_vis_src_saved, target, FM5_VIS_SRC_PATCH_LEN);
    rc = publish_guard_jump(target, g_vis_src_cave);
    if (rc != 0) {
        return -7;
    }
    g_vis_src_target = target;
    return 0;
}

int fm5_visibility_shield_install(uint8_t *base)
{
    uint8_t *branch;
    int was_active;
    int guard_rc;
    int helper_rc;
    int src_rc;

    if (base == NULL) {
        return -1;
    }
    if (g_vis_state == 1 && fm5_visibility_shield_intact()) {
        return 1;
    }
    AcquireSRWLockExclusive(&g_vis_lock);
    was_active = (g_vis_state == 1);
    branch = base + FM5_VIS_BRANCH_RVA;

    if (!vis_page_readable(branch) ||
        !(fm5_vis_is_branch_original(branch) ||
          fm5_vis_is_branch_fixed(branch))) {
        ReleaseSRWLockExclusive(&g_vis_lock);
        return -2; /* fail-closed: nada foi escrito */
    }
    if (fm5_vis_is_branch_original(branch)) {
        if (publish_branch_fix(branch) != 0) {
            ReleaseSRWLockExclusive(&g_vis_lock);
            return -6;
        }
    }
    g_vis_branch_target = branch;

    /* Camada [2]: melhor esforço — nunca invalida a camada [1]. */
    guard_rc = install_guard(base);
    if (guard_rc == 0) {
        InterlockedExchange(&g_vis_guard_active, 1);
    } else if (g_vis_guard_active != 1) {
        fm5_log_printf("P2: trava de visibilidade (where/_Mylast em 0x%05x) "
                "indisponivel (rc=%d) — branch JGE segue ativo",
                (unsigned)FM5_VIS_GUARD_RVA, guard_rc);
    }

    /* Camada [3]: melhor esforço — helper `74` -> `73` (0x85b770). */
    helper_rc = install_helper(base);
    if (helper_rc == 0) {
        InterlockedExchange(&g_vis_helper_active, 1);
    } else if (g_vis_helper_active != 1) {
        fm5_log_printf("P2: helper de copia (em 0x%05x) indisponivel "
                "(rc=%d) — JGE + trava seguem ativos",
                (unsigned)FM5_VIS_HELPER_RVA, helper_rc);
    }

    /* Camada [4]: melhor esforço — clamp de where na fonte (0x8580e0). */
    src_rc = install_src(base);
    if (src_rc == 0) {
        InterlockedExchange(&g_vis_src_active, 1);
    } else if (g_vis_src_active != 1) {
        fm5_log_printf("P2: trava na fonte do insert (em 0x%05x) "
                "indisponivel (rc=%d) — demais camadas seguem ativas",
                (unsigned)FM5_VIS_SRC_RVA, src_rc);
    }

    g_vis_state = 1;
    ReleaseSRWLockExclusive(&g_vis_lock);
    return was_active ? 1 : 0;
}

void fm5_visibility_shield_uninstall(uint8_t *base)
{
    DWORD old_protect = 0;

    if (base == NULL) {
        return;
    }
    AcquireSRWLockExclusive(&g_vis_lock);
    if (g_vis_guard_active == 1 && g_vis_guard_target != NULL) {
        if (VirtualProtect(g_vis_guard_target, FM5_VIS_GUARD_PATCH_LEN,
                           PAGE_EXECUTE_READWRITE, &old_protect)) {
            memcpy(g_vis_guard_target, g_vis_guard_saved,
                   FM5_VIS_GUARD_PATCH_LEN);
            FlushInstructionCache(GetCurrentProcess(), g_vis_guard_target,
                                  FM5_VIS_GUARD_PATCH_LEN);
            VirtualProtect(g_vis_guard_target, FM5_VIS_GUARD_PATCH_LEN,
                           old_protect, &old_protect);
        }
    }
    /* Camada [4]: restaura o E9 da fonte ANTES de liberar a caverna. */
    if (g_vis_src_active == 1 && g_vis_src_target != NULL) {
        uint8_t *starget = g_vis_src_target;
        if (src_jump_is_ours(starget) &&
            VirtualProtect(starget, FM5_VIS_SRC_PATCH_LEN,
                           PAGE_EXECUTE_READWRITE, &old_protect)) {
            memcpy(starget, g_vis_src_saved, FM5_VIS_SRC_PATCH_LEN);
            FlushInstructionCache(GetCurrentProcess(), starget,
                                  FM5_VIS_SRC_PATCH_LEN);
            VirtualProtect(starget, FM5_VIS_SRC_PATCH_LEN, old_protect,
                           &old_protect);
        }
    }
    /* Camada [3]: devolve `73` -> `74` no helper (só se o fix é nosso). */
    if (g_vis_helper_active == 1 && g_vis_helper_target != NULL) {
        uint8_t *htarget = g_vis_helper_target;
        uint8_t *hstore = htarget + (FM5_VIS_HELPER_STORE_RVA -
                                     FM5_VIS_HELPER_RVA);
        if (fm5_vis_is_helper_fixed(htarget) &&
            VirtualProtect(hstore, FM5_VIS_HELPER_PATCH_LEN,
                           PAGE_EXECUTE_READWRITE, &old_protect)) {
            memcpy(hstore, g_vis_helper_saved, FM5_VIS_HELPER_PATCH_LEN);
            FlushInstructionCache(GetCurrentProcess(), hstore,
                                  FM5_VIS_HELPER_PATCH_LEN);
            VirtualProtect(hstore, FM5_VIS_HELPER_PATCH_LEN, old_protect,
                           &old_protect);
        }
    }
    if (g_vis_cave != NULL) {
        VirtualFree(g_vis_cave, 0, MEM_RELEASE);
        g_vis_cave = NULL;
    }
    if (g_vis_src_cave != NULL) {
        VirtualFree(g_vis_src_cave, 0, MEM_RELEASE);
        g_vis_src_cave = NULL;
    }
    if (g_vis_branch_target != NULL) {
        uint8_t *branch = g_vis_branch_target;
        if (vis_page_readable(branch) && fm5_vis_is_branch_fixed(branch) &&
            VirtualProtect(branch, FM5_VIS_BRANCH_PATCH_LEN,
                           PAGE_EXECUTE_READWRITE, &old_protect)) {
            branch[0] = fm5_vis_branch_original()[0];
            branch[1] = fm5_vis_branch_original()[1];
            FlushInstructionCache(GetCurrentProcess(), branch,
                                  FM5_VIS_BRANCH_PATCH_LEN);
            VirtualProtect(branch, FM5_VIS_BRANCH_PATCH_LEN, old_protect,
                           &old_protect);
        }
    }
    g_vis_branch_target = NULL;
    g_vis_guard_target = NULL;
    g_vis_helper_target = NULL;
    g_vis_src_target = NULL;
    InterlockedExchange(&g_vis_guard_active, 0);
    InterlockedExchange(&g_vis_helper_active, 0);
    InterlockedExchange(&g_vis_src_active, 0);
    g_vis_state = 0;
    ReleaseSRWLockExclusive(&g_vis_lock);
}

int fm5_visibility_shield_active(void)
{
    return (g_vis_state == 1) ? 1 : 0;
}

int fm5_visibility_shield_guard_active(void)
{
    return (g_vis_guard_active == 1) ? 1 : 0;
}

int fm5_visibility_shield_intact(void)
{
    uint8_t *branch = g_vis_branch_target;

    if (g_vis_state != 1 || branch == NULL) {
        return 0;
    }
    if (!vis_page_readable(branch) || !fm5_vis_is_branch_fixed(branch)) {
        return 0;
    }
    if (g_vis_guard_active == 1) {
        uint8_t *gtarget = g_vis_guard_target;
        if (gtarget == NULL || !vis_page_readable(gtarget)) {
            return 0;
        }
        if (!guard_jump_is_ours(gtarget)) {
            return 0; /* sobrescrito pelo mapeador: rearme necessário */
        }
    }
    if (g_vis_helper_active == 1) {
        uint8_t *htarget = g_vis_helper_target;
        if (htarget == NULL || !vis_page_readable(htarget)) {
            return 0;
        }
        if (!fm5_vis_is_helper_fixed(htarget)) {
            return 0; /* `73` revertido pelo mapeador: rearme necessário */
        }
    }
    if (g_vis_src_active == 1) {
        uint8_t *starget = g_vis_src_target;
        if (starget == NULL || !vis_page_readable(starget)) {
            return 0;
        }
        if (!src_jump_is_ours(starget)) {
            return 0; /* E9 da fonte sobrescrito: rearme necessário */
        }
    }
    return 1;
}
