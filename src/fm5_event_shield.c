/*
 * fm5_event_shield.c — instalação Windows da guarda anti-NULL da fila de
 * eventos do executável do TÍTULO (crash 0xC0000005 em rip=0x140687f4c).
 *
 * Estratégia:
 *   1. os 7 bytes vivos em base+0x687f48 precisam casar com a sequência
 *      forense (mov rax,[rcx+8]; mov [rax],rcx) — senão NADA é escrito
 *      (fail-closed: base errada, página ilegível ou build divergente);
 *   2. aloca uma caverna executável dentro de ±2 GiB do alvo (o salto de
 *      entrada é um E9 rel32 de 5 bytes);
 *   3. escreve a caverna: mov rax,[rcx+8]; pushfq; test rax,rax; jz skip;
 *      mov [rax],rcx; skip: popfq; jmp [rip+0] -> base+0x687f4f;
 *   4. publica o E9 com um ÚNICO store de 8 bytes alinhado (0x687f48 é
 *      8-byte aligned) preservando os bytes 5..7 que não são cobertos pelo
 *      patch lógico de 5 bytes. Isso evita patch "rasgado" em outra thread
 *      que esteja executando a função durante a transição de tela;
 *   5. RE-DETECÇÃO: fm5_event_shield_intact() confere que o E9 publicado
 *      ainda aponta para a nossa caverna. Se o mapeador/decifrador reescrever
 *      os 7 bytes e devolver a sequência original, install() reaplica o salto
 *      (reusando a mesma caverna); se os bytes forem outros, falha fechado.
 *
 * A validação é feita SEMPRE contra os bytes vivos e SÓ depois de confirmar
 * que a página está legível (never read blind: a base do título é um mapa
 * manual do Azimuth, não um módulo do loader).
 */
#include "fm5_event_shield.h"

#ifndef _WIN32
#error "fm5_event_shield.c e apenas para o build Windows (mingw-w64)."
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

#include "fm5_event_shield_encode.h"
#include "fm5_log.h"

#define FM5_SHIELD_CAVE_ALLOC 64u
#define FM5_SHIELD_STORE_LEN  8u   /* store atômico alinhado (RVA termina em 8) */

static void           *g_shield_cave;
static uint8_t        *g_shield_target;
static volatile LONG   g_shield_state;   /* 0 = inativa, 1 = ativa */
static SRWLOCK         g_shield_lock = SRWLOCK_INIT;

/* Página legível? A base do título é um mapa manual: nunca leia às cegas. */
static int shield_page_readable(const void *addr)
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

static void *alloc_near(void *target, size_t size)
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

/* Publica (ou republica) o E9 alinhado para `cave` sem patch rasgado. */
static int publish_jump(uint8_t *target, void *cave)
{
    uint8_t patch[FM5_SHIELD_PATCH_LEN];
    uint64_t store;
    DWORD old_protect = 0;

    if (((uintptr_t)target & (FM5_SHIELD_STORE_LEN - 1u)) != 0) {
        return -1; /* alinhamento inesperado: não faz patch rasgado */
    }
    if (fm5_shield_encode_jump(patch, (uint64_t)(uintptr_t)target,
                               (uint64_t)(uintptr_t)cave) != 0) {
        return -2; /* caverna fora de ±2 GiB (fail-closed) */
    }
    if (!VirtualProtect(target, FM5_SHIELD_STORE_LEN,
                        PAGE_EXECUTE_READWRITE, &old_protect)) {
        return -3;
    }
    /* Preserva os bytes 5..7 (resto da instrução morta + 1º byte da
     * instrução de retomada) e troca só os 5 do E9. */
    memcpy(&store, target, sizeof(store));
    memcpy(&store, patch, FM5_SHIELD_PATCH_LEN);
    *(volatile uint64_t *)(void *)target = store;
    FlushInstructionCache(GetCurrentProcess(), target, FM5_SHIELD_STORE_LEN);
    VirtualProtect(target, FM5_SHIELD_STORE_LEN, old_protect, &old_protect);
    return 0;
}

int fm5_event_shield_intact(void)
{
    const uint8_t *p;
    int32_t disp;

    if (g_shield_state != 1 || !g_shield_target || !g_shield_cave) {
        return 0;
    }
    p = g_shield_target;
    if (!shield_page_readable(p)) {
        return 0;
    }
    if (p[0] != 0xE9) {
        return 0;
    }
    memcpy(&disp, p + 1, sizeof(disp));
    return (uint64_t)(uintptr_t)(p + FM5_SHIELD_PATCH_LEN) + (int64_t)disp ==
           (uint64_t)(uintptr_t)g_shield_cave;
}

int fm5_event_shield_install(uint8_t *base)
{
    uint8_t *target;
    void    *cave;
    size_t   cave_len;

    if (!base) {
        return -1;
    }
    /* Caminho rápido (a cada poll): ativa e íntegra. */
    if (g_shield_state == 1 && fm5_event_shield_intact()) {
        return 1;
    }

    AcquireSRWLockExclusive(&g_shield_lock);
    if (g_shield_state == 1) {
        int rc;
        if (fm5_event_shield_intact()) {
            ReleaseSRWLockExclusive(&g_shield_lock);
            return 1;
        }
        /* Alvo reescrito: reusa a caverna só se voltou a ser a sequência
         * original do build 1.0.0.20 (fail-closed em qualquer outro caso). */
        target = base + FM5_SHIELD_RVA;
        if (!shield_page_readable(target) || !fm5_shield_is_original(target)) {
            ReleaseSRWLockExclusive(&g_shield_lock);
            return -2;
        }
        rc = publish_jump(target, g_shield_cave);
        ReleaseSRWLockExclusive(&g_shield_lock);
        if (rc == 0) {
            fm5_log_printf("P2: guarda NULL na fila de eventos (0x%05x) "
                           "rearmada na mesma cave=%p (tid=%lu)",
                           (unsigned)FM5_SHIELD_RVA, g_shield_cave,
                           fm5_log_tid());
        }
        return rc;
    }

    target = base + FM5_SHIELD_RVA;
    if (!shield_page_readable(target) || !fm5_shield_is_original(target)) {
        ReleaseSRWLockExclusive(&g_shield_lock);
        return -2; /* base errada / não mapeada / build divergente */
    }

    cave = alloc_near(target, FM5_SHIELD_CAVE_ALLOC);
    if (!cave) {
        ReleaseSRWLockExclusive(&g_shield_lock);
        return -3;
    }
    cave_len = fm5_shield_encode_cave(
        (uint8_t *)cave, FM5_SHIELD_CAVE_ALLOC,
        (uint64_t)(uintptr_t)(base + FM5_SHIELD_RESUME_RVA));
    if (cave_len != FM5_SHIELD_CAVE_LEN) {
        VirtualFree(cave, 0, MEM_RELEASE);
        ReleaseSRWLockExclusive(&g_shield_lock);
        return -4;
    }
    if (publish_jump(target, cave) != 0) {
        VirtualFree(cave, 0, MEM_RELEASE);
        ReleaseSRWLockExclusive(&g_shield_lock);
        return -5;
    }

    g_shield_cave = cave;
    g_shield_target = target;
    g_shield_state = 1;
    ReleaseSRWLockExclusive(&g_shield_lock);

    fm5_log_printf("P2: guarda NULL na fila de eventos (0x%05x) instalada — "
                   "cave=%p (tid=%lu)",
                   (unsigned)FM5_SHIELD_RVA, cave, fm5_log_tid());
    return 0;
}

void fm5_event_shield_uninstall(uint8_t *base)
{
    uint8_t *target;
    DWORD old_protect = 0;

    if (!base || g_shield_state != 1) {
        return;
    }
    AcquireSRWLockExclusive(&g_shield_lock);
    if (g_shield_state == 1) {
        target = base + FM5_SHIELD_RVA;
        if (shield_page_readable(target) &&
            VirtualProtect(target, FM5_SHIELD_STORE_LEN,
                           PAGE_EXECUTE_READWRITE, &old_protect)) {
            memcpy(target, fm5_shield_original(), FM5_SHIELD_ORIG_LEN);
            FlushInstructionCache(GetCurrentProcess(), target,
                                  FM5_SHIELD_ORIG_LEN);
            VirtualProtect(target, FM5_SHIELD_STORE_LEN, old_protect,
                           &old_protect);
        }
        if (g_shield_cave) {
            VirtualFree(g_shield_cave, 0, MEM_RELEASE);
            g_shield_cave = NULL;
        }
        g_shield_target = NULL;
        g_shield_state = 0;
    }
    ReleaseSRWLockExclusive(&g_shield_lock);
}

int fm5_event_shield_active(void)
{
    return g_shield_state == 1;
}
