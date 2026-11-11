/*
 * fm5_detour.c — implementação do motor de detour (Windows/x86-64).
 */
#include "fm5_detour.h"

#ifndef _WIN32
#error "fm5_detour.c e apenas para o build Windows (mingw-w64)."
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

#include "fm5_patch_bytes.h"

#define FM5_TRAMPOLINE_SIZE 96

/* Aloca o trampolim o mais perto possível do alvo: o E8/E9 relocado só alcança
 * destinos dentro de ±2 GB. A varredura é limitada; se nada perto estiver
 * livre, cai no VirtualAlloc(NULL) e a checagem de alcance decide se o hook
 * pode ser instalado (fail-closed). */
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

int fm5_hook_install(fm5_hook_t *hook)
{
    void *tramp;
    uint8_t patch[32];
    DWORD old_protect = 0;

    if (!hook || !hook->target || !hook->hook_fn) {
        return -1;
    }
    if (hook->patch_len < FM5_ABS_JMP_LEN ||
        hook->patch_len > sizeof(hook->saved)) {
        return -2;
    }
    if (hook->expect && hook->expect_len > 0 &&
        memcmp(hook->target, hook->expect, hook->expect_len) != 0) {
        return -3; /* assinatura divergente: fail-closed, nao corrompe nada */
    }

    tramp = alloc_near(hook->target, FM5_TRAMPOLINE_SIZE);
    if (!tramp) {
        return -4;
    }

    /* Copia os bytes originais e corrige eventual rel32 conhecido. */
    memcpy(hook->saved, hook->target, hook->patch_len);
    memcpy(tramp, hook->target, hook->patch_len);

    if (hook->rel32_offset >= 0 &&
        (size_t)(hook->rel32_offset + 5) <= hook->patch_len) {
        int off = hook->rel32_offset;
        int32_t new_disp = 0;
        int rc = fm5_relocate_rel32_checked(
            (const uint8_t *)tramp, hook->patch_len, hook->rel32_offset,
            (uint64_t)(uintptr_t)hook->target, (uint64_t)(uintptr_t)tramp,
            &new_disp);
        if (rc < 0) {
            /* Trampolim longe demais para o rel32: nao instala o hook. */
            VirtualFree(tramp, 0, MEM_RELEASE);
            return -6;
        }
        if (rc > 0) {
            fm5_write_rel32((uint8_t *)tramp + off + 1, new_disp);
        }
    }

    /* Trampolim: bytes originais + jmp absoluto indireto (rip-relative) de
     * volta ao alvo+patch_len. Nenhum registrador é alterado. */
    fm5_encode_tail((uint8_t *)tramp + hook->patch_len,
                    (uint64_t)(uintptr_t)hook->target + hook->patch_len);
    hook->trampoline = tramp;

    /* Prepara o patch de entrada: jmp absoluto + NOPs. */
    fm5_encode_abs_jmp(patch, (uint64_t)(uintptr_t)hook->hook_fn);
    fm5_fill_nops(patch, FM5_ABS_JMP_LEN, hook->patch_len);

    if (!VirtualProtect(hook->target, hook->patch_len, PAGE_EXECUTE_READWRITE,
                        &old_protect)) {
        VirtualFree(tramp, 0, MEM_RELEASE);
        hook->trampoline = NULL;
        return -5;
    }
    memcpy(hook->target, patch, hook->patch_len);
    FlushInstructionCache(GetCurrentProcess(), hook->target, hook->patch_len);
    VirtualProtect(hook->target, hook->patch_len, old_protect, &old_protect);

    hook->installed = 1;
    return 0;
}

void fm5_hook_uninstall(fm5_hook_t *hook)
{
    DWORD old_protect = 0;
    if (!hook || !hook->installed || !hook->target) {
        return;
    }
    if (VirtualProtect(hook->target, hook->patch_len, PAGE_EXECUTE_READWRITE,
                       &old_protect)) {
        memcpy(hook->target, hook->saved, hook->patch_len);
        FlushInstructionCache(GetCurrentProcess(), hook->target,
                              hook->patch_len);
        VirtualProtect(hook->target, hook->patch_len, old_protect,
                       &old_protect);
    }
    if (hook->trampoline) {
        VirtualFree(hook->trampoline, 0, MEM_RELEASE);
        hook->trampoline = NULL;
    }
    hook->installed = 0;
}
