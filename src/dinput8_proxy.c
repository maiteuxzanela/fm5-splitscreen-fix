/*
 * dinput8_proxy.c — DLL proxy de dinput8 para o Azimuth (Player 2).
 *
 * O azimuth.exe importa DINPUT8.dll. Colocamos esta DLL no diretório do jogo
 * com o nome dinput8.dll; o Wine a carrega (com WINEDLLOVERRIDES=dinput8=n,b)
 * e nós:
 *   1) instalamos os hooks WinRT do split-screen (fm5_hooks_init);
 *   2) encaminhamos os 5 exports reais de dinput8 para a DLL nativa original.
 *
 * A DLL real é procurada, em ordem, em:
 *   - $FM5_DINPUT8_REAL (caminho explícito)
 *   - <dir do exe>\dinput8_real.dll (cópia feita pelo run_fm5_p2_split.sh)
 *   - <system32>\dinput8.dll
 * Um guarda de recursão evita que o proxy carregue a si mesmo quando o Wine
 * resolve o nome dinput8 de volta para o diretório do jogo.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fm5_hooks.h"
#include "fm5_log.h"
#include "fm5_once_loader.h"

static HMODULE g_self;

/* TICKET-HARNESS-167: carregamento serializado da DLL real.
 *
 * Antes: `g_real_tried = 1` era marcado ANTES de LoadLibraryA (23 ms no
 * Wine); a segunda thread (wine_wginput_worker x "Azimuth wheels") via
 * trial=1/handle=NULL recebia E_FAIL. Agora fm5_once_resolve mantém o
 * lock exclusivo durante toda a carga: a segunda thread espera e recebe o
 * handle válido. */
static fm5_once_loader_t g_real_loader = FM5_ONCE_LOADER_INIT;

static HMODULE try_load(const char *path)
{
    HMODULE h;
    if (!path || !path[0]) {
        return NULL;
    }
    h = LoadLibraryA(path);
    if (!h) {
        return NULL;
    }
    if (h == g_self) {
        /* Recursão: o loader resolveu o nome de volta para o proxy. */
        FreeLibrary(h);
        return NULL;
    }
    return h;
}

/*
 * do_load_real — callback executado uma única vez, SEGURANDO o lock
 * exclusivo do loader (ver fm5_once_loader.h). O log usa tid para provar no
 * fm5_p2_hook.log qual thread ("Azimuth wheels" ou "wine_wginput_worker")
 * executou a carga e que a outra apenas aguardou.
 */
static void *do_load_real(void *ctx)
{
    char exe[MAX_PATH];
    char path[MAX_PATH];
    const char *env;
    char *slash;
    UINT sys_len;
    HMODULE real;

    (void)ctx;

    env = getenv("FM5_DINPUT8_REAL");
    if (env && env[0]) {
        real = try_load(env);
        if (real) {
            fm5_log_printf("[dinput8_proxy] resolve_real: loaded %s -> %p (tid=%lu)\n",
                           env, (void *)real, fm5_log_tid());
            return real;
        }
    }

    if (GetModuleFileNameA(NULL, exe, MAX_PATH)) {
        slash = strrchr(exe, '\\');
        if (slash) {
            slash[1] = '\0';
        }
        if (strlen(exe) + 18 < sizeof(path)) {
            strcpy(path, exe);
            strcat(path, "dinput8_real.dll");
            real = try_load(path);
            if (real) {
                fm5_log_printf("[dinput8_proxy] resolve_real: loaded %s -> %p (tid=%lu)\n",
                               path, (void *)real, fm5_log_tid());
                return real;
            }
        }
    }

    sys_len = GetSystemDirectoryA(path, MAX_PATH);
    if (sys_len > 0 && sys_len + 14 < MAX_PATH) {
        strcat(path, "\\dinput8.dll");
        real = try_load(path);
        if (real) {
            fm5_log_printf("[dinput8_proxy] resolve_real: loaded %s -> %p (tid=%lu)\n",
                           path, (void *)real, fm5_log_tid());
            return real;
        }
    }

    fm5_log_printf("[dinput8_proxy] resolve_real: ERRO - dinput8 real nao "
                   "encontrado (tid=%lu)\n", fm5_log_tid());
    return NULL;
}

static HMODULE resolve_real(void)
{
    return (HMODULE)fm5_once_resolve(&g_real_loader, do_load_real, NULL);
}

/* ------------------------------------------------------------------------- */
/* Resolução lazy (serializada) dos pontos de entrada reais                  */
/* ------------------------------------------------------------------------- */
typedef struct fm5_proc_ctx {
    const char *name;
} fm5_proc_ctx_t;

static void *do_load_proc(void *ctx)
{
    const fm5_proc_ctx_t *pc = (const fm5_proc_ctx_t *)ctx;
    HMODULE real;

    if (!pc || !pc->name) {
        return NULL;
    }
    real = resolve_real();
    if (!real) {
        return NULL;
    }
    return (void *)GetProcAddress(real, pc->name);
}

static FARPROC real_proc(fm5_once_loader_t *loader, const char *name)
{
    fm5_proc_ctx_t ctx;

    ctx.name = name;
    return (FARPROC)fm5_once_resolve(loader, do_load_proc, &ctx);
}

/* ------------------------------------------------------------------------- */
/* DllMain                                                                   */
/* ------------------------------------------------------------------------- */
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = (HMODULE)hinst;
        DisableThreadLibraryCalls(hinst);
        /* Instala os hooks WinRT cedo: a UI de usuários pode ser consultada
         * antes de qualquer chamada a DirectInput. */
        fm5_hooks_init();
    } else if (reason == DLL_PROCESS_DETACH) {
        fm5_hooks_shutdown();
    }
    return TRUE;
}

/* ------------------------------------------------------------------------- */
/* Exports reais de dinput8.dll (Wine/Proton)                                */
/* ------------------------------------------------------------------------- */
typedef HRESULT (WINAPI *DirectInput8Create_t)(HINSTANCE, DWORD,
                                               const GUID *, LPVOID *,
                                               void *);
typedef HRESULT (WINAPI *DllCanUnloadNow_t)(void);
typedef HRESULT (WINAPI *DllGetClassObject_t)(const GUID *, const GUID *,
                                              LPVOID *);
typedef HRESULT (WINAPI *DllRegisterServer_t)(void);
typedef HRESULT (WINAPI *DllUnregisterServer_t)(void);

/* TICKET-HARNESS-167: cada ponteiro lazy tem seu próprio once-loader; a
 * primeira chamada concorrente resolve GetProcAddress e todas as demais
 * recebem o ponteiro já preenchido, nunca NULL transitório. */
static fm5_once_loader_t g_p_DirectInput8Create = FM5_ONCE_LOADER_INIT;
static fm5_once_loader_t g_p_DllCanUnloadNow = FM5_ONCE_LOADER_INIT;
static fm5_once_loader_t g_p_DllGetClassObject = FM5_ONCE_LOADER_INIT;
static fm5_once_loader_t g_p_DllRegisterServer = FM5_ONCE_LOADER_INIT;
static fm5_once_loader_t g_p_DllUnregisterServer = FM5_ONCE_LOADER_INIT;

HRESULT WINAPI DirectInput8Create(HINSTANCE hinst, DWORD dwVersion,
                                  const GUID *riidltf, LPVOID *ppvOut,
                                  void *punkOuter)
{
    static volatile LONG call_count;
    DirectInput8Create_t fn =
        (DirectInput8Create_t)real_proc(&g_p_DirectInput8Create,
                                        "DirectInput8Create");
    LONG n = InterlockedIncrement(&call_count);
    HRESULT hr;

    if (!fn) {
        hr = (HRESULT)0x80004005; /* E_FAIL */
    } else {
        hr = fn(hinst, dwVersion, riidltf, ppvOut, punkOuter);
    }

    /* Loga no máximo as 16 primeiras chamadas para não inundar o log. */
    if (n <= 16) {
        fm5_log_printf("[dinput8_proxy] DirectInput8Create(tid=%lu) -> "
                       "real=%p hr=0x%08lx\n",
                       fm5_log_tid(), (void *)resolve_real(),
                       (unsigned long)(uint32_t)hr);
    }

    return hr;
}

HRESULT WINAPI DllCanUnloadNow(void)
{
    DllCanUnloadNow_t fn = (DllCanUnloadNow_t)
        real_proc(&g_p_DllCanUnloadNow, "DllCanUnloadNow");
    if (!fn) {
        return (HRESULT)0x80004005;
    }
    return fn();
}

HRESULT WINAPI DllGetClassObject(const GUID *rclsid, const GUID *riid,
                                 LPVOID *ppv)
{
    DllGetClassObject_t fn = (DllGetClassObject_t)
        real_proc(&g_p_DllGetClassObject, "DllGetClassObject");
    if (!fn) {
        return (HRESULT)0x80004005;
    }
    return fn(rclsid, riid, ppv);
}

HRESULT WINAPI DllRegisterServer(void)
{
    DllRegisterServer_t fn = (DllRegisterServer_t)
        real_proc(&g_p_DllRegisterServer, "DllRegisterServer");
    if (!fn) {
        return (HRESULT)0x80004005;
    }
    return fn();
}

HRESULT WINAPI DllUnregisterServer(void)
{
    DllUnregisterServer_t fn = (DllUnregisterServer_t)
        real_proc(&g_p_DllUnregisterServer, "DllUnregisterServer");
    if (!fn) {
        return (HRESULT)0x80004005;
    }
    return fn();
}
