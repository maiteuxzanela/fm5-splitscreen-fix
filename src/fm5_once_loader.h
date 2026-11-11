/*
 * fm5_once_loader.h — resolução única, serializada e thread-safe.
 *
 * Problema real (TICKET-HARNESS-167): no Wine/Proton, a DLL
 * windows.gaming.input (thread wine_wginput_worker) e a thread "Azimuth
 * wheels" do azimuth.exe chamam DirectInput8Create com ~10 ms de diferença.
 * A primeira entra em resolve_real() e gasta ~23 ms dentro de
 * LoadLibraryA("dinput8_real.dll"); a segunda via `g_real == NULL &&
 * g_real_tried == 1` recebia NULL (E_FAIL) e abortava a enumeração de
 * gamepads.
 *
 * Este cabeçalho implementa o padrão "once" correto: o callback de carga é
 * executado SEGURANDO O LOCK EXCLUSIVO. A primeira thread carrega; qualquer
 * outra que chame fm5_once_resolve() durante a carga fica bloqueada no lock
 * e, ao entrar, encontra tried != 0 e o handle já preenchido — nunca NULL
 * transitório, nunca carga duplicada.
 *
 * Portabilidade:
 *   - Windows (mingw/Proton): SRWLOCK + Acquire/ReleaseSRWLockExclusive.
 *   - POSIX (testes Linux):    pthread_mutex_t + pthread_mutex_lock/unlock.
 *
 * Header puro, sem dependências além do lock nativo — testável em Linux sem
 * mocks (tests/test_fm5_once_loader.c).
 */
#ifndef FM5_ONCE_LOADER_H
#define FM5_ONCE_LOADER_H

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <pthread.h>
#endif

typedef struct fm5_once_loader {
#ifdef _WIN32
    SRWLOCK lock;
#else
    pthread_mutex_t lock;
#endif
    void *handle;      /* resultado do load_fn; NULL também é cacheado */
    volatile int tried; /* 0 = nunca tentou; 1 = tentou (com sucesso ou não) */
} fm5_once_loader_t;

/* Inicializador estático (usável em variável global/estática). */
#ifdef _WIN32
#  define FM5_ONCE_LOADER_INIT { SRWLOCK_INIT, NULL, 0 }
#else
#  define FM5_ONCE_LOADER_INIT { PTHREAD_MUTEX_INITIALIZER, NULL, 0 }
#endif

/* Inicializador dinâmico (para variáveis em heap/stack). */
static inline void fm5_once_loader_init(fm5_once_loader_t *loader)
{
    if (!loader) {
        return;
    }
    loader->handle = NULL;
    loader->tried = 0;
#ifdef _WIN32
    InitializeSRWLock(&loader->lock);
#else
    pthread_mutex_init(&loader->lock, NULL);
#endif
}

static inline void fm5_once_loader_lock(fm5_once_loader_t *loader)
{
#ifdef _WIN32
    AcquireSRWLockExclusive(&loader->lock);
#else
    pthread_mutex_lock(&loader->lock);
#endif
}

static inline void fm5_once_loader_unlock(fm5_once_loader_t *loader)
{
#ifdef _WIN32
    ReleaseSRWLockExclusive(&loader->lock);
#else
    pthread_mutex_unlock(&loader->lock);
#endif
}

/*
 * Executa load_fn(ctx) no máximo UMA vez por loader.
 *
 * Contrato:
 *   - O lock exclusivo é adquirido ANTES de testar `tried` e só é liberado
 *     depois de gravar `handle` e marcar `tried = 1` — logo, threads
 *     concorrentes esperam a carga terminar e recebem o MESMO handle.
 *   - Falha (load_fn devolve NULL) também é cacheada: não há retry
 *     implosivo nem corrida de recarga.
 *   - Retorna o handle cacheado (pode ser NULL em caso de falha).
 */
static inline void *fm5_once_resolve(fm5_once_loader_t *loader,
                                     void *(*load_fn)(void *ctx), void *ctx)
{
    void *result;

    if (!loader || !load_fn) {
        return NULL;
    }

    fm5_once_loader_lock(loader);

    if (loader->tried) {
        result = loader->handle;
        fm5_once_loader_unlock(loader);
        return result;
    }

    result = load_fn(ctx); /* carga pesada SEGURANDO o lock */
    loader->handle = result;
    loader->tried = 1;

    fm5_once_loader_unlock(loader);
    return result;
}

#endif /* FM5_ONCE_LOADER_H */
