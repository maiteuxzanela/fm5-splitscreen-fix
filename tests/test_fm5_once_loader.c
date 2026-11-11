/*
 * test_fm5_once_loader.c — prova determinística do once-loader
 * (TICKET-HARNESS-167), sem mocks e sem rede.
 *
 * Reproduz a corrida real do Wine/Proton: a primeira thread gasta 25 ms
 * dentro do callback de carga (equivalente ao LoadLibraryA de
 * dinput8_real.dll) enquanto outras 3 chegam ao mesmo loader. A versão
 * antiga devolvia NULL para as retardatárias (tried=1, handle=NULL);
 * a correta faz todas aguardarem o lock e receberem o MESMO handle.
 *
 * Cobre:
 *   1) 4 threads concorrentes (pthread_barrier) -> load_calls == 1 e
 *      TODAS recebem o handle esperado (nenhuma NULL), bloqueando ~25 ms;
 *   2) chamada posterior reusa o cache (não recarrega);
 *   3) falha (callback NULL) também é cacheada: 4 threads, 1 chamada,
 *      todas recebem NULL de forma consistente;
 *   4) inicializadores estático (FM5_ONCE_LOADER_INIT) e dinâmico;
 *   5) argumentos NULL não derrubam o processo.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "fm5_once_loader.h"

#define N_THREADS 4
#define LOAD_NS   25000000L /* 25 ms — ~23 ms do LoadLibraryA real no Wine */
#define MIN_WAIT_MS 20.0   /* todas devem ter bloqueado quase toda a carga */

typedef struct shared {
    fm5_once_loader_t *loader;
    pthread_barrier_t *barrier;
    long load_ns;
    void *load_result;
    int load_calls;      /* incrementado atomicamente no callback */
} shared_t;

typedef struct worker_arg {
    shared_t *shared;
    void *out;
    double elapsed_ms;
} worker_arg_t;

typedef struct round_result {
    int load_calls;
    void *out[N_THREADS];
    double elapsed_ms[N_THREADS];
} round_result_t;

static int failures;

static void check(int cond, const char *msg)
{
    if (cond) {
        printf("PASS: %s\n", msg);
    } else {
        printf("FAIL: %s\n", msg);
        failures++;
    }
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void sleep_ns(long ns)
{
    struct timespec req;
    struct timespec rem;

    req.tv_sec = ns / 1000000000L;
    req.tv_nsec = ns % 1000000000L;
    while (nanosleep(&req, &rem) != 0 && errno == EINTR) {
        req = rem;
    }
}

/* Callback de carga: conta chamadas e dorme SEGURANDO o lock do loader. */
static void *load_cb(void *ctx)
{
    shared_t *s = (shared_t *)ctx;

    __atomic_add_fetch(&s->load_calls, 1, __ATOMIC_SEQ_CST);
    sleep_ns(s->load_ns);
    return s->load_result;
}

static void *worker_main(void *ctx)
{
    worker_arg_t *w = (worker_arg_t *)ctx;
    double t0;

    /* Barreira: as 4 threads entram em fm5_once_resolve juntas. */
    pthread_barrier_wait(w->shared->barrier);

    t0 = now_ms();
    w->out = fm5_once_resolve(w->shared->loader, load_cb, w->shared);
    w->elapsed_ms = now_ms() - t0;
    return NULL;
}

/* Dispara N_THREADS workers concorrentes no loader informado. */
static void run_round(fm5_once_loader_t *loader, void *load_result,
                      shared_t *shared, round_result_t *res)
{
    pthread_t threads[N_THREADS];
    worker_arg_t args[N_THREADS];
    pthread_barrier_t barrier;
    int i;

    memset(res, 0, sizeof(*res));
    memset(shared, 0, sizeof(*shared));
    shared->loader = loader;
    shared->barrier = &barrier;
    shared->load_ns = LOAD_NS;
    shared->load_result = load_result;

    if (pthread_barrier_init(&barrier, NULL, N_THREADS) != 0) {
        printf("FAIL: pthread_barrier_init\n");
        failures++;
        return;
    }

    for (i = 0; i < N_THREADS; i++) {
        args[i].shared = shared;
        args[i].out = NULL;
        args[i].elapsed_ms = 0.0;
        if (pthread_create(&threads[i], NULL, worker_main, &args[i]) != 0) {
            printf("FAIL: pthread_create[%d]\n", i);
            failures++;
            pthread_barrier_destroy(&barrier);
            return;
        }
    }

    for (i = 0; i < N_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_barrier_destroy(&barrier);

    res->load_calls = __atomic_load_n(&shared->load_calls, __ATOMIC_SEQ_CST);
    for (i = 0; i < N_THREADS; i++) {
        res->out[i] = args[i].out;
        res->elapsed_ms[i] = args[i].elapsed_ms;
    }
}

/* ------------------------------------------------------------------------- */

static void test_concurrent_success(void)
{
    static int sentinel;
    fm5_once_loader_t loader = FM5_ONCE_LOADER_INIT; /* inicializador estático */
    shared_t shared;
    round_result_t res;
    void *expected = (void *)&sentinel;
    int i;
    int all_expected = 1;
    int none_null = 1;
    int all_blocked = 1;
    void *again;

    run_round(&loader, expected, &shared, &res);

    check(res.load_calls == 1,
          "callback de load executado exatamente 1 vez (load_calls == 1)");

    for (i = 0; i < N_THREADS; i++) {
        if (res.out[i] != expected) {
            all_expected = 0;
        }
        if (res.out[i] == NULL) {
            none_null = 0;
        }
        if (res.elapsed_ms[i] < MIN_WAIT_MS) {
            all_blocked = 0;
            printf("      thread %d retornou em %.2f ms (< %.0f ms)\n",
                   i, res.elapsed_ms[i], MIN_WAIT_MS);
        }
    }
    check(none_null, "nenhuma das 4 threads concorrentes recebeu NULL");
    check(all_expected, "todas as 4 threads receberam o handle esperado");
    check(all_blocked,
          "todas as 4 threads aguardaram a carga (~25 ms), sem E_FAIL precoce");

    /* Chamada posterior: cache hit, nenhuma nova carga. */
    again = fm5_once_resolve(&loader, load_cb, &shared);
    check(again == expected, "chamada posterior devolve o handle cacheado");
    check(__atomic_load_n(&shared.load_calls, __ATOMIC_SEQ_CST) == 1,
          "chamada posterior nao repete o callback (load_calls continua 1)");
}

static void test_concurrent_failure_cached(void)
{
    fm5_once_loader_t loader;
    shared_t shared;
    round_result_t res;
    int i;
    int all_null = 1;

    fm5_once_loader_init(&loader); /* inicializador dinâmico */
    run_round(&loader, NULL, &shared, &res); /* callback "falha" -> NULL */

    check(res.load_calls == 1,
          "falha: callback NULL executado exatamente 1 vez (sem retry)");
    for (i = 0; i < N_THREADS; i++) {
        if (res.out[i] != NULL) {
            all_null = 0;
        }
    }
    check(all_null,
          "falha: todas as 4 threads recebem NULL de forma consistente");

    check(fm5_once_resolve(&loader, load_cb, &shared) == NULL,
          "falha: resultado negativo permanece cacheado");
    check(__atomic_load_n(&shared.load_calls, __ATOMIC_SEQ_CST) == 1,
          "falha: nenhuma recarga posterior (load_calls continua 1)");
}

static void test_null_arguments(void)
{
    fm5_once_loader_t loader = FM5_ONCE_LOADER_INIT;

    check(fm5_once_resolve(NULL, load_cb, NULL) == NULL,
          "loader NULL devolve NULL sem crash");
    check(fm5_once_resolve(&loader, NULL, NULL) == NULL,
          "callback NULL devolve NULL sem crash");
}

int main(void)
{
    printf("== test_fm5_once_loader (TICKET-HARNESS-167) ==\n");

    test_concurrent_success();
    test_concurrent_failure_cached();
    test_null_arguments();

    if (failures) {
        printf("RESULTADO: FALHA (%d assercoes)\n", failures);
        return 1;
    }
    printf("RESULTADO: OK — carregamento unico serializado e sem NULL "
           "transitorio\n");
    return 0;
}
