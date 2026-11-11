/*
 * fm5_identity.c — implementação portátil do núcleo de identidade (ver .h).
 *
 * Thread-safety: SRWLOCK no Windows (mingw) e pthread_mutex_t no POSIX.
 * Toda a lógica é determinística e não faz I/O.
 */
#include "fm5_identity.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <pthread.h>
#endif

/* ------------------------------------------------------------------------- */
/* Lock abstraction                                                          */
/* ------------------------------------------------------------------------- */
static int lock_create(void **out)
{
#ifdef _WIN32
    SRWLOCK *lk = (SRWLOCK *)calloc(1, sizeof(SRWLOCK));
    if (!lk) {
        return -1;
    }
    InitializeSRWLock(lk);
    *out = lk;
    return 0;
#else
    pthread_mutex_t *lk = (pthread_mutex_t *)calloc(1, sizeof(pthread_mutex_t));
    if (!lk) {
        return -1;
    }
    if (pthread_mutex_init(lk, NULL) != 0) {
        free(lk);
        return -1;
    }
    *out = lk;
    return 0;
#endif
}

static void lock_destroy(void *lock)
{
    if (!lock) {
        return;
    }
#ifdef _WIN32
    free(lock);
#else
    pthread_mutex_destroy((pthread_mutex_t *)lock);
    free(lock);
#endif
}

static void lock_acquire(void *lock)
{
    if (!lock) {
        return;
    }
#ifdef _WIN32
    AcquireSRWLockExclusive((SRWLOCK *)lock);
#else
    pthread_mutex_lock((pthread_mutex_t *)lock);
#endif
}

static void lock_release(void *lock)
{
    if (!lock) {
        return;
    }
#ifdef _WIN32
    ReleaseSRWLockExclusive((SRWLOCK *)lock);
#else
    pthread_mutex_unlock((pthread_mutex_t *)lock);
#endif
}

/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------- */
static void copy_tag(char *dst, size_t cap, const char *src)
{
    size_t n;
    if (!dst || cap == 0) {
        return;
    }
    if (!src) {
        src = "";
    }
    n = strlen(src);
    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void make_tag(char *dst, size_t cap, int index)
{
    if (index <= 0) {
        copy_tag(dst, cap, "Player 1");
        return;
    }
    /* "Player N" */
    {
        char buf[FM5_P2_TAG_MAX];
        char digits[12];
        size_t d = 0;
        int v = index + 1; /* índice 1 -> "Player 2" */
        size_t i;
        if (v < 0) {
            v = 0;
        }
        do {
            digits[d++] = (char)('0' + (v % 10));
            v /= 10;
        } while (v > 0 && d < sizeof(digits));
        i = 0;
        buf[i++] = 'P';
        buf[i++] = 'l';
        buf[i++] = 'a';
        buf[i++] = 'y';
        buf[i++] = 'e';
        buf[i++] = 'r';
        buf[i++] = ' ';
        while (d > 0 && i < sizeof(buf) - 1) {
            buf[i++] = digits[--d];
        }
        buf[i] = '\0';
        copy_tag(dst, cap, buf);
    }
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */
void fm5_identity_init(fm5_identity_t *id, int max_users, const char *p2_tag)
{
    int i;
    if (!id) {
        return;
    }
    memset(id, 0, sizeof(*id));

    if (max_users < 2) {
        max_users = 2;
    }
    if (max_users > FM5_P2_MAX_USERS) {
        max_users = FM5_P2_MAX_USERS;
    }
    id->max_users = max_users;
    /* TICKET-HARNESS-162/163: no boot o console expõe 2 perfis (Player 1 nativo
     * e Player 2 virtual). É o que o Forza exige para habilitar o split-screen.
     * TICKET-HARNESS-163: os CONTROLES nascem todos no índice 0 (Player 1); a
     * eleição de P1 (A) e P2 (Start) acontece em fm5_identity_cascade_claim. */
    id->user_count = (max_users < 2) ? max_users : 2;
    id->controller_count = 0;
    id->p1_locked = 0;
    id->p2_locked = 0;

    id->users[0].index = 0;
    id->users[0].user_id = FM5_USER_ID_PLAYER1;
    make_tag(id->users[0].gamer_tag, sizeof(id->users[0].gamer_tag), 0);
    id->users[0].native_user = NULL;
    id->users[0].native_inner = NULL;

    for (i = 1; i < FM5_P2_MAX_USERS; i++) {
        id->users[i].index = i;
        id->users[i].user_id = FM5_USER_ID_VIRTUAL_BASE + (uint64_t)i;
        make_tag(id->users[i].gamer_tag, sizeof(id->users[i].gamer_tag), i);
        id->users[i].native_user = NULL;
        id->users[i].native_inner = NULL;
    }

    if (p2_tag && p2_tag[0] != '\0') {
        /* A tag configurada vale para todos os virtuais (Player 2, 3, ...). */
        for (i = 1; i < FM5_P2_MAX_USERS; i++) {
            copy_tag(id->users[i].gamer_tag, sizeof(id->users[i].gamer_tag),
                     p2_tag);
        }
    }

    (void)lock_create(&id->lock);
}

void fm5_identity_destroy(fm5_identity_t *id)
{
    if (!id) {
        return;
    }
    lock_destroy(id->lock);
    id->lock = NULL;
}

/* ------------------------------------------------------------------------- */
/* Registro de controles (chamadas com o lock adquirido)                     */
/* ------------------------------------------------------------------------- */
static int find_controller_locked(fm5_identity_t *id, void *controller)
{
    int i;
    for (i = 0; i < id->controller_count; i++) {
        if (id->controller_keys[i] == controller) {
            return i;
        }
    }
    return -1;
}

/* Registra um controle novo no índice padrão da cascata: 0 (Player 1) antes do
 * primeiro A; o primeiro índice de usuário LIVRE a partir de 1 depois do P1
 * eleito (TICKET-HARNESS-171: o secundário nasce direto como Player 2 virtual,
 * e um controle que chega depois pega a vaga 1 se ela ainda estiver vazia).
 * Devolve o slot ou -1 se o pool de controles esgotou. */
static int first_free_user_index_locked(const fm5_identity_t *id)
{
    int candidate;
    int i;

    for (candidate = 1; candidate <= id->controller_count; candidate++) {
        int used = 0;
        for (i = 0; i < id->controller_count; i++) {
            if (id->controller_user[i] == candidate) {
                used = 1;
                break;
            }
        }
        if (!used) {
            return candidate;
        }
    }
    return id->controller_count;
}

static int default_index_locked(const fm5_identity_t *id)
{
    if (!id->p1_locked) {
        return 0;
    }
    return first_free_user_index_locked(id);
}

static int register_controller_locked(fm5_identity_t *id, void *controller)
{
    int slot;
    if (id->controller_count >= FM5_P2_MAX_CONTROLLERS) {
        return -1;
    }
    slot = id->controller_count++;
    id->controller_keys[slot] = controller;
    id->controller_user[slot] = default_index_locked(id);
    return slot;
}

static int controller_slot_locked(fm5_identity_t *id, void *controller)
{
    int slot = find_controller_locked(id, controller);
    if (slot < 0) {
        slot = register_controller_locked(id, controller);
    }
    return slot;
}

int fm5_identity_index_for_controller(fm5_identity_t *id, void *controller)
{
    int slot;
    int index;
    if (!id || !controller) {
        return -1;
    }
    lock_acquire(id->lock);
    slot = controller_slot_locked(id, controller);
    if (slot < 0) {
        lock_release(id->lock);
        return -1;
    }
    index = id->controller_user[slot];
    lock_release(id->lock);
    return index;
}

int fm5_identity_is_assigned_controller(fm5_identity_t *id, void *controller)
{
    int assigned = 0;
    int slot;
    if (!id || !controller) {
        return 0;
    }
    lock_acquire(id->lock);
    slot = find_controller_locked(id, controller);
    if (slot >= 0 && id->controller_user[slot] >= 0) {
        assigned = 1;
    }
    lock_release(id->lock);
    return assigned;
}

/* TICKET-HARNESS-171 — chaves dos controles associados a `index`. A camada
 * Windows usa o índice 1 (Player 2 virtual) para disparar
 * ControllerPairingChanged com um User VÁLIDO: o Forza aborta o evento quando
 * args->get_User() devolve NULL (140675e3e: je 0x140675f67). */
int fm5_identity_controllers_for_index(fm5_identity_t *id, int index,
                                       void **out, int cap)
{
    int total = 0;
    int i;

    if (!id || !out || cap <= 0 || index < 0) {
        return 0;
    }
    lock_acquire(id->lock);
    for (i = 0; i < id->controller_count; i++) {
        if (id->controller_user[i] != index) {
            continue;
        }
        if (total < cap) {
            out[total] = id->controller_keys[i];
        }
        total++;
    }
    lock_release(id->lock);
    return total;
}

/* TICKET-HARNESS-171 — chaves dos controles em índices >= 2 (Player 3+). Eles
 * não têm canal de usuário; recebem o evento de pareamento com User = NULL
 * para o jogo descartar o User CACHEADO do Player 1. */
int fm5_identity_demoted_controllers(fm5_identity_t *id, void **out, int cap)
{
    int total = 0;
    int i;

    if (!id || !out || cap <= 0) {
        return 0;
    }
    lock_acquire(id->lock);
    for (i = 0; i < id->controller_count; i++) {
        if (id->controller_user[i] < 2) {
            continue;
        }
        if (total < cap) {
            out[total] = id->controller_keys[i];
        }
        total++;
    }
    lock_release(id->lock);
    return total;
}

/* Slot de controle que já detém `index`, ou -1. Chamar com o lock adquirido. */
static int slot_for_index_locked(fm5_identity_t *id, int index)
{
    int i;
    for (i = 0; i < id->controller_count; i++) {
        if (id->controller_user[i] == index) {
            return i;
        }
    }
    return -1;
}

int fm5_identity_cascade_claim(fm5_identity_t *id, void *controller,
                               uint32_t buttons, int *out_index)
{
    int slot;
    int i;

    if (out_index) {
        *out_index = -1;
    }
    if (!id || !controller) {
        return FM5_CASCADE_NONE;
    }

    lock_acquire(id->lock);
    slot = controller_slot_locked(id, controller);
    if (slot < 0) {
        lock_release(id->lock);
        return FM5_CASCADE_NONE; /* pool de controles esgotado */
    }

    /*
     * FASE 2 — o PRIMEIRO A elege o Player 1 definitivo. No mesmo instante, os
     * demais controles registrados são PROMOVIDOS, em ordem de registro, para
     * os índices 1, 2, 3, ... — TICKET-HARNESS-171. O primeiro secundário já
     * nasce como Player 2 VIRTUAL (índice 1) e passa a ser servido por
     * Controller::get_User; é essa identidade VÁLIDA que o evento
     * ControllerPairingChanged entrega ao jogo (um User NULL faria o Forza
     * abortar em 140675e3e e o segundo controle continuaria sendo Player 1).
     */
    if ((buttons & FM5_IDENTITY_BUTTON_A) != 0 && !id->p1_locked) {
        int next = 1;
        id->p1_locked = 1;
        for (i = 0; i < id->controller_count; i++) {
            id->controller_user[i] = (i == slot) ? 0 : next++;
        }
        if (out_index) {
            *out_index = 0;
        }
        lock_release(id->lock);
        return FM5_CASCADE_P1_ELECTED;
    }

    /*
     * FASE 3 — no lobby, o PRIMEIRO Start de um controle secundário (que não é
     * o dono do índice 0, tipicamente o Player 2 virtual do índice 1) confirma
     * o Player 2 definitivo (índice 1). Os demais controles do pool são
     * empurrados para os índices 2, 3, ... para não colidirem com P1/P2. Só
     * existe P2 depois que P1 foi eleito.
     */
    if ((buttons & FM5_IDENTITY_BUTTON_MENU) != 0 && id->p1_locked &&
        !id->p2_locked) {
        int p1_slot = slot_for_index_locked(id, 0);
        if (p1_slot >= 0 && p1_slot != slot) {
            int next = 2;
            id->p2_locked = 1;
            for (i = 0; i < id->controller_count; i++) {
                if (i == p1_slot) {
                    id->controller_user[i] = 0; /* P1 definitivo */
                } else if (i == slot) {
                    id->controller_user[i] = 1; /* P2 definitivo */
                } else {
                    id->controller_user[i] = next++; /* demais -> 2, 3, ... */
                }
            }
            if (id->user_count < 2) {
                id->user_count = 2;
            }
            if (out_index) {
                *out_index = 1;
            }
            lock_release(id->lock);
            return FM5_CASCADE_P2_ELECTED;
        }
    }

    lock_release(id->lock);
    return FM5_CASCADE_NONE;
}

int fm5_identity_claim_player(fm5_identity_t *id, void *controller,
                              uint32_t buttons)
{
    int index = -1;
    int event = fm5_identity_cascade_claim(id, controller, buttons, &index);
    if (event == FM5_CASCADE_NONE) {
        return -1;
    }
    return index;
}

int fm5_identity_p1_locked(fm5_identity_t *id)
{
    int locked;
    if (!id) {
        return 0;
    }
    lock_acquire(id->lock);
    locked = id->p1_locked;
    lock_release(id->lock);
    return locked;
}

int fm5_identity_p2_locked(fm5_identity_t *id)
{
    int locked;
    if (!id) {
        return 0;
    }
    lock_acquire(id->lock);
    locked = id->p2_locked;
    lock_release(id->lock);
    return locked;
}

int fm5_identity_is_primary_controller(fm5_identity_t *id, void *controller)
{
    int primary = 0;
    int slot;
    if (!id || !controller) {
        return 0;
    }
    lock_acquire(id->lock);
    slot = find_controller_locked(id, controller);
    if (slot >= 0 && id->p1_locked && id->controller_user[slot] == 0) {
        primary = 1;
    }
    lock_release(id->lock);
    return primary;
}

int fm5_identity_index_claimed(fm5_identity_t *id, int index)
{
    int claimed = 0;
    if (!id || index < 0 || index >= FM5_P2_MAX_USERS) {
        return 0;
    }
    lock_acquire(id->lock);
    if (index == 0) {
        /* Só há P1 definitivo depois do primeiro A. */
        claimed = id->p1_locked;
    } else if (index == 1) {
        /* P2 provisório no boot NÃO conta: só o Start elege e notifica. */
        claimed = id->p2_locked;
    } else {
        claimed = (slot_for_index_locked(id, index) >= 0);
    }
    lock_release(id->lock);
    return claimed;
}

int fm5_identity_active_users(fm5_identity_t *id)
{
    int n;
    if (!id) {
        return 1;
    }
    lock_acquire(id->lock);
    n = id->user_count;
    if (n < 1) {
        n = 1;
    }
    if (n > id->max_users) {
        n = id->max_users;
    }
    lock_release(id->lock);
    return n;
}

const fm5_user_t *fm5_identity_user(fm5_identity_t *id, int index)
{
    if (!id || index < 0 || index >= FM5_P2_MAX_USERS) {
        return NULL;
    }
    return &id->users[index];
}

const fm5_user_t *fm5_identity_user_for_controller(fm5_identity_t *id,
                                                   void *controller)
{
    int index = fm5_identity_index_for_controller(id, controller);
    if (index < 0) {
        return NULL;
    }
    return fm5_identity_user(id, index);
}

int fm5_identity_bind_native(fm5_identity_t *id, int index,
                             void *native_user, void *native_inner)
{
    if (!id || index < 0 || index >= FM5_P2_MAX_USERS) {
        return -1;
    }
    lock_acquire(id->lock);
    id->users[index].native_user = native_user;
    id->users[index].native_inner = native_inner;
    lock_release(id->lock);
    return 0;
}

int fm5_identity_is_virtual_inner(fm5_identity_t *id, const void *inner)
{
    int i;
    int found = 0;
    if (!id || !inner) {
        return 0;
    }
    lock_acquire(id->lock);
    for (i = 1; i < FM5_P2_MAX_USERS; i++) {
        if (id->users[i].native_inner == inner) {
            found = 1;
            break;
        }
    }
    lock_release(id->lock);
    return found;
}

int fm5_identity_snapshot(fm5_identity_t *id, const fm5_user_t **out, int cap)
{
    int n;
    int i;
    if (!id || !out || cap <= 0) {
        return 0;
    }
    lock_acquire(id->lock);
    n = id->user_count;
    if (n < 1) {
        n = 1;
    }
    if (n > id->max_users) {
        n = id->max_users;
    }
    if (n > cap) {
        n = cap;
    }
    for (i = 0; i < n; i++) {
        out[i] = &id->users[i];
    }
    lock_release(id->lock);
    return n;
}

fm5_status_t fm5_resolve_get_user(fm5_identity_t *id, void *controller,
                                  void **out, void *p1_native,
                                  fm5_user_materializer mat, void *ctx)
{
    int index;
    void *user;

    (void)p1_native; /* o Player 1 é devolvido pela função original do exe */

    if (!out) {
        return FM5_E_POINTER;
    }

    index = fm5_identity_index_for_controller(id, controller);
    if (index == 0) {
        /* FASE 1/2 — Player 1 (todo controle antes do primeiro A e o dono do
         * índice 0 depois): o hook serve o User nativo do singleton. */
        return FM5_DELEGATE;
    }
    if (index == 1) {
        /* TICKET-HARNESS-164 — isolamento estrito do Player 2: uma vez que o
         * Player 1 foi eleito (p1_locked), o controle de índice 1 NUNCA mais
         * delega ao User nativo (que é o Player 1). Ele responde como Player 2
         * materializando o User virtual. Sem isso, o controle secundário
         * herdava a identidade de P1 e comandava os mesmos menus.
         *
         * Antes do primeiro A (p1_locked == 0) o controle provisório continua
         * delegando ao nativo para que o próprio A/Start chegue ao jogo. */
        if (!fm5_identity_p1_locked(id)) {
            return FM5_DELEGATE;
        }
        user = mat ? mat(ctx, id, index) : NULL;
        if (!user) {
            return FM5_E_OUTOFMEMORY;
        }
        *out = user;
        return FM5_HANDLED;
    }

    /*
     * TICKET-HARNESS-171 — sentinela NEUTRO (< 0: argumentos inválidos ou pool
     * de controles esgotado) e qualquer índice sem canal (>= 2, Player 3 em
     * diante): o exe original responde S_OK com *out = NULL.
     *
     * Esse NULL é intencional: um controle sem canal de usuário não pode
     * herdar a identidade do Player 1 (era o que acontecia quando voltávamos a
     * delegar). No Durango a ENTRADA continua fluindo — só Controller::get_User
     * devolve NULL, exatamente como um controle sem perfil no console. O
     * Player 2 não passa por aqui: o secundário é promovido ao índice 1 no
     * próprio 'A' e recebe o User virtual (FM5_HANDLED).
     */
    *out = NULL;
    return FM5_SERVED_NULL;
}

int fm5_identity_index_for_id(fm5_identity_t *id, uint32_t console_id)
{
    int max;
    if (!id || console_id == 0) {
        return -1;
    }
    lock_acquire(id->lock);
    max = id->max_users;
    lock_release(id->lock);
    if (console_id > (uint32_t)max) {
        return -1;
    }
    return (int)console_id - 1;
}

int fm5_identity_console_count(fm5_identity_t *id)
{
    int max;
    int count;
    if (!id) {
        return 2;
    }
    lock_acquire(id->lock);
    max = id->max_users;
    count = id->user_count;
    lock_release(id->lock);

    /* O Player 2 é virtual e sempre existe no split-screen: o jogo precisa ver
     * no mínimo 2 usuários para oferecer a segunda vaga. */
    if (count < 2) {
        count = 2;
    }
    if (count > max) {
        count = max;
    }
    if (count < 1) {
        count = 1;
    }
    return count;
}

int fm5_identity_index_for_native_user(fm5_identity_t *id,
                                       const void *native_user)
{
    int i;
    int found = -1;
    if (!id || !native_user) {
        return -1;
    }
    lock_acquire(id->lock);
    for (i = 0; i < FM5_P2_MAX_USERS; i++) {
        if (id->users[i].native_user == native_user) {
            found = i;
            break;
        }
    }
    lock_release(id->lock);
    return found;
}

fm5_status_t fm5_resolve_get_user_by_id(fm5_identity_t *id, uint32_t console_id,
                                        void **out,
                                        fm5_user_materializer mat, void *ctx)
{
    int index;
    void *user;

    if (!out || !id) {
        return FM5_E_POINTER;
    }

    if (console_id == FM5_CONSOLE_ID_PLAYER1) {
        /* Player 1 nativo: a camada Windows lê UserStatics+0x18. */
        return FM5_DELEGATE;
    }

    index = fm5_identity_index_for_id(id, console_id);
    if (index < 0) {
        /* Fora do range: o exe original grava NULL e devolve S_OK. */
        *out = NULL;
        return FM5_SERVED_NULL;
    }

    user = mat ? mat(ctx, id, index) : NULL;
    if (!user) {
        return FM5_E_OUTOFMEMORY;
    }
    *out = user;
    return FM5_HANDLED;
}

int fm5_identity_add_observer(fm5_identity_t *id, fm5_user_added_observer cb,
                              void *ctx)
{
    int slot;
    if (!id || !cb) {
        return -1;
    }
    lock_acquire(id->lock);
    if (id->observer_count >= FM5_P2_MAX_OBSERVERS) {
        lock_release(id->lock);
        return -1;
    }
    slot = id->observer_count++;
    id->observers[slot] = cb;
    id->observer_ctx[slot] = ctx;
    lock_release(id->lock);
    return 0;
}

int fm5_identity_was_notified(fm5_identity_t *id, int index)
{
    int yes;
    if (!id || index <= 0 || index >= FM5_P2_MAX_USERS) {
        return 0;
    }
    lock_acquire(id->lock);
    yes = (id->notified_mask & (1u << (unsigned)index)) != 0;
    lock_release(id->lock);
    return yes;
}

int fm5_identity_notify_user_added(fm5_identity_t *id, void *sender, int index)
{
    fm5_user_added_observer local_cb[FM5_P2_MAX_OBSERVERS];
    void *local_ctx[FM5_P2_MAX_OBSERVERS];
    int n;
    int i;

    if (!id || index <= 0 || index >= FM5_P2_MAX_USERS) {
        return 0;
    }
    lock_acquire(id->lock);
    if (id->notified_mask & (1u << (unsigned)index)) {
        lock_release(id->lock);
        return 0; /* idempotente: nunca dispara duas vezes o mesmo usuário */
    }
    id->notified_mask |= (1u << (unsigned)index);
    n = id->observer_count;
    if (n > FM5_P2_MAX_OBSERVERS) {
        n = FM5_P2_MAX_OBSERVERS;
    }
    /* Snapshot sob lock; os callbacks rodam FORA do lock (evita deadlock e
     * permite que o jogo reentre em get_Users durante o handler). */
    for (i = 0; i < n; i++) {
        local_cb[i] = id->observers[i];
        local_ctx[i] = id->observer_ctx[i];
    }
    lock_release(id->lock);

    for (i = 0; i < n; i++) {
        local_cb[i](local_ctx[i], sender, index);
    }
    return n;
}

int fm5_resolve_get_users(fm5_identity_t *id, void *p1_native,
                          void **out_users, int cap,
                          fm5_user_materializer mat, void *ctx)
{
    int n;
    int i;

    if (!id || !out_users || cap <= 0) {
        return 0;
    }

    n = fm5_identity_active_users(id);
    if (n <= 1) {
        return 0; /* delega: visão original com o Player 1 */
    }
    if (n > cap) {
        n = cap;
    }

    out_users[0] = p1_native;
    for (i = 1; i < n; i++) {
        out_users[i] = mat ? mat(ctx, id, i) : NULL;
        if (!out_users[i]) {
            /* Falha de materialização: mantém o Player 1 para não expor
             * entrada inválida; ainda assim o Player 2 já foi materializado
             * pelo caminho get_User quando o controle 2 pressionou A. */
            out_users[i] = p1_native;
        }
    }
    return n;
}

/* ------------------------------------------------------------------------- */
/* TICKET-HARNESS-168 — identidade Guest exposta pela vtable de User          */
/* ------------------------------------------------------------------------- */

/* Formata `value` em decimal ASCII. Devolve o número de dígitos escritos ou -1
 * quando o buffer não comporta o número + terminador NUL. */
static int u64_to_dec(uint64_t value, char *buf, size_t cap)
{
    char reversed[24];
    int digits = 0;
    int i;

    if (!buf || cap == 0) {
        return -1;
    }
    do {
        reversed[digits++] = (char)('0' + (int)(value % 10ULL));
        value /= 10ULL;
    } while (value != 0ULL && digits < (int)sizeof(reversed));

    if ((size_t)digits + 1 > cap) {
        return -1;
    }
    for (i = 0; i < digits; i++) {
        buf[i] = reversed[digits - 1 - i];
    }
    buf[digits] = '\0';
    return digits;
}

int fm5_identity_is_guest(fm5_identity_t *id, int index)
{
    int max_users;

    if (!id || index < 0) {
        return 0;
    }
    lock_acquire(id->lock);
    max_users = id->max_users;
    lock_release(id->lock);

    /* O Player 1 é o usuário nativo assinado da conta; todo índice virtual
     * (1..max_users-1) é um Convidado, como no console Xbox. */
    return (index >= 1 && index < max_users) ? 1 : 0;
}

const char *fm5_identity_xbox_user_id(fm5_identity_t *id, int index,
                                      char *buf, size_t cap)
{
    int max_users;
    uint64_t xuid;

    if (!id || !buf || index < 0) {
        return NULL;
    }
    lock_acquire(id->lock);
    max_users = id->max_users;
    lock_release(id->lock);
    if (index >= max_users) {
        return NULL;
    }

    /* XUID determinístico: base nativa + índice. Nunca colide entre P1 e P2,
     * o que evita o compartilhamento de ConnectedStorageSpace. */
    xuid = FM5_XBOX_USER_ID_BASE + (uint64_t)index;
    if (u64_to_dec(xuid, buf, cap) < 0) {
        return NULL;
    }
    return buf;
}

const char *fm5_identity_xbox_user_hash(fm5_identity_t *id, int index,
                                        char *buf, size_t cap)
{
    int max_users;

    if (!id || !buf || index < 0) {
        return NULL;
    }
    lock_acquire(id->lock);
    max_users = id->max_users;
    lock_release(id->lock);
    if (index >= max_users) {
        return NULL;
    }

    /* XboxUserHash é 1-based (Player 1 -> "1", Player 2 -> "2"). */
    if (u64_to_dec((uint64_t)index + 1ULL, buf, cap) < 0) {
        return NULL;
    }
    return buf;
}
