/*
 * fm5_identity.h — Núcleo portátil de identidade multi-usuário do Azimuth
 *                  (Forza Motorsport 5 / Split-Screen Player 2).
 *
 * Este módulo NÃO depende de Windows nem do binário azimuth.exe: ele contém a
 * lógica determinística de associação Controller* -> User (Player 1 / Player 2)
 * e a decisão de quais usuários expor em UserStatics::get_Users.
 *
 * A camada Windows (fm5_hooks.c) apenas faz o plumbing de ABI (AddRef, alocação
 * e vtables do próprio azimuth.exe); as decisões de identidade vivem aqui e são
 * exercitadas por testes nativos reais (tests/test_fm5_identity.c e
 * tests/test_fm5_contract.c) sem mocks da lógica sob teste.
 *
 * Evidência de RE (azimuth.exe 1.0.4, PE32+ x86-64, image base 0x140000000):
 *   Controller::get_User             VA 0x14019a4c0 (RVA 0x19a4c0)
 *   UserStatics::get_Users           VA 0x1400424a0 (RVA 0x424a0)
 *   UserDisplayInfo::get_DisplayName VA 0x140041d10 (RVA 0x41d10)
 *   UserStatics::GetUserById         VA 0x140042580 (RVA 0x42580)
 *   UserStatics vtable[6] (count)    VA 0x140042480 (RVA 0x42480)
 *   User::get_Id                     VA 0x140041f70 (RVA 0x41f70)
 *
 * O build 1.0.4 pré-inicializa o Player 1 em UserStatics+0x18 e responde
 * GetUserById SOMENTE para id == 1 (`cmp $1,%edx; jne -> NULL`). Além disso
 * o slot 6 da vtable de UserStatics devolve o literal 1 e o slot 6 da vtable
 * de User (`get_Id`) devolve o literal 1 para QUALQUER instância. Este núcleo
 * fornece as decisões puras (sem Windows) para: mapear id de console (1-based)
 * para índice interno, decidir a contagem exposta e notificar observadores de
 * UserAdded exatamente uma vez por usuário virtual.
 */
#ifndef FM5_IDENTITY_H
#define FM5_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FM5_P2_MAX_USERS        8
/* TICKET-HARNESS-160: pool de nós de controle (js0, js1, js2, ...). O host da
 * Maiteux expõe 3 nós (dois uinput virtuais do remotegamepad + o controle USB
 * físico). O pool precisa acomodar todos eles sem recusar o controle físico. */
#define FM5_P2_MAX_CONTROLLERS  8
#define FM5_P2_TAG_MAX          32
#define FM5_P2_MAX_OBSERVERS    8

/* IDs de console do Xbox são 1-based: Player 1 == 1, Player 2 == 2, ...
 * É exatamente o valor usado por UserStatics::GetUserById no parâmetro edx. */
#define FM5_CONSOLE_ID_PLAYER1  1u

/* Identificadores de usuário exclusivos e estáveis. O Player 1 (nativo) usa
 * sempre FM5_USER_ID_PLAYER1; usuários virtuais usam FM5_USER_ID_VIRTUAL_BASE
 * + índice. Nunca são zero e nunca colidem entre si. */
#define FM5_USER_ID_PLAYER1       0x1000000000000001ULL
#define FM5_USER_ID_VIRTUAL_BASE  0x1000000000000100ULL

/*
 * TICKET-HARNESS-168 — identidade Guest do Player 2 virtual.
 *
 * O XUID nativo do Player 1 é 0x9000000000000 = 2533274790395904: é
 * exatamente a constante imediata de User::get_XboxUserId (RVA 0x042150), que
 * a converte para decimal antes de criar a HSTRING. Cada usuário virtual usa
 * base + índice, portanto o Player 2 responde 2533274790395905 — um XUID
 * distinto do Player 1, que evita a colisão de ConnectedStorageSpace e faz o
 * Forza entrar no fast-path de Convidado (Guest).
 *
 * O XboxUserHash segue a mesma lógica 1-based: Player 1 -> "1", Player 2 ->
 * "2". A camada Windows devolve esses valores como HSTRING pela vtable de
 * User (slots 14 e 15) e marca IsGuest = true (slot 10) para os virtuais.
 */
#define FM5_XBOX_USER_ID_BASE       2533274790395904ULL
#define FM5_XBOX_USER_ID_PLAYER1    FM5_XBOX_USER_ID_BASE
#define FM5_XBOX_USER_ID_PLAYER2    (FM5_XBOX_USER_ID_BASE + 1ULL)
#define FM5_XBOX_USER_HASH_PLAYER1  "1"
#define FM5_XBOX_USER_HASH_PLAYER2  "2"

/* TICKET-HARNESS-166 — bits do enum Windows.Xbox.Input.GamepadButtons
 * (Xbox One ERA), que é o layout efetivamente consumido pelo Forza 5 depois do
 * `shl $2` aplicado pelo Azimuth em Windows.Gaming.Input.GamepadButtons.
 * Duplicados aqui para o núcleo portátil não depender de fm5_buttons.h. */
#define FM5_IDENTITY_BUTTON_MENU 0x0004u /* Start */
#define FM5_IDENTITY_BUTTON_VIEW 0x0008u /* Back  */

/* Bit A do enum Xbox One ERA. É o botão que elege o Player 1 definitivo na
 * tela de abertura (splash), como no console Xbox. */
#define FM5_IDENTITY_BUTTON_A    0x0010u

/* Índice neutro / NÃO-ASSIGNADO.
 *
 * TICKET-HARNESS-163: nenhum controle nasce neutro — no boot todos nascem no
 * índice 0 (Player 1) para que o primeiro 'A' chegue ao jogo.
 * TICKET-HARNESS-171: depois do 'A' o secundário é PROMOVIDO direto ao índice
 * 1 (Player 2 virtual), então nenhum controle registrado fica neutro. O valor
 * continua sendo o sentinela de "sem índice de usuário" devolvido por
 * fm5_identity_index_for_controller em erro/pool esgotado e tratado por
 * fm5_resolve_get_user como "sem canal" (S_OK + NULL). */
#define FM5_INDEX_NEUTRAL        (-1)

/*
 * TICKET-HARNESS-163 — eventos da máquina de estados em cascata.
 *
 *   FASE 1 (boot/splash): TODO controle registrado responde índice 0 (Player 1)
 *     e Controller::get_User serve o usuário nativo. Nunca NULL no boot: no
 *     Durango um controle sem perfil silencia as entradas e o 'A' não funciona.
 *   FASE 2 (primeiro A): o primeiro controle a pressionar A torna-se o Player 1
 *     DEFINITIVO (índice 0). TICKET-HARNESS-171: os demais controles
 *     registrados são PROMOVIDOS na hora, em ordem de registro, para os
 *     índices 1, 2, 3, ... — o primeiro secundário já é o Player 2 VIRTUAL
 *     (índice 1) e passa a ser servido por Controller::get_User.
 *   FASE 3 (primeiro Start no lobby): o controle de índice 1 (ou qualquer
 *     secundário) que pressionar Start confirma o Player 2 DEFINITIVO
 *     (índice 1), tem o User virtual anunciado via UserAdded e empurra os
 *     demais para o índice 2 (Player 3).
 */
#define FM5_CASCADE_NONE        0
#define FM5_CASCADE_P1_ELECTED  1
#define FM5_CASCADE_P2_ELECTED  2

typedef struct fm5_user {
    int      index;                        /* 0 = Player 1; >=1 = virtual */
    uint64_t user_id;                      /* exclusivo e estável */
    char     gamer_tag[FM5_P2_TAG_MAX];    /* "Player 1", "Player 2", ... */
    void    *native_user;                  /* objeto WinRT User do exe (opaco) */
    void    *native_inner;                 /* UserDisplayInfo do exe (opaco) */
} fm5_user_t;

/* Observador de UserAdded: recebe o mesmo `sender` entregue ao notificador e o
 * índice do usuário recém-adicionado (>0). A camada Windows registra aqui o
 * despachante que invoca os delegates WinRT capturados da vtable[7]. */
typedef void (*fm5_user_added_observer)(void *observer_ctx, void *sender,
                                        int index);

typedef struct fm5_identity {
    void  *lock;                           /* SRWLOCK* (Win) / pthread_mutex_t* */
    int    max_users;
    int    user_count;                     /* usuários materializados (>=1) */
    int    controller_count;               /* controles registrados */
    void  *controller_keys[FM5_P2_MAX_CONTROLLERS];
    int    controller_user[FM5_P2_MAX_CONTROLLERS];
    fm5_user_t users[FM5_P2_MAX_USERS];
    /* TICKET-HARNESS-163 — travas da cascata. p1_locked: o primeiro A elegeu o
     * Player 1 definitivo. p2_locked: o primeiro Start no lobby elegeu o
     * Player 2 definitivo (e materializou o virtual). */
    int    p1_locked;
    int    p2_locked;
    int    observer_count;
    uint32_t notified_mask;                /* bit k = índice k já notificado */
    fm5_user_added_observer observers[FM5_P2_MAX_OBSERVERS];
    void  *observer_ctx[FM5_P2_MAX_OBSERVERS];
} fm5_identity_t;

/* Materializador injetado pela camada Windows: cria (uma única vez) o objeto
 * WinRT User nativo para o índice. Em teste, devolve um sentinela determinístico.
 * Retorna o ponteiro do usuário nativo ou NULL em falha. */
typedef void *(*fm5_user_materializer)(void *ctx, fm5_identity_t *id, int index);

typedef enum fm5_status {
    FM5_DELEGATE      = 0,   /* chamar a função original do exe */
    FM5_HANDLED       = 1,   /* *out já preenchido por este resolvedor */
    FM5_SERVED_NULL   = 2,   /* *out = NULL e S_OK (id sem usuário, como o exe) */
    FM5_E_POINTER     = -1,  /* out == NULL -> 0x80004003 */
    FM5_E_OUTOFMEMORY = -2   /* materialização falhou -> 0x8007000E */
} fm5_status_t;

/* Inicializa a identidade. p2_tag == NULL usa "Player 2". max_users é
 * limitado a [2, FM5_P2_MAX_USERS]. */
void fm5_identity_init(fm5_identity_t *id, int max_users, const char *p2_tag);
void fm5_identity_destroy(fm5_identity_t *id);

/* Retorna o índice de usuário associado ao controle.
 *
 * TICKET-HARNESS-163/171 — atribuição em CASCATA (modelo de console Xbox):
 *   - FASE 1: todo controle NOVO nasce no índice 0 (Player 1). Enquanto o
 *     primeiro A não chega, todos respondem como Player 1;
 *   - FASE 2: o A elege o P1 definitivo (índice 0) e o primeiro controle
 *     secundário registrado recebe o índice 1 (Player 2 virtual); os demais
 *     seguem em 2, 3, ...;
 *   - FASE 3: o Start do lobby confirma o índice 1 e empurra o resto para 2+.
 *   - Um controle que aparece DEPOIS da eleição nasce no primeiro índice de
 *     usuário livre a partir de 1 (índice 1 se a vaga do P2 ainda estiver
 *     vazia, senão 2, 3, ...).
 *
 * O pool de CONTROLES (FM5_P2_MAX_CONTROLLERS) é separado do pool de USUÁRIOS
 * (max_users); a função devolve -1 (FM5_INDEX_NEUTRAL) quando o pool de
 * controles esgota ou os argumentos são inválidos. Para distinguir os casos de
 * erro use fm5_identity_is_assigned_controller. */
int fm5_identity_index_for_controller(fm5_identity_t *id, void *controller);

/*
 * TICKET-HARNESS-168/171 — 1 se o controle está ASSIGNADO a um índice de
 * usuário (>= 0: 0 = Player 1, 1 = Player 2 virtual, 2+ = sem canal), 0 se não
 * está registrado ou os argumentos são inválidos. Não registra o controle
 * (efeito colateral zero).
 */
int fm5_identity_is_assigned_controller(fm5_identity_t *id, void *controller);

/*
 * TICKET-HARNESS-171 — snapshot dos controles ASSOCIADOS a um índice.
 *
 * Depois do primeiro 'A' o controle secundário já é o Player 2 VIRTUAL
 * (índice 1). É esse conjunto que precisa receber um evento
 * ControllerPairingChanged com o `User` virtual MATERIALIZADO: a rotina
 * 0x140675e10 do Forza aborta o evento quando `args->get_User()` é NULL
 * (`140675e3e: je 0x140675f67`), então o rebaixamento para NULL nunca surtiu
 * efeito dentro do jogo.
 *
 * Escreve até `cap` chaves de dispositivo em out[0..n-1] e devolve a
 * QUANTIDADE TOTAL de controles naquele índice (que pode ser maior que `cap`;
 * nesse caso só as primeiras `cap` chaves foram copiadas). `id`/`out` nulos,
 * `cap <= 0` ou `index < 0` devolvem 0.
 */
int fm5_identity_controllers_for_index(fm5_identity_t *id, int index,
                                       void **out, int cap);

/*
 * TICKET-HARNESS-171 — snapshot dos controles em índices >= 2 (Player 3+).
 *
 * Eles não têm canal de usuário (`Controller::get_User` -> S_OK + NULL), mas
 * continuam precisando do evento de pareamento com `User = NULL` para o jogo
 * descartar o `User` CACHEADO do Player 1. Mesmo contrato de contagem de
 * fm5_identity_controllers_for_index.
 */
int fm5_identity_demoted_controllers(fm5_identity_t *id, void **out, int cap);

/*
 * TICKET-HARNESS-163 — máquina de estados em cascata.
 *
 * Registra o controle (nascendo no índice 0) e aplica, atomicamente sob o lock:
 *   FASE 2 — `buttons` contém A e o Player 1 ainda não foi eleito:
 *     o controle vira Player 1 DEFINITIVO (índice 0); os demais controles do
 *     pool são PROMOVIDOS, em ordem de registro, para os índices 1, 2, 3, ...
 *     (TICKET-HARNESS-171: o primeiro secundário já é o Player 2 VIRTUAL).
 *     Evento FM5_CASCADE_P1_ELECTED, *out_index = 0.
 *   FASE 3 — `buttons` contém Start/Menu, o P1 já foi eleito e o P2 ainda não,
 *     e o controle NÃO é o dono do índice 0 (tipicamente o de índice 1):
 *     vira Player 2 DEFINITIVO (índice 1); demais controles passam ao índice 2.
 *     Evento FM5_CASCADE_P2_ELECTED, *out_index = 1.
 *   Caso contrário: FM5_CASCADE_NONE e *out_index = -1.
 *
 * `out_index` pode ser NULL. A prioridade é A sobre Start na mesma leitura.
 */
int fm5_identity_cascade_claim(fm5_identity_t *id, void *controller,
                               uint32_t buttons, int *out_index);

/* TICKET-HARNESS-163 — wrapper compatível: devolve o índice eleito (0 ou 1) em
 * uma transição, ou -1 quando nada muda (evento FM5_CASCADE_NONE). */
int fm5_identity_claim_player(fm5_identity_t *id, void *controller,
                              uint32_t buttons);

/* 1 se o Player 1 definitivo já foi eleito (primeiro A). */
int fm5_identity_p1_locked(fm5_identity_t *id);

/* 1 se o Player 2 definitivo já foi eleito (primeiro Start no lobby). */
int fm5_identity_p2_locked(fm5_identity_t *id);

/* 1 se o controle é o Player 1 DEFINITIVO (dono do índice 0 após a eleição).
 * Antes do primeiro A nenhum controle é "primário": todos são Player 1
 * provisórios. Controles desconhecidos e NULL devolvem 0. */
int fm5_identity_is_primary_controller(fm5_identity_t *id, void *controller);

/* 1 se o índice tem dono DEFINITIVO: índice 0 -> P1 eleito por A; índice 1 ->
 * P2 confirmado por Start (TICKET-HARNESS-171: o índice já é SERVIDO ao
 * secundário desde o A, mas o UserAdded só sai na confirmação); índices >= 2 ->
 * algum controle reatribuído pela cascata. Usado pela camada Windows para só
 * disparar UserAdded de um usuário efetivamente eleito; a exposição de 2 perfis
 * em get_Users no boot não conta. */
int fm5_identity_index_claimed(fm5_identity_t *id, int index);

/* Número de usuários ativos a expor em get_Users. TICKET-HARNESS-162: no boot
 * o console expõe 2 perfis (Player 1 nativo + Player 2 virtual), que é o que o
 * Forza exige para habilitar a segunda vaga do split-screen. */
int fm5_identity_active_users(fm5_identity_t *id);

const fm5_user_t *fm5_identity_user(fm5_identity_t *id, int index);
const fm5_user_t *fm5_identity_user_for_controller(fm5_identity_t *id,
                                                   void *controller);

/* Liga o objeto WinRT nativo ao índice. Retorna 0 em sucesso. */
int fm5_identity_bind_native(fm5_identity_t *id, int index,
                             void *native_user, void *native_inner);

/* 1 se `inner` é o UserDisplayInfo de um usuário virtual (Player 2+). */
int fm5_identity_is_virtual_inner(fm5_identity_t *id, const void *inner);

/* Snapshot dos usuários ativos; devolve a quantidade escrita em out[0..cap-1]. */
int fm5_identity_snapshot(fm5_identity_t *id, const fm5_user_t **out, int cap);

/*
 * Espelha Controller::get_User na cascata do TICKET-HARNESS-163, com o
 * isolamento estrito do Player 2 do TICKET-HARNESS-164:
 *   - índice 0 (Player 1, inclusive TODO controle antes do primeiro A) ->
 *     FM5_DELEGATE (o chamador executa o caminho nativo e devolve o User);
 *   - índice 1 ANTES do primeiro A (p1_locked == 0) -> FM5_DELEGATE (o
 *     controle provisório continua ouvido como Player 1 nativo; devolver NULL
 *     no boot silencia o controle no Durango);
 *   - índice 1 DEPOIS do P1 eleito (p1_locked == 1) -> materializa o User
 *     virtual do Player 2 e escreve *out (FM5_HANDLED). TICKET-HARNESS-171: o
 *     controle secundário é promovido a este índice no MESMO instante do 'A',
 *     então já responde como Player 2 virtual. NUNCA devolve FM5_DELEGATE: o
 *     controle secundário não pode herdar a identidade de P1 e comandar os
 *     menus do jogador 1;
 *   - índice NEUTRO (< 0, sentinela de erro/pool esgotado) -> FM5_SERVED_NULL
 *     (*out = NULL, S_OK), como o exe para um controle sem perfil;
 *   - índice >= 2 -> FM5_SERVED_NULL (*out = NULL), pois só P1 e P2 têm canal;
 *   - out == NULL  -> FM5_E_POINTER.
 */
fm5_status_t fm5_resolve_get_user(fm5_identity_t *id, void *controller,
                                  void **out, void *p1_native,
                                  fm5_user_materializer mat, void *ctx);

/*
 * Espelha UserStatics::get_Users (0x1400424a0):
 *   - 1 usuário ativo -> retorna 0 (delegar à função original, que devolve a
 *                        visão com o Player 1);
 *   - N >= 2 usuários -> preenche out_users[0..N-1] (out_users[0] == p1_native)
 *                        e retorna N para a camada Windows construir a IVectorView.
 */
int fm5_resolve_get_users(fm5_identity_t *id, void *p1_native,
                          void **out_users, int cap,
                          fm5_user_materializer mat, void *ctx);

/* ------------------------------------------------------------------------- */
/* UserStatics::GetUserById (§ hardcode `cmp $1,%edx; jne -> NULL`)           */
/* ------------------------------------------------------------------------- */

/* Converte o ID de console (1-based) para o índice interno (0-based).
 * Retorna -1 quando o ID é 0, está acima de max_users ou `id` é NULL. */
int fm5_identity_index_for_id(fm5_identity_t *id, uint32_t console_id);

/* Quantidade de usuários exposta ao jogo (espelha vtable[6]). Como o Player 2
 * é virtual e sempre existe na configuração de split-screen, o mínimo é 2
 * (respeitando max_users). Sem `id`, devolve 2. */
int fm5_identity_console_count(fm5_identity_t *id);

/* Índice cujo `native_user` é exatamente `native_user` (0 = Player 1 nativo).
 * -1 se o ponteiro não pertence a nenhum usuário conhecido. */
int fm5_identity_index_for_native_user(fm5_identity_t *id,
                                       const void *native_user);

/* ------------------------------------------------------------------------- */
/* TICKET-HARNESS-168 — identidade Guest na vtable de User                    */
/* ------------------------------------------------------------------------- */

/*
 * 1 se o índice é um usuário VIRTUAL/Guest (1 <= index < max_users), 0 para o
 * Player 1 nativo (índice 0), índices inválidos ou `id` NULL.
 *
 * Esse é o predicado que a camada Windows usa em User::get_IsGuest (slot 10 da
 * vtable 0x6c0b48). O Player 2 virtual é sempre um Convidado no console.
 */
int fm5_identity_is_guest(fm5_identity_t *id, int index);

/*
 * Escreve em `buf` o XUID decimal do índice e devolve `buf` (NUL-terminated).
 *
 *   índice 0 (Player 1) -> "2533274790395904" (FM5_XBOX_USER_ID_PLAYER1)
 *   índice 1 (Player 2) -> "2533274790395905" (FM5_XBOX_USER_ID_PLAYER2)
 *   índice N            -> "2533274790395904" + N
 *
 * Devolve NULL se `id`/`buf` forem inválidos, se o índice estiver fora de
 * [0, max_users) ou se `cap` não couber o número + terminador.
 */
const char *fm5_identity_xbox_user_id(fm5_identity_t *id, int index,
                                      char *buf, size_t cap);

/*
 * Escreve em `buf` o XboxUserHash decimal 1-based e devolve `buf`.
 *
 *   índice 0 (Player 1) -> "1" (FM5_XBOX_USER_HASH_PLAYER1)
 *   índice 1 (Player 2) -> "2" (FM5_XBOX_USER_HASH_PLAYER2)
 *   índice N            -> (N + 1)
 *
 * Devolve NULL nas mesmas condições de fm5_identity_xbox_user_id.
 */
const char *fm5_identity_xbox_user_hash(fm5_identity_t *id, int index,
                                        char *buf, size_t cap);

/*
 * Espelha UserStatics::GetUserById (RVA 0x42580):
 *   - out == NULL                   -> FM5_E_POINTER (0x80004003);
 *   - console_id == 1               -> FM5_DELEGATE (o hook serve o Player 1
 *                                      nativo lendo UserStatics+0x18);
 *   - 2 <= console_id <= max_users  -> materializa o índice console_id-1 e
 *                                      devolve FM5_HANDLED com *out preenchido;
 *   - qualquer outro console_id     -> FM5_SERVED_NULL (*out = NULL, S_OK),
 *                                      exatamente como o binário original.
 */
fm5_status_t fm5_resolve_get_user_by_id(fm5_identity_t *id, uint32_t console_id,
                                        void **out,
                                        fm5_user_materializer mat, void *ctx);

/* ------------------------------------------------------------------------- */
/* UserAdded observers (+0x20 do UserStatics)                                 */
/* ------------------------------------------------------------------------- */

/* Registra um observador de UserAdded. Retorna 0 em sucesso, -1 se a lista
 * estiver cheia ou os argumentos forem inválidos. */
int fm5_identity_add_observer(fm5_identity_t *id, fm5_user_added_observer cb,
                              void *ctx);

/*
 * Notifica os observadores do índice virtual `index` (>=1) com `sender` — no
 * máximo UMA vez por índice (idempotente). Retorna quantos observadores foram
 * chamados nesta notificação (0 se já notificado / índice do Player 1).
 */
int fm5_identity_notify_user_added(fm5_identity_t *id, void *sender, int index);

/* 1 se o índice já foi notificado via UserAdded. */
int fm5_identity_was_notified(fm5_identity_t *id, int index);

#ifdef __cplusplus
}
#endif

#endif /* FM5_IDENTITY_H */
