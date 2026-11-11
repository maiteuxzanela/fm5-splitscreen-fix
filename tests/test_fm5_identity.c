/*
 * test_fm5_identity.c — testes determinísticos REAIS do núcleo de identidade.
 *
 * Compila e roda no host Linux (gcc), exercitando a MESMA unidade de código
 * (src/fm5_identity.c) que a DLL usa no Windows. Sem mocks: o materializador
 * de usuário é um colaborador injetado (contrato público do núcleo) e aqui
 * devolve sentinelas determinísticos para provar a orquestração.
 *
 * TICKET-HARNESS-163 — máquina de estados em CASCATA:
 *   FASE 1 (boot):    todo controle nasce no índice 0 (Player 1); get_User
 *                     devolve DELEGATE (nativo) para TODOS — nunca NULL.
 *   FASE 2 (A):       o primeiro A elege o P1 definitivo e REBAIXA os demais
 *                     controles do pool para NÃO-ASSIGNADOS (TICKET 168).
 *   FASE 3 (Start):   o primeiro Start de um não-assignado elege o P2
 *                     definitivo, materializa o User virtual e move os demais
 *                     para o índice 2 (Player 3).
 *
 * TICKET-HARNESS-164: depois do P1 eleito, um controle secundário NUNCA mais
 * devolve DELEGATE (jamais herda a identidade do Player 1). Start/Back só
 * existem em 0x0200/0x0100; DPadUp (0x0040) e DPadDown (0x0080) permanecem
 * intactos.
 *
 * TICKET-HARNESS-168: o controle rebaixado responde S_OK + NULL (o "sem
 * perfil" do console) até pedir a vaga com Start; a identidade Guest é exposta
 * por IsGuest/XboxUserHash/XboxUserId (XUID base 2533274790395904 + índice).
 */
#include "fm5_identity.h"
/* Header puro (static inline) da recomposicao de botoes, para encadear a
 * codificacao CRUA de Start (0x0200 classico) ate a eleicao do Player 2. */
#include "../fm5-p2/src/fm5_buttons.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures;
static int g_checks;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_checks++;                                                          \
        if (!(cond)) {                                                       \
            g_failures++;                                                    \
            fprintf(stderr, "FALHA %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                    \
    } while (0)

#define CHECK_STR_EQ(a, b) CHECK(strcmp((a), (b)) == 0)

/* Materializador de teste: sentinela por índice; falha configurável. */
typedef struct mat_state {
    int calls;
    int fail_at; /* índice que deve falhar; -1 = nunca */
} mat_state_t;

static void *test_materializer(void *ctx, fm5_identity_t *id, int index)
{
    mat_state_t *st = (mat_state_t *)ctx;
    (void)id;
    st->calls++;
    if (st->fail_at == index) {
        return NULL;
    }
    return (void *)(uintptr_t)(0x1000u + (unsigned)index);
}

/* ------------------------------------------------------------------------- */
/* Boot: 2 perfis expostos, TODO controle nasce Player 1                      */
/* ------------------------------------------------------------------------- */
static void test_init_defaults(void)
{
    fm5_identity_t id;
    const fm5_user_t *u;

    fm5_identity_init(&id, 2, NULL);

    CHECK(id.max_users == 2);
    CHECK(fm5_identity_active_users(&id) == 2);
    CHECK(fm5_identity_console_count(&id) == 2);

    u = fm5_identity_user(&id, 0);
    CHECK(u != NULL);
    CHECK(u->index == 0);
    CHECK(u->user_id == FM5_USER_ID_PLAYER1);
    CHECK_STR_EQ(u->gamer_tag, "Player 1");
    CHECK(u->native_user == NULL);

    u = fm5_identity_user(&id, 1);
    CHECK(u != NULL);
    CHECK(u->index == 1);
    CHECK(u->user_id == FM5_USER_ID_VIRTUAL_BASE + 1);
    CHECK_STR_EQ(u->gamer_tag, "Player 2");

    CHECK(fm5_identity_user(&id, -1) == NULL);
    CHECK(fm5_identity_user(&id, FM5_P2_MAX_USERS) == NULL);
    CHECK(fm5_identity_p1_locked(&id) == 0);
    CHECK(fm5_identity_p2_locked(&id) == 0);

    fm5_identity_destroy(&id);
}

/* TICKET-HARNESS-163: FASE 1 — todos nascem no índice 0 (Player 1). */
static void test_controllers_born_player1(void)
{
    fm5_identity_t id;
    mat_state_t st = {0, -1};
    int a = 0x11, b = 0x22;
    void *out = (void *)0x1;

    fm5_identity_init(&id, 2, NULL);

    CHECK(fm5_identity_index_for_controller(&id, &a) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &b) == 0);
    /* Player 1 provisório não é "primário definitivo" antes do A. */
    CHECK(fm5_identity_is_primary_controller(&id, &a) == 0);
    CHECK(fm5_identity_is_primary_controller(&id, &b) == 0);
    /* Nenhum índice tem dono definitivo no boot. */
    CHECK(fm5_identity_index_claimed(&id, 0) == 0);
    CHECK(fm5_identity_index_claimed(&id, 1) == 0);

    /* CRÍTICO: get_User no boot DEVE delegar ao nativo para TODOS. Devolver
     * NULL (FM5_SERVED_NULL) silencia o controle no Durango e o A não chega. */
    out = (void *)0x1;
    CHECK(fm5_resolve_get_user(&id, &a, &out, NULL, test_materializer, &st) ==
          FM5_DELEGATE);
    out = (void *)0x1;
    CHECK(fm5_resolve_get_user(&id, &b, &out, NULL, test_materializer, &st) ==
          FM5_DELEGATE);
    CHECK(st.calls == 0);

    CHECK(fm5_identity_active_users(&id) == 2);
    CHECK(fm5_identity_console_count(&id) == 2);

    CHECK(fm5_identity_index_for_controller(&id, NULL) == -1);
    CHECK(fm5_identity_claim_player(NULL, &a, FM5_IDENTITY_BUTTON_A) == -1);
    CHECK(fm5_identity_claim_player(&id, NULL, FM5_IDENTITY_BUTTON_A) == -1);

    fm5_identity_destroy(&id);
}

/* ------------------------------------------------------------------------- */
/* FASE 2 (primeiro A) e FASE 3 (primeiro Start)                              */
/* ------------------------------------------------------------------------- */
/* TICKET-HARNESS-171 — FASE 2 promove o secundário a Player 2 VIRTUAL. */
static void test_cascade_a_elects_p1_and_promotes_secondary(void)
{
    fm5_identity_t id;
    mat_state_t st = {0, -1};
    int pad_a = 0x11;
    int pad_b = 0x22;
    int pad_c = 0x33;
    int index = -1;
    void *out = NULL;

    fm5_identity_init(&id, 3, NULL);
    /* Pool registrado no boot: todos Player 1. */
    CHECK(fm5_identity_index_for_controller(&id, &pad_a) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &pad_b) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &pad_c) == 0);

    /* Start antes de qualquer A não cria P2 (não existe P2 sem P1). */
    CHECK(fm5_identity_claim_player(&id, &pad_b,
                                    FM5_IDENTITY_BUTTON_MENU) == -1);
    CHECK(fm5_identity_index_for_controller(&id, &pad_b) == 0);
    CHECK(fm5_identity_p2_locked(&id) == 0);

    /* FASE 2 — primeiro A de pad_a. */
    CHECK(fm5_identity_cascade_claim(&id, &pad_a, FM5_IDENTITY_BUTTON_A,
                                     &index) == FM5_CASCADE_P1_ELECTED);
    CHECK(index == 0);
    CHECK(fm5_identity_index_for_controller(&id, &pad_a) == 0);
    /* TICKET-HARNESS-171: o secundário (primeiro registrado depois do P1) é
     * promovido NA HORA ao índice 1 (Player 2 virtual); o terceiro vai ao 2. */
    CHECK(fm5_identity_index_for_controller(&id, &pad_b) == 1);
    CHECK(fm5_identity_index_for_controller(&id, &pad_c) == 2);
    CHECK(fm5_identity_is_assigned_controller(&id, &pad_a) == 1);
    CHECK(fm5_identity_is_assigned_controller(&id, &pad_b) == 1);
    CHECK(fm5_identity_is_assigned_controller(&id, &pad_c) == 1);
    CHECK(fm5_identity_p1_locked(&id) == 1);
    CHECK(fm5_identity_p2_locked(&id) == 0);
    CHECK(fm5_identity_index_claimed(&id, 0) == 1);
    /* A vaga do P2 só é ANUNCIADA (UserAdded) no Start da FASE 3. */
    CHECK(fm5_identity_index_claimed(&id, 1) == 0);
    CHECK(fm5_identity_is_primary_controller(&id, &pad_a) == 1);
    CHECK(fm5_identity_is_primary_controller(&id, &pad_b) == 0);
    CHECK(fm5_identity_is_primary_controller(&id, &pad_c) == 0);

    /* O secundário JÁ responde como Player 2 virtual (FM5_HANDLED), sem
     * delegar ao User nativo do Player 1. */
    out = (void *)0x1;
    CHECK(fm5_resolve_get_user(&id, &pad_b, &out, NULL, test_materializer,
                               &st) == FM5_HANDLED);
    CHECK(out == (void *)(uintptr_t)0x1001);
    CHECK(st.calls == 1);

    /* Um SEGUNDO A (de um secundário) não rouba o P1 nem o reassina. */
    CHECK(fm5_identity_claim_player(&id, &pad_b,
                                    FM5_IDENTITY_BUTTON_A) == -1);
    CHECK(fm5_identity_index_for_controller(&id, &pad_b) == 1);

    /* FASE 3 — Start do P2 confirma a vaga e não muda os índices. */
    CHECK(fm5_identity_cascade_claim(&id, &pad_b, FM5_IDENTITY_BUTTON_MENU,
                                     &index) == FM5_CASCADE_P2_ELECTED);
    CHECK(index == 1);
    CHECK(fm5_identity_index_for_controller(&id, &pad_b) == 1);
    CHECK(fm5_identity_index_for_controller(&id, &pad_c) == 2);
    CHECK(fm5_identity_index_for_controller(&id, &pad_a) == 0);
    CHECK(fm5_identity_p2_locked(&id) == 1);
    CHECK(fm5_identity_index_claimed(&id, 1) == 1);

    /* Start de outro secundário depois do P2 eleito não muda nada. */
    CHECK(fm5_identity_claim_player(&id, &pad_c,
                                    FM5_IDENTITY_BUTTON_MENU) == -1);
    CHECK(fm5_identity_index_for_controller(&id, &pad_c) == 2);

    CHECK(fm5_identity_console_count(&id) == 2);

    fm5_identity_destroy(&id);
}

static void test_cascade_three_node_get_user(void)
{
    fm5_identity_t id;
    mat_state_t st = {0, -1};
    int js0 = 0, js1 = 0, js2 = 0;
    void *out = NULL;

    fm5_identity_init(&id, 2, NULL);
    CHECK(fm5_identity_index_for_controller(&id, &js0) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &js1) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &js2) == 0);

    /* Boot: TODOS delegam ao User nativo (nunca NULL). */
    CHECK(fm5_resolve_get_user(&id, &js2, &out, NULL, test_materializer, &st) ==
          FM5_DELEGATE);
    CHECK(fm5_resolve_get_user(&id, &js0, &out, NULL, test_materializer, &st) ==
          FM5_DELEGATE);
    CHECK(st.calls == 0);

    /* A no controle físico js2 -> P1 definitivo; js0 (primeiro registrado
     * secundário) -> Player 2 virtual (índice 1) e js1 -> índice 2. */
    CHECK(fm5_identity_claim_player(&id, &js2, FM5_IDENTITY_BUTTON_A) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &js0) == 1);
    CHECK(fm5_identity_index_for_controller(&id, &js1) == 2);
    /* TICKET-HARNESS-171: o secundário já é o Player 2 virtual — materializa e
     * devolve FM5_HANDLED, nunca o User nativo do P1. */
    out = (void *)0x1;
    CHECK(fm5_resolve_get_user(&id, &js0, &out, NULL, test_materializer, &st) ==
          FM5_HANDLED);
    CHECK(out == (void *)(uintptr_t)0x1001);
    CHECK(st.calls == 1);
    /* js1 (índice 2) não tem canal de usuário: S_OK + NULL. */
    out = (void *)0x1;
    CHECK(fm5_resolve_get_user(&id, &js1, &out, NULL, test_materializer, &st) ==
          FM5_SERVED_NULL);
    CHECK(out == NULL);

    /* Start em js0 no lobby -> P2 definitivo (mesmo índice 1). */
    CHECK(fm5_identity_claim_player(&id, &js0,
                                    FM5_IDENTITY_BUTTON_MENU) == 1);
    out = NULL;
    CHECK(fm5_resolve_get_user(&id, &js2, &out, NULL, test_materializer, &st) ==
          FM5_DELEGATE);
    CHECK(out == NULL);
    CHECK(fm5_resolve_get_user(&id, &js0, &out, NULL, test_materializer, &st) ==
          FM5_HANDLED);
    CHECK(out == (void *)(uintptr_t)0x1001);

    fm5_identity_destroy(&id);
}

static void test_cascade_idempotent(void)
{
    fm5_identity_t id;
    int pad_a = 1, pad_b = 2;

    fm5_identity_init(&id, 2, NULL);
    CHECK(fm5_identity_index_for_controller(&id, &pad_a) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &pad_b) == 0);

    CHECK(fm5_identity_claim_player(&id, &pad_a, FM5_IDENTITY_BUTTON_A) == 0);
    /* Repetir A não gera nova transição nem troca de vaga. */
    CHECK(fm5_identity_claim_player(&id, &pad_a, FM5_IDENTITY_BUTTON_A) == -1);
    /* P1 pressionando Start continua P1 (não vira P2). */
    CHECK(fm5_identity_claim_player(&id, &pad_a,
                                    FM5_IDENTITY_BUTTON_MENU) == -1);
    CHECK(fm5_identity_index_for_controller(&id, &pad_a) == 0);

    CHECK(fm5_identity_claim_player(&id, &pad_b,
                                    FM5_IDENTITY_BUTTON_MENU) == 1);
    /* Repetir Start não reeleger; A do P2 não o promove nem o rebaixa. */
    CHECK(fm5_identity_claim_player(&id, &pad_b,
                                    FM5_IDENTITY_BUTTON_MENU) == -1);
    CHECK(fm5_identity_claim_player(&id, &pad_b,
                                    FM5_IDENTITY_BUTTON_A) == -1);
    CHECK(fm5_identity_index_for_controller(&id, &pad_b) == 1);

    fm5_identity_destroy(&id);
}

static void test_cascade_ignores_other_buttons(void)
{
    fm5_identity_t id;
    int a = 1;

    fm5_identity_init(&id, 2, NULL);
    CHECK(fm5_identity_index_for_controller(&id, &a) == 0);

    /* B/X/Y/View sem A ou Start não elegem ninguém. TICKET-HARNESS-166: bits
     * do enum Xbox One ERA (B=0x0020, X=0x0040, Y=0x0080, View=0x0008,
     * DPadUp=0x0100, DPadDown=0x0200). */
    CHECK(fm5_identity_claim_player(&id, &a, 0x0020u) == -1);
    CHECK(fm5_identity_claim_player(&id, &a, 0x0040u) == -1);
    CHECK(fm5_identity_claim_player(&id, &a, 0x0080u) == -1);
    CHECK(fm5_identity_claim_player(&id, &a,
                                    FM5_IDENTITY_BUTTON_VIEW) == -1);
    CHECK(fm5_identity_claim_player(&id, &a, 0x0100u) == -1);
    CHECK(fm5_identity_claim_player(&id, &a, 0x0200u) == -1);
    CHECK(fm5_identity_index_for_controller(&id, &a) == 0);
    CHECK(fm5_identity_p1_locked(&id) == 0);

    /* A + Start na mesma leitura: A tem prioridade -> P1. */
    CHECK(fm5_identity_claim_player(&id, &a,
                                    FM5_IDENTITY_BUTTON_A |
                                        FM5_IDENTITY_BUTTON_MENU) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &a) == 0);
    CHECK(fm5_identity_p1_locked(&id) == 1);
    CHECK(fm5_identity_p2_locked(&id) == 0);

    fm5_identity_destroy(&id);
}

/* Controle que aparece DEPOIS das eleições nasce no primeiro índice LIVRE. */
static void test_cascade_late_controller_registration(void)
{
    fm5_identity_t id;
    int c1 = 1, late1 = 2, late2 = 3;

    fm5_identity_init(&id, 3, NULL);
    CHECK(fm5_identity_index_for_controller(&id, &c1) == 0);
    CHECK(fm5_identity_claim_player(&id, &c1, FM5_IDENTITY_BUTTON_A) == 0);

    /* TICKET-HARNESS-171: depois do P1 eleito o controle novo ocupa a vaga do
     * Player 2 virtual (índice 1), que está livre. */
    CHECK(fm5_identity_index_for_controller(&id, &late1) == 1);
    CHECK(fm5_identity_is_assigned_controller(&id, &late1) == 1);

    CHECK(fm5_identity_claim_player(&id, &late1,
                                    FM5_IDENTITY_BUTTON_MENU) == 1);
    /* Depois do P2 eleito, controle novo entra no índice 2 (Player 3). */
    CHECK(fm5_identity_index_for_controller(&id, &late2) == 2);

    fm5_identity_destroy(&id);
}

static void test_controller_pool_limit(void)
{
    fm5_identity_t id;
    int c[FM5_P2_MAX_CONTROLLERS + 1];
    int i;

    fm5_identity_init(&id, 2, NULL);
    for (i = 0; i < FM5_P2_MAX_CONTROLLERS; i++) {
        CHECK(fm5_identity_index_for_controller(&id, &c[i]) == 0);
    }
    CHECK(fm5_identity_index_for_controller(&id, &c[FM5_P2_MAX_CONTROLLERS]) ==
          -1);

    fm5_identity_destroy(&id);
}

static void test_primary_helper(void)
{
    fm5_identity_t id;
    int a = 7, b = 8;

    fm5_identity_init(&id, 2, NULL);
    CHECK(fm5_identity_is_primary_controller(&id, &a) == 0);
    (void)fm5_identity_index_for_controller(&id, &a);
    (void)fm5_identity_index_for_controller(&id, &b);
    CHECK(fm5_identity_is_primary_controller(&id, &a) == 0);

    CHECK(fm5_identity_claim_player(&id, &a, FM5_IDENTITY_BUTTON_A) == 0);
    CHECK(fm5_identity_is_primary_controller(&id, &a) == 1);
    CHECK(fm5_identity_is_primary_controller(&id, &b) == 0);
    CHECK(fm5_identity_is_primary_controller(&id, NULL) == 0);
    CHECK(fm5_identity_is_primary_controller(NULL, &a) == 0);

    fm5_identity_destroy(&id);
}

static void test_lock_helpers(void)
{
    int c = 0;
    CHECK(fm5_identity_p1_locked(NULL) == 0);
    CHECK(fm5_identity_p2_locked(NULL) == 0);

    {
        fm5_identity_t id;
        fm5_identity_init(&id, 2, NULL);
        CHECK(fm5_identity_p1_locked(&id) == 0);
        CHECK(fm5_identity_p2_locked(&id) == 0);
        CHECK(fm5_identity_claim_player(&id, &c, FM5_IDENTITY_BUTTON_A) == 0);
        CHECK(fm5_identity_p1_locked(&id) == 1);
        CHECK(fm5_identity_p2_locked(&id) == 0);
        fm5_identity_destroy(&id);
    }
}

static void test_max_users_clamped(void)
{
    fm5_identity_t id;
    fm5_identity_init(&id, 1, NULL);
    CHECK(id.max_users == 2); /* mínimo 2 */
    fm5_identity_destroy(&id);

    fm5_identity_init(&id, 999, NULL);
    CHECK(id.max_users == FM5_P2_MAX_USERS); /* máximo da constante */
    fm5_identity_destroy(&id);
}

static void test_custom_tag(void)
{
    fm5_identity_t id;
    const fm5_user_t *u;

    fm5_identity_init(&id, 3, "Jogador 2");
    u = fm5_identity_user(&id, 1);
    CHECK(u != NULL);
    CHECK_STR_EQ(u->gamer_tag, "Jogador 2");
    /* Player 1 nunca é renomeado. */
    CHECK_STR_EQ(fm5_identity_user(&id, 0)->gamer_tag, "Player 1");

    fm5_identity_destroy(&id);
}

/* ------------------------------------------------------------------------- */
/* Controller::get_User                                                       */
/* ------------------------------------------------------------------------- */
static void test_resolve_get_user(void)
{
    fm5_identity_t id;
    mat_state_t st = {0, -1};
    int c1 = 0x1, c2 = 0x2;
    void *out = NULL;
    fm5_status_t s;

    fm5_identity_init(&id, 3, NULL);

    /* out == NULL -> E_POINTER, sem tocar o materializador. */
    s = fm5_resolve_get_user(&id, &c1, NULL, NULL, test_materializer, &st);
    CHECK(s == FM5_E_POINTER);
    CHECK(st.calls == 0);

    /* Boot/FASE 1 -> DELEGATE (nativo) para todos, sem materializar. */
    s = fm5_resolve_get_user(&id, &c1, &out, NULL, test_materializer, &st);
    CHECK(s == FM5_DELEGATE);
    CHECK(st.calls == 0);

    /* A elege P1 -> caminho nativo (delegate). */
    CHECK(fm5_identity_claim_player(&id, &c1, FM5_IDENTITY_BUTTON_A) == 0);
    out = NULL;
    s = fm5_resolve_get_user(&id, &c1, &out, NULL, test_materializer, &st);
    CHECK(s == FM5_DELEGATE);
    CHECK(st.calls == 0);

    /* TICKET-HARNESS-171: depois do P1 eleito o controle secundário já é o
     * Player 2 VIRTUAL — get_User materializa o User do índice 1 (nunca o User
     * nativo do Player 1). */
    out = (void *)0x1;
    s = fm5_resolve_get_user(&id, &c2, &out, NULL, test_materializer, &st);
    CHECK(s == FM5_HANDLED);
    CHECK(out == (void *)(uintptr_t)0x1001);
    CHECK(fm5_identity_index_for_controller(&id, &c2) == 1);
    CHECK(fm5_identity_is_assigned_controller(&id, &c2) == 1);
    CHECK(st.calls == 1);

    /* Start confirma a vaga; a materialização continua servindo o virtual. */
    CHECK(fm5_identity_claim_player(&id, &c2, FM5_IDENTITY_BUTTON_MENU) == 1);
    out = NULL;
    s = fm5_resolve_get_user(&id, &c2, &out, NULL, test_materializer, &st);
    CHECK(s == FM5_HANDLED);
    CHECK(out == (void *)(uintptr_t)0x1001);
    CHECK(st.calls == 2);

    /* Reutilização do mesmo índice continua entregando o sentinela. */
    out = NULL;
    s = fm5_resolve_get_user(&id, &c2, &out, NULL, test_materializer, &st);
    CHECK(s == FM5_HANDLED);
    CHECK(out == (void *)(uintptr_t)0x1001);

    fm5_identity_destroy(&id);
}

static void test_resolve_get_user_index2_is_null(void)
{
    fm5_identity_t id;
    mat_state_t st = {0, -1};
    int p1 = 1, p2 = 2, p3 = 3;
    void *out = (void *)0x1;

    fm5_identity_init(&id, 3, NULL);
    (void)fm5_identity_index_for_controller(&id, &p1);
    (void)fm5_identity_index_for_controller(&id, &p2);
    (void)fm5_identity_index_for_controller(&id, &p3);
    CHECK(fm5_identity_claim_player(&id, &p1, FM5_IDENTITY_BUTTON_A) == 0);
    CHECK(fm5_identity_claim_player(&id, &p2,
                                    FM5_IDENTITY_BUTTON_MENU) == 1);
    CHECK(fm5_identity_index_for_controller(&id, &p3) == 2);

    out = (void *)0x1;
    CHECK(fm5_resolve_get_user(&id, &p3, &out, NULL, test_materializer, &st) ==
          FM5_SERVED_NULL);
    CHECK(out == NULL);

    fm5_identity_destroy(&id);
}

static void test_resolve_get_user_oom(void)
{
    fm5_identity_t id;
    mat_state_t st = {0, 1};
    int c1 = 0x1, c2 = 0x2;
    void *out = NULL;

    fm5_identity_init(&id, 3, NULL);
    CHECK(fm5_identity_claim_player(&id, &c1, FM5_IDENTITY_BUTTON_A) == 0);
    CHECK(fm5_identity_claim_player(&id, &c2, FM5_IDENTITY_BUTTON_MENU) == 1);
    out = NULL;
    CHECK(fm5_resolve_get_user(&id, &c2, &out, NULL, test_materializer, &st) ==
          FM5_E_OUTOFMEMORY);
    CHECK(out == NULL);

    fm5_identity_destroy(&id);
}

/* ------------------------------------------------------------------------- */
/* UserStatics::get_Users — 2 perfis desde o boot                             */
/* ------------------------------------------------------------------------- */
static void test_resolve_get_users(void)
{
    fm5_identity_t id;
    mat_state_t st = {0, -1};
    int p1 = 0xAAAA;
    void *users[FM5_P2_MAX_USERS];
    int n;

    fm5_identity_init(&id, 4, NULL);

    /* No boot já expõe 2 usuários (P1 nativo + P2 virtual). */
    n = fm5_resolve_get_users(&id, &p1, users, FM5_P2_MAX_USERS,
                              test_materializer, &st);
    CHECK(n == 2);
    CHECK(users[0] == &p1);
    CHECK(users[1] == (void *)(uintptr_t)0x1001);
    CHECK(st.calls == 1);

    /* Cap menor que a contagem: nunca escreve além do cap. */
    n = fm5_resolve_get_users(&id, &p1, users, 1, test_materializer, &st);
    CHECK(n == 1);
    CHECK(users[0] == &p1);

    fm5_identity_destroy(&id);
}

/* ------------------------------------------------------------------------- */
/* Bind / snapshot / tags                                                     */
/* ------------------------------------------------------------------------- */
static void test_bind_and_virtual_inner(void)
{
    fm5_identity_t id;
    void *inner1 = (void *)0x5001;
    void *inner2 = (void *)0x5002;

    fm5_identity_init(&id, 3, NULL);

    CHECK(fm5_identity_is_virtual_inner(&id, inner1) == 0);
    CHECK(fm5_identity_bind_native(&id, 1, (void *)0x4001, inner1) == 0);
    CHECK(fm5_identity_is_virtual_inner(&id, inner1) == 1);
    CHECK(fm5_identity_is_virtual_inner(&id, inner2) == 0);
    CHECK(fm5_identity_is_virtual_inner(&id, NULL) == 0);

    /* Bind no Player 1 não o torna virtual. */
    CHECK(fm5_identity_bind_native(&id, 0, (void *)0x4000, inner2) == 0);
    CHECK(fm5_identity_is_virtual_inner(&id, inner2) == 0);

    CHECK(fm5_identity_user(&id, 1)->native_user == (void *)0x4001);
    CHECK(fm5_identity_user(&id, 1)->native_inner == inner1);

    CHECK(fm5_identity_bind_native(&id, -1, inner1, inner1) == -1);
    CHECK(fm5_identity_bind_native(&id, FM5_P2_MAX_USERS, inner1, inner1) == -1);

    fm5_identity_destroy(&id);
}

static void test_snapshot_unique_ids(void)
{
    fm5_identity_t id;
    const fm5_user_t *snap[FM5_P2_MAX_USERS];
    int n, i, j;

    fm5_identity_init(&id, FM5_P2_MAX_USERS, NULL);
    /* Boot: 2 perfis expostos e distintos. */
    n = fm5_identity_snapshot(&id, snap, FM5_P2_MAX_USERS);
    CHECK(n == 2);
    CHECK(snap[0]->index == 0);
    CHECK(snap[1]->index == 1);
    CHECK(snap[0]->user_id != snap[1]->user_id);

    /* A cascata não cria usuários além de P1/P2: com 8 controles, só P1 e P2
     * têm canal de usuário (o resto vai para o índice 2 e get_User dá NULL). */
    {
        int keys[FM5_P2_MAX_USERS];
        for (i = 0; i < FM5_P2_MAX_USERS; i++) {
            keys[i] = 0x7000 + i;
            CHECK(fm5_identity_index_for_controller(&id, &keys[i]) == 0);
        }
        CHECK(fm5_identity_claim_player(&id, &keys[0],
                                        FM5_IDENTITY_BUTTON_A) == 0);
        /* TICKET-HARNESS-171: o secundário nasce no índice 1 e os demais em
         * 2, 3, ... (ordem de registro). */
        for (i = 1; i < FM5_P2_MAX_USERS; i++) {
            CHECK(fm5_identity_index_for_controller(&id, &keys[i]) == i);
        }
        CHECK(fm5_identity_claim_player(&id, &keys[1],
                                        FM5_IDENTITY_BUTTON_MENU) == 1);
        for (i = 2; i < FM5_P2_MAX_USERS; i++) {
            CHECK(fm5_identity_index_for_controller(&id, &keys[i]) == i);
        }
    }
    n = fm5_identity_snapshot(&id, snap, FM5_P2_MAX_USERS);
    CHECK(n == 2);
    for (i = 0; i < n; i++) {
        CHECK(snap[i]->index == i);
        CHECK(snap[i]->user_id != 0);
        for (j = i + 1; j < n; j++) {
            CHECK(snap[i]->user_id != snap[j]->user_id);
        }
    }

    /* Cap 2 devolve só 2. */
    CHECK(fm5_identity_snapshot(&id, snap, 2) == 2);

    fm5_identity_destroy(&id);
}

static void test_user_for_controller(void)
{
    fm5_identity_t id;
    int c1 = 0x1, c2 = 0x2;

    fm5_identity_init(&id, 3, NULL);
    /* FASE 1: todo controle responde pelo Player 1 (índice 0). */
    CHECK(fm5_identity_user_for_controller(&id, &c1)->index == 0);
    CHECK(fm5_identity_user_for_controller(&id, &c2)->index == 0);
    CHECK(fm5_identity_claim_player(&id, &c1, FM5_IDENTITY_BUTTON_A) == 0);
    CHECK(fm5_identity_user_for_controller(&id, &c1)->index == 0);
    /* TICKET-HARNESS-171: o secundário é promovido a Player 2 virtual no
     * próprio 'A' e passa a resolver o usuário do índice 1. */
    CHECK(fm5_identity_user_for_controller(&id, &c2)->index == 1);
    CHECK(fm5_identity_claim_player(&id, &c2, FM5_IDENTITY_BUTTON_MENU) == 1);
    CHECK(fm5_identity_user_for_controller(&id, &c2)->index == 1);
    CHECK(fm5_identity_user_for_controller(&id, &c1)->index == 0);
    CHECK(fm5_identity_user_for_controller(&id, NULL) == NULL);
    fm5_identity_destroy(&id);
}

/* ------------------------------------------------------------------------- */
/* TICKET-HARNESS-159: GetUserById, contagem e UserAdded                      */
/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */
/* TICKET-HARNESS-168 — identidade Guest (IsGuest / XboxUserHash / XboxUserId) */
/* ------------------------------------------------------------------------- */
static void test_guest_identity(void)
{
    fm5_identity_t id;
    char buf[32];

    fm5_identity_init(&id, 4, NULL);

    /* O Player 1 é o usuário nativo assinado; todo índice virtual é Guest. */
    CHECK(fm5_identity_is_guest(&id, 0) == 0);
    CHECK(fm5_identity_is_guest(&id, 1) == 1);
    CHECK(fm5_identity_is_guest(&id, 2) == 1);
    CHECK(fm5_identity_is_guest(&id, 3) == 1);

    /* Índices fora de [0, max_users) e id incompatível nunca são Guest. */
    CHECK(fm5_identity_is_guest(&id, -1) == 0);
    CHECK(fm5_identity_is_guest(&id, -7) == 0);
    CHECK(fm5_identity_is_guest(&id, 4) == 0);   /* == max_users */
    CHECK(fm5_identity_is_guest(&id, 99) == 0);
    CHECK(fm5_identity_is_guest(NULL, 1) == 0);

    /* XUID: base nativa 2533274790395904 (imediato de User::get_XboxUserId). */
    CHECK(fm5_identity_xbox_user_id(&id, 0, buf, sizeof(buf)) == buf);
    CHECK(strcmp(buf, "2533274790395904") == 0);
    CHECK(strcmp(buf, "2533274790395904") == 0);
    CHECK(FM5_XBOX_USER_ID_BASE == 2533274790395904ULL);
    CHECK(FM5_XBOX_USER_ID_PLAYER1 == 2533274790395904ULL);
    CHECK(FM5_XBOX_USER_ID_PLAYER2 == 2533274790395905ULL);

    /* P2 tem XUID DISTINTO do P1 (evita colisão de ConnectedStorageSpace). */
    CHECK(fm5_identity_xbox_user_id(&id, 1, buf, sizeof(buf)) == buf);
    CHECK(strcmp(buf, "2533274790395905") == 0);
    CHECK(fm5_identity_xbox_user_id(&id, 2, buf, sizeof(buf)) == buf);
    CHECK(strcmp(buf, "2533274790395906") == 0);
    CHECK(fm5_identity_xbox_user_id(&id, 3, buf, sizeof(buf)) == buf);
    CHECK(strcmp(buf, "2533274790395907") == 0);

    /* Hash 1-based: "1" para o P1, "N+1" para o virtual. */
    CHECK(fm5_identity_xbox_user_hash(&id, 0, buf, sizeof(buf)) == buf);
    CHECK(strcmp(buf, "1") == 0);
    CHECK(strcmp(buf, FM5_XBOX_USER_HASH_PLAYER1) == 0);
    CHECK(fm5_identity_xbox_user_hash(&id, 1, buf, sizeof(buf)) == buf);
    CHECK(strcmp(buf, "2") == 0);
    CHECK(strcmp(buf, FM5_XBOX_USER_HASH_PLAYER2) == 0);
    CHECK(fm5_identity_xbox_user_hash(&id, 2, buf, sizeof(buf)) == buf);
    CHECK(strcmp(buf, "3") == 0);

    /* Limites: índice fora do range, buffer curto, ponteiros nulos. */
    CHECK(fm5_identity_xbox_user_id(&id, -1, buf, sizeof(buf)) == NULL);
    CHECK(fm5_identity_xbox_user_id(&id, 4, buf, sizeof(buf)) == NULL);
    CHECK(fm5_identity_xbox_user_hash(&id, -1, buf, sizeof(buf)) == NULL);
    CHECK(fm5_identity_xbox_user_hash(&id, 4, buf, sizeof(buf)) == NULL);
    CHECK(fm5_identity_xbox_user_id(&id, 0, NULL, sizeof(buf)) == NULL);
    CHECK(fm5_identity_xbox_user_hash(&id, 0, NULL, sizeof(buf)) == NULL);
    CHECK(fm5_identity_xbox_user_id(&id, 0, buf, 0) == NULL);
    /* 16 dígitos + NUL não cabem em 16 bytes. */
    CHECK(fm5_identity_xbox_user_id(&id, 0, buf, 16) == NULL);
    CHECK(fm5_identity_xbox_user_id(NULL, 0, buf, sizeof(buf)) == NULL);
    CHECK(fm5_identity_xbox_user_hash(NULL, 0, buf, sizeof(buf)) == NULL);

    /* max_users menor: índice 1 deixa de existir como usuário. */
    {
        fm5_identity_t small;
        fm5_identity_init(&small, 2, NULL);
        CHECK(fm5_identity_is_guest(&small, 1) == 1);
        CHECK(fm5_identity_is_guest(&small, 2) == 0);
        CHECK(fm5_identity_xbox_user_id(&small, 2, buf, sizeof(buf)) == NULL);
        fm5_identity_destroy(&small);
    }

    fm5_identity_destroy(&id);
}

/* TICKET-HARNESS-171 — a promoção do secundário é imediata e o primeiro Start
 * de QUALQUER secundário confirma a vaga do Player 2 (ordem de chegada, como
 * no console); o restante cai para os índices 2, 3, ... */
static void test_secondary_promoted_then_late_start(void)
{
    fm5_identity_t id;
    mat_state_t st = {0, -1};
    int p1 = 0x31, pad2 = 0x32, pad3 = 0x33;
    void *out = (void *)0x1;

    fm5_identity_init(&id, 3, NULL);
    (void)fm5_identity_index_for_controller(&id, &p1);
    (void)fm5_identity_index_for_controller(&id, &pad2);
    (void)fm5_identity_index_for_controller(&id, &pad3);

    CHECK(fm5_identity_claim_player(&id, &p1, FM5_IDENTITY_BUTTON_A) == 0);
    /* Ordem de registro: pad2 -> índice 1 (P2 virtual), pad3 -> índice 2. */
    CHECK(fm5_identity_index_for_controller(&id, &pad2) == 1);
    CHECK(fm5_identity_index_for_controller(&id, &pad3) == 2);
    CHECK(fm5_identity_is_assigned_controller(&id, &pad2) == 1);

    /* 50 leituras do índice 2: sempre NULL (sem canal), nunca o P1. */
    {
        int i;
        for (i = 0; i < 50; i++) {
            out = (void *)0x1;
            CHECK(fm5_resolve_get_user(&id, &pad3, &out, NULL,
                                       test_materializer, &st) ==
                  FM5_SERVED_NULL);
            CHECK(out == NULL);
        }
    }
    CHECK(st.calls == 0);
    /* O secundário do índice 1 já é servido como Player 2 virtual. */
    out = (void *)0x1;
    CHECK(fm5_resolve_get_user(&id, &pad2, &out, NULL, test_materializer,
                               &st) == FM5_HANDLED);
    CHECK(out == (void *)(uintptr_t)0x1001);
    CHECK(st.calls == 1);

    /* pad3 (o ÚLTIMO registrado) aperta Start primeiro e fica com a vaga. */
    CHECK(fm5_identity_claim_player(&id, &pad3, FM5_IDENTITY_BUTTON_MENU) == 1);
    CHECK(fm5_identity_index_for_controller(&id, &pad3) == 1);
    CHECK(fm5_identity_index_for_controller(&id, &pad2) == 2);
    CHECK(fm5_identity_index_for_controller(&id, &p1) == 0);

    fm5_identity_destroy(&id);
}
static void test_index_for_id(void)
{
    fm5_identity_t id;

    fm5_identity_init(&id, 4, NULL);
    CHECK(fm5_identity_index_for_id(&id, 1) == 0);  /* Player 1 */
    CHECK(fm5_identity_index_for_id(&id, 2) == 1);  /* Player 2 */
    CHECK(fm5_identity_index_for_id(&id, 4) == 3);
    CHECK(fm5_identity_index_for_id(&id, 0) == -1);
    CHECK(fm5_identity_index_for_id(&id, 5) == -1);
    CHECK(fm5_identity_index_for_id(NULL, 1) == -1);
    fm5_identity_destroy(&id);
}

static void test_console_count(void)
{
    fm5_identity_t id;
    int keys[3];

    fm5_identity_init(&id, 2, NULL);
    CHECK(fm5_identity_console_count(&id) == 2);
    fm5_identity_destroy(&id);

    fm5_identity_init(&id, 4, NULL);
    CHECK(fm5_identity_console_count(&id) == 2);
    CHECK(fm5_identity_claim_player(&id, &keys[0],
                                    FM5_IDENTITY_BUTTON_A) == 0);
    CHECK(fm5_identity_claim_player(&id, &keys[1],
                                    FM5_IDENTITY_BUTTON_MENU) == 1);
    /* A cascata elege apenas P2: a contagem exposta segue em 2. */
    CHECK(fm5_identity_console_count(&id) == 2);
    CHECK(fm5_identity_claim_player(&id, &keys[2],
                                    FM5_IDENTITY_BUTTON_MENU) == -1);
    CHECK(fm5_identity_console_count(&id) == 2);
    fm5_identity_destroy(&id);

    CHECK(fm5_identity_console_count(NULL) == 2);
}

static void test_resolve_get_user_by_id(void)
{
    fm5_identity_t id;
    mat_state_t st = {0, -1};
    void *out = NULL;

    fm5_identity_init(&id, 4, NULL);

    /* out == NULL -> E_POINTER, sem materializar. */
    CHECK(fm5_resolve_get_user_by_id(&id, 1, NULL, test_materializer, &st) ==
          FM5_E_POINTER);
    CHECK(st.calls == 0);

    /* id 1 -> Player 1 nativo (delegate), sem materializar. */
    CHECK(fm5_resolve_get_user_by_id(&id, 1, &out, test_materializer, &st) ==
          FM5_DELEGATE);
    CHECK(out == NULL);
    CHECK(st.calls == 0);

    /* id 2 -> Player 2 virtual materializado com AddRef feito pelo hook. */
    out = NULL;
    CHECK(fm5_resolve_get_user_by_id(&id, 2, &out, test_materializer, &st) ==
          FM5_HANDLED);
    CHECK(out == (void *)(uintptr_t)0x1001);
    CHECK(st.calls == 1);

    /* id 3 -> índice 2. */
    out = NULL;
    CHECK(fm5_resolve_get_user_by_id(&id, 3, &out, test_materializer, &st) ==
          FM5_HANDLED);
    CHECK(out == (void *)(uintptr_t)0x1002);
    CHECK(st.calls == 2);

    /* id 0 e id fora do range -> NULL + S_OK, como o binário original. */
    out = (void *)0x1;
    CHECK(fm5_resolve_get_user_by_id(&id, 0, &out, test_materializer, &st) ==
          FM5_SERVED_NULL);
    CHECK(out == NULL);
    out = (void *)0x1;
    CHECK(fm5_resolve_get_user_by_id(&id, 99, &out, test_materializer, &st) ==
          FM5_SERVED_NULL);
    CHECK(out == NULL);
    CHECK(st.calls == 2);

    fm5_identity_destroy(&id);

    /* Falha de materialização -> E_OUTOFMEMORY. */
    {
        mat_state_t fail = {0, 1};
        fm5_identity_init(&id, 3, NULL);
        out = NULL;
        CHECK(fm5_resolve_get_user_by_id(&id, 2, &out, test_materializer,
                                         &fail) == FM5_E_OUTOFMEMORY);
        CHECK(out == NULL);
        fm5_identity_destroy(&id);
    }
}

static void test_index_for_native_user(void)
{
    fm5_identity_t id;

    fm5_identity_init(&id, 3, NULL);
    CHECK(fm5_identity_index_for_native_user(&id, NULL) == -1);
    CHECK(fm5_identity_index_for_native_user(&id, (void *)0x4001) == -1);

    CHECK(fm5_identity_bind_native(&id, 0, (void *)0x4000, (void *)0x5000) == 0);
    CHECK(fm5_identity_bind_native(&id, 1, (void *)0x4001, (void *)0x5001) == 0);
    CHECK(fm5_identity_index_for_native_user(&id, (void *)0x4000) == 0);
    CHECK(fm5_identity_index_for_native_user(&id, (void *)0x4001) == 1);
    CHECK(fm5_identity_index_for_native_user(&id, (void *)0x9999) == -1);

    fm5_identity_destroy(&id);
}

typedef struct obs_state {
    int calls;
    void *last_ctx;
    void *last_sender;
    int last_index;
} obs_state_t;

static void obs_cb(void *ctx, void *sender, int index)
{
    obs_state_t *st = (obs_state_t *)ctx;
    st->calls++;
    st->last_ctx = ctx;
    st->last_sender = sender;
    st->last_index = index;
}

static void test_user_added_observers(void)
{
    fm5_identity_t id;
    obs_state_t a = {0, NULL, NULL, 0};
    obs_state_t b = {0, NULL, NULL, 0};
    int sender = 0xABCD;

    fm5_identity_init(&id, 3, NULL);

    CHECK(fm5_identity_add_observer(&id, NULL, NULL) == -1);
    CHECK(fm5_identity_add_observer(&id, obs_cb, &a) == 0);
    CHECK(fm5_identity_add_observer(&id, obs_cb, &b) == 0);

    /* Índice do Player 1 nunca é notificado. */
    CHECK(fm5_identity_notify_user_added(&id, &sender, 0) == 0);
    CHECK(a.calls == 0 && b.calls == 0);

    /* Player 2: dispara para os dois observadores, uma única vez. */
    CHECK(fm5_identity_notify_user_added(&id, &sender, 1) == 2);
    CHECK(a.calls == 1 && b.calls == 1);
    CHECK(a.last_ctx == &a && b.last_ctx == &b);
    CHECK(a.last_sender == &sender && b.last_sender == &sender);
    CHECK(a.last_index == 1 && b.last_index == 1);
    CHECK(fm5_identity_was_notified(&id, 1) == 1);

    /* Idempotente: segunda chamada não redispara. */
    CHECK(fm5_identity_notify_user_added(&id, &sender, 1) == 0);
    CHECK(a.calls == 1 && b.calls == 1);

    /* Índice fora do range não dispara nem marca. */
    CHECK(fm5_identity_notify_user_added(&id, &sender, FM5_P2_MAX_USERS) == 0);
    CHECK(fm5_identity_notify_user_added(&id, &sender, -1) == 0);
    CHECK(fm5_identity_notify_user_added(NULL, &sender, 1) == 0);
    CHECK(fm5_identity_was_notified(&id, 2) == 0);

    /* Limite de observadores respeitado (2 já registrados). */
    {
        int i;
        for (i = 2; i < FM5_P2_MAX_OBSERVERS; i++) {
            CHECK(fm5_identity_add_observer(&id, obs_cb, &a) == 0);
        }
        CHECK(fm5_identity_add_observer(&id, obs_cb, &a) == -1);
    }

    fm5_identity_destroy(&id);
}

/* TICKET-HARNESS-166 — cadeia ponta-a-ponta na unidade portátil:
 *   leitura já no enum Xbox One ERA (Menu = 0x0004)
 *     -> fm5_buttons_recompose (PASS-THROUGH PURO)
 *     -> fm5_identity_claim_player -> Player 2 definitivo (indice 1)
 *     -> fm5_identity_notify_user_added -> UserAdded (uma vez).
 * Prova tambem que o controle que ja e P1 NAO e promovido ao apertar Start e
 * que o D-Pad (DPadUp 0x0100 / DPadDown 0x0200) NAO e Start/Back. */
static void test_raw_start_encoding_claims_player2(void)
{
    fm5_identity_t id;
    obs_state_t obs;
    int p1 = 0;
    int p2 = 1;
    int sender = 0x5151;
    uint32_t raw_start = FM5_GB_MENU; /* 0x0004 — Start no enum Xbox One ERA */
    uint32_t composed;

    /* Start no enum Xbox One ERA e reconhecido e permanece intacto. */
    CHECK(fm5_buttons_start_pressed(raw_start) == 1);
    CHECK(fm5_buttons_back_pressed(raw_start) == 0);
    composed = fm5_buttons_recompose(raw_start, 0);
    CHECK(composed == raw_start); /* pass-through puro */
    CHECK((composed & FM5_GB_MENU) == FM5_GB_MENU);
    CHECK((composed & FM5_GB_A) == 0); /* Start cru nao carrega A */

    /* As setas do D-pad NAO sao Start/Back nem viram Menu/View. */
    CHECK(fm5_buttons_start_pressed(FM5_GB_DPAD_UP) == 0);
    CHECK(fm5_buttons_start_pressed(FM5_GB_DPAD_DOWN) == 0);
    CHECK(fm5_buttons_back_pressed(FM5_GB_DPAD_UP) == 0);
    CHECK(fm5_buttons_back_pressed(FM5_GB_DPAD_DOWN) == 0);
    CHECK(fm5_buttons_recompose(FM5_GB_DPAD_DOWN, 0) == FM5_GB_DPAD_DOWN);
    CHECK(fm5_buttons_recompose(FM5_GB_DPAD_UP, 0) == FM5_GB_DPAD_UP);

    memset(&obs, 0, sizeof(obs));
    fm5_identity_init(&id, 2, NULL);
    CHECK(fm5_identity_add_observer(&id, obs_cb, &obs) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &p1) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &p2) == 0);

    /* P1 eleito com A (0x0010 == FM5_GB_A). */
    CHECK(fm5_identity_claim_player(&id, &p1, FM5_GB_A) == 0);
    /* TICKET-HARNESS-171: o secundário já é o Player 2 virtual (índice 1). */
    CHECK(fm5_identity_index_for_controller(&id, &p2) == 1);

    /* Start do secundário confirma a vaga do P2 definitivo (indice 1). */
    CHECK(fm5_identity_claim_player(&id, &p2,
                                    composed & FM5_GB_MENU) == 1);

    /* O controle que ja e P1 NUNCA e promovido a P2 ao apertar Start. */
    CHECK(fm5_identity_claim_player(&id, &p1,
                                    composed & FM5_GB_MENU) == -1);
    CHECK(fm5_identity_index_for_controller(&id, &p1) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &p2) == 1);

    /* UserAdded dispara para o indice 1 e e idempotente. */
    CHECK(fm5_identity_notify_user_added(&id, &sender, 1) == 1);
    CHECK(obs.calls == 1);
    CHECK(obs.last_index == 1);
    CHECK(fm5_identity_notify_user_added(&id, &sender, 1) == 0);
    CHECK(obs.calls == 1);

    fm5_identity_destroy(&id);
}

/* TICKET-HARNESS-171 — isolamento estrito do Player 2. Depois da eleição do
 * Player 1, o controle secundário já é servido com o User virtual do Player 2
 * (FM5_HANDLED) e NUNCA delega ao User nativo do P1. O Start apenas confirma a
 * vaga (UserAdded). */
static void test_secondary_serves_virtual_after_p1(void)
{
    fm5_identity_t id;
    mat_state_t st = {0, -1};
    int p1 = 0x1111;
    int p2 = 0x2222;
    void *out = NULL;

    fm5_identity_init(&id, 2, NULL);

    /* Antes de qualquer eleicao, os dois delegam (boot seguro). */
    CHECK(fm5_resolve_get_user(&id, &p1, &out, NULL, test_materializer, &st) ==
          FM5_DELEGATE);
    CHECK(fm5_resolve_get_user(&id, &p2, &out, NULL, test_materializer, &st) ==
          FM5_DELEGATE);
    CHECK(st.calls == 0);

    /* A elege o P1 no controle p1 e promove p2 ao índice 1. */
    CHECK(fm5_identity_claim_player(&id, &p1, FM5_IDENTITY_BUTTON_A) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &p2) == 1);

    /* P1 continua nativo. */
    out = NULL;
    CHECK(fm5_resolve_get_user(&id, &p1, &out, NULL, test_materializer, &st) ==
          FM5_DELEGATE);
    CHECK(out == NULL);

    /* Secundário: SEMPRE o User virtual do Player 2, nunca o nativo do P1. */
    {
        int i;
        for (i = 0; i < 4; i++) {
            out = NULL;
            CHECK(fm5_resolve_get_user(&id, &p2, &out, NULL,
                                       test_materializer, &st) == FM5_HANDLED);
            CHECK(out == (void *)(uintptr_t)0x1001);
        }
    }
    CHECK(st.calls == 4);

    /* Start confirma a vaga; o User servido continua o mesmo virtual. */
    CHECK(fm5_identity_claim_player(&id, &p2, FM5_IDENTITY_BUTTON_MENU) == 1);
    out = NULL;
    CHECK(fm5_resolve_get_user(&id, &p2, &out, NULL, test_materializer, &st) ==
          FM5_HANDLED);
    CHECK(out == (void *)(uintptr_t)0x1001);

    fm5_identity_destroy(&id);
}

/* TICKET-HARNESS-171 — snapshots por índice usados pelo evento de pareamento:
 * o índice 1 leva o User VIRTUAL do Player 2 (nunca NULL, senão o Forza aborta
 * em 140675e3e) e os índices >= 2 levam User = NULL. */
static void test_controller_snapshots_by_index(void)
{
    fm5_identity_t id;
    int dev_a = 0x51, dev_b = 0x52, dev_c = 0x53, dev_d = 0x54;
    void *keys[FM5_P2_MAX_CONTROLLERS];
    int n;

    fm5_identity_init(&id, 2, NULL);

    /* Argumentos inválidos: zero, sem efeito colateral. */
    CHECK(fm5_identity_controllers_for_index(NULL, 1, keys, 4) == 0);
    CHECK(fm5_identity_controllers_for_index(&id, 1, NULL, 4) == 0);
    CHECK(fm5_identity_controllers_for_index(&id, 1, keys, 0) == 0);
    CHECK(fm5_identity_controllers_for_index(&id, -1, keys, 4) == 0);
    CHECK(fm5_identity_demoted_controllers(NULL, keys, 4) == 0);
    CHECK(fm5_identity_demoted_controllers(&id, NULL, 4) == 0);
    CHECK(fm5_identity_demoted_controllers(&id, keys, 0) == 0);

    /* FASE 1: todos no índice 0 — nenhum secundário, nenhum rebaixado. */
    CHECK(fm5_identity_index_for_controller(&id, &dev_a) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &dev_b) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &dev_c) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &dev_d) == 0);
    memset(keys, 0, sizeof(keys));
    CHECK(fm5_identity_controllers_for_index(&id, 1, keys,
                                             FM5_P2_MAX_CONTROLLERS) == 0);
    CHECK(fm5_identity_demoted_controllers(&id, keys,
                                           FM5_P2_MAX_CONTROLLERS) == 0);

    /* FASE 2: A em dev_a -> dev_b é o Player 2 virtual (índice 1) e dev_c/dev_d
     * ficam nos índices 2 e 3 (sem canal de usuário). */
    CHECK(fm5_identity_claim_player(&id, &dev_a, FM5_IDENTITY_BUTTON_A) == 0);
    memset(keys, 0, sizeof(keys));
    n = fm5_identity_controllers_for_index(&id, 1, keys,
                                           FM5_P2_MAX_CONTROLLERS);
    CHECK(n == 1);
    CHECK(keys[0] == &dev_b);
    memset(keys, 0, sizeof(keys));
    n = fm5_identity_demoted_controllers(&id, keys, FM5_P2_MAX_CONTROLLERS);
    CHECK(n == 2);
    CHECK(keys[0] == &dev_c && keys[1] == &dev_d);
    /* Contagem total pode exceder o cap: só as primeiras chaves são copiadas. */
    memset(keys, 0, sizeof(keys));
    CHECK(fm5_identity_demoted_controllers(&id, keys, 1) == 2);
    CHECK(keys[0] == &dev_c && keys[1] == NULL);
    /* O índice 0 (Player 1) nunca entra em nenhum dos dois snapshots. */
    memset(keys, 0, sizeof(keys));
    CHECK(fm5_identity_controllers_for_index(&id, 0, keys,
                                             FM5_P2_MAX_CONTROLLERS) == 1);
    CHECK(keys[0] == &dev_a);

    /* FASE 3: Start do índice 1 não move ninguém; snapshots continuam iguais. */
    CHECK(fm5_identity_claim_player(&id, &dev_b,
                                    FM5_IDENTITY_BUTTON_MENU) == 1);
    memset(keys, 0, sizeof(keys));
    CHECK(fm5_identity_controllers_for_index(&id, 1, keys,
                                             FM5_P2_MAX_CONTROLLERS) == 1);
    CHECK(keys[0] == &dev_b);
    CHECK(fm5_identity_demoted_controllers(&id, keys,
                                           FM5_P2_MAX_CONTROLLERS) == 2);

    fm5_identity_destroy(&id);
}

int main(void)
{
    test_init_defaults();
    test_controllers_born_player1();
    test_cascade_a_elects_p1_and_promotes_secondary();
    test_cascade_three_node_get_user();
    test_cascade_idempotent();
    test_cascade_ignores_other_buttons();
    test_cascade_late_controller_registration();
    test_controller_pool_limit();
    test_primary_helper();
    test_lock_helpers();
    test_max_users_clamped();
    test_custom_tag();
    test_resolve_get_user();
    test_resolve_get_user_index2_is_null();
    test_resolve_get_user_oom();
    test_resolve_get_users();
    test_bind_and_virtual_inner();
    test_snapshot_unique_ids();
    test_user_for_controller();
    test_index_for_id();
    test_console_count();
    test_resolve_get_user_by_id();
    test_index_for_native_user();
    test_user_added_observers();
    test_raw_start_encoding_claims_player2();
    test_secondary_serves_virtual_after_p1();
    test_guest_identity();
    test_secondary_promoted_then_late_start();
    test_controller_snapshots_by_index();

    if (g_failures) {
        fprintf(stderr, "\n%d/%d verificacoes FALHARAM\n", g_failures,
                g_checks);
        return 1;
    }
    printf("OK: %d verificacoes do nucleo de identidade passaram\n", g_checks);
    return 0;
}
