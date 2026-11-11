/*
 * test_fm5_systemui.c — testes determinísticos REAIS da bridge sintetizada
 * Windows.Xbox.UI.SystemUI (TICKET-HARNESS-165).
 *
 * Compila e roda no host Linux (gcc), exercitando a MESMA unidade de código
 * (src/fm5_systemui.c) que a DLL usa no Windows. Sem mocks de framework: os
 * colaboradores externos são contratos públicos reais:
 *   - o provider do User do Player 2 devolve um sentinela determinístico e
 *     contabiliza AddRef;
 *   - o delegate de Completed é um objeto COM concreto (vtable própria) que
 *     registra a invocação.
 *
 * Cobre:
 *   1.  GUID de ISystemUIStatics no layout de memória correto;
 *   2.  reconhecimento exato do nome de classe;
 *   3.  ativação S_OK (nunca REGDB_E_CLASSNOTREG), IID divergente e ponteiros;
 *   4.  ShowAccountPickerAsync no slot 8 (offset 0x40) da vtable;
 *   5.  IAsyncOperation já Completed (Id/Status/ErrorCode/Cancel/Close);
 *   6.  put_Completed invoca Invoke(op, 1) e get_Completed devolve o handler;
 *   7.  GetResults entrega IAccountPickerResult com cache estável;
 *   8.  IAccountPickerResult::get_User devolve o Player 2 com AddRef e
 *       get_Operation == 0 (Completed);
 *   9.  ciclo completo: ativar -> ShowAccountPickerAsync -> handler ->
 *       GetResults -> get_User (nenhum erro em nenhuma etapa);
 *   10. contagem de referências e QueryInterface.
 */
#include "fm5_systemui.h"

#include <stdio.h>
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

/* ------------------------------------------------------------------------- */
/* Delegate concreto (objeto COM real, vtable própria)                       */
/* ------------------------------------------------------------------------- */
typedef struct fake_handler_vt {
    int32_t (*query_interface)(void *self, const void *riid, void **out);
    uint32_t (*add_ref)(void *self);
    uint32_t (*release)(void *self);
    int32_t (*invoke)(void *self, void *sender, void *args);
} fake_handler_vt_t;

typedef struct fake_handler {
    const fake_handler_vt_t *vt;
    uint32_t refcount;
    int invoke_count;
    void *last_sender;
    int last_status;
} fake_handler_t;

static int32_t fake_qi(void *self, const void *riid, void **out)
{
    (void)self;
    (void)riid;
    if (!out) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    *out = self;
    return FM5_SYSTEMUI_S_OK;
}

static uint32_t fake_add_ref(void *self)
{
    fake_handler_t *h = (fake_handler_t *)self;
    h->refcount++;
    return h->refcount;
}

static uint32_t fake_release(void *self)
{
    fake_handler_t *h = (fake_handler_t *)self;
    if (h->refcount > 0) {
        h->refcount--;
    }
    return h->refcount;
}

static int32_t fake_invoke(void *self, void *sender, void *args)
{
    fake_handler_t *h = (fake_handler_t *)self;
    h->invoke_count++;
    h->last_sender = sender;
    h->last_status = (int)(uintptr_t)args;
    return FM5_SYSTEMUI_S_OK;
}

static const fake_handler_vt_t g_fake_handler_vt = {
    fake_qi, fake_add_ref, fake_release, fake_invoke
};

static void handler_init(fake_handler_t *h)
{
    memset(h, 0, sizeof(*h));
    h->vt = &g_fake_handler_vt;
    h->refcount = 1;
}

/* ------------------------------------------------------------------------- */
/* Provider do User do Player 2                                              */
/* ------------------------------------------------------------------------- */
#define P2_SENTINEL ((void *)(uintptr_t)0x5002u)

typedef struct provider_state {
    void *user;
    int calls;
    int addref_calls;
} provider_state_t;

static void *provider_get_user(void *ctx)
{
    provider_state_t *st = (provider_state_t *)ctx;
    st->calls++;
    return st->user;
}

/* O addref recebe o MESMO ponteiro devolvido pelo provider (o User), então o
 * teste usa um estado anexado ao sentinela por uma tabela estática simples. */
static provider_state_t *g_provider_state;

static void user_addref(void *obj)
{
    if (obj == P2_SENTINEL && g_provider_state) {
        g_provider_state->addref_calls++;
    }
}

/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------- */
static fm5_systemui_statics_t *make_statics(fm5_systemui_t *ui)
{
    void *factory = NULL;
    int32_t hr = fm5_systemui_create_statics(ui, fm5_systemui_iid_statics,
                                             &factory);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(factory != NULL);
    return (fm5_systemui_statics_t *)factory;
}

static fm5_async_op_t *make_op(fm5_systemui_t *ui,
                               fm5_systemui_statics_t *statics)
{
    void *op = NULL;
    int32_t hr;

    CHECK(statics != NULL);
    if (!statics) {
        return NULL;
    }
    hr = statics->vt->show_account_picker_async(statics, NULL, NULL, &op);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(op != NULL);
    (void)ui;
    return (fm5_async_op_t *)op;
}

/* ------------------------------------------------------------------------- */
/* 1) GUID / constantes                                                      */
/* ------------------------------------------------------------------------- */
static void test_constants(void)
{
    static const uint8_t expected[16] = {
        0x0e, 0xd8, 0x0d, 0x1a, 0x9d, 0x3f, 0xfa, 0x4c,
        0x8e, 0x50, 0x0e, 0x2e, 0xbd, 0x1a, 0xa7, 0x2f
    };

    CHECK(sizeof(fm5_systemui_iid_statics) == 16);
    CHECK(memcmp(fm5_systemui_iid_statics, expected, sizeof(expected)) == 0);
    CHECK(fm5_systemui_iid_matches(fm5_systemui_iid_statics) == 1);
    CHECK(fm5_systemui_iid_matches(NULL) == 1);
    {
        uint8_t wrong[16];
        memcpy(wrong, expected, sizeof(wrong));
        wrong[0] ^= 0xff;
        CHECK(fm5_systemui_iid_matches(wrong) == 0);
    }

    /* Slots exigidos pelo contrato do jogo. */
    CHECK(FM5_SYSTEMUI_VT_SHOW_ACCOUNT_PICKER == 8u);
    CHECK(FM5_SYSTEMUI_VT_SHOW_ACCOUNT_PICKER * sizeof(void *) == 0x40u);
    CHECK(FM5_ASYNC_VT_PUT_COMPLETED == 6u);
    CHECK(FM5_ASYNC_VT_GET_COMPLETED == 7u);
    CHECK(FM5_ASYNC_VT_GET_RESULTS == 8u);
    CHECK(FM5_ASYNC_VT_GET_ID == 9u);
    CHECK(FM5_ASYNC_VT_GET_STATUS == 10u);
    CHECK(FM5_ASYNC_VT_GET_ERROR_CODE == 11u);
    CHECK(FM5_ASYNC_VT_CANCEL == 12u);
    CHECK(FM5_ASYNC_VT_CLOSE == 13u);
    CHECK(FM5_RESULT_VT_GET_USER == 6u);
    CHECK(FM5_RESULT_VT_GET_OPERATION == 7u);
    CHECK(FM5_ASYNC_STATUS_COMPLETED == 1);
    CHECK(FM5_ACCOUNT_OPERATION_COMPLETED == 0u);
    CHECK(FM5_SYSTEMUI_REGDB_E_CLASSNOTREG == (int32_t)0x80040154u);
}

/* ------------------------------------------------------------------------- */
/* 2) Reconhecimento do nome de classe                                       */
/* ------------------------------------------------------------------------- */
static void test_class_match(void)
{
    CHECK(fm5_systemui_class_matches(FM5_SYSTEMUI_CLASS_W) == 1);
    CHECK(fm5_systemui_class_matches(L"Windows.Xbox.UI.SystemUI") == 1);
    CHECK(fm5_systemui_class_matches(L"Windows.Xbox.UI.SystemUI2") == 0);
    CHECK(fm5_systemui_class_matches(L"Windows.Xbox.UI.System") == 0);
    CHECK(fm5_systemui_class_matches(L"Windows.Xbox.UI.Popups") == 0);
    CHECK(fm5_systemui_class_matches(L"Windows.Xbox.System.User") == 0);
    /* Nome de classe WinRT é case-sensitive. */
    CHECK(fm5_systemui_class_matches(L"windows.xbox.ui.systemui") == 0);
    CHECK(fm5_systemui_class_matches(L"") == 0);
    CHECK(fm5_systemui_class_matches(NULL) == 0);
}

/* ------------------------------------------------------------------------- */
/* 3) Ativação                                                               */
/* ------------------------------------------------------------------------- */
static void test_activation(void)
{
    fm5_systemui_t ui;
    void *factory = (void *)(uintptr_t)0xAAAAu;
    int32_t hr = 0;
    int32_t sentinel = 0x1234;

    fm5_systemui_init(&ui);

    /* Outra classe: NÃO é tratada (o chamador delega ao original). */
    sentinel = (int32_t)0x1234;
    hr = sentinel;
    CHECK(fm5_systemui_try_activate(&ui, L"Windows.Xbox.System.User",
                                    fm5_systemui_iid_statics, &factory,
                                    &hr) == 0);
    CHECK(hr == sentinel);
    CHECK(factory == (void *)(uintptr_t)0xAAAAu);

    /* Classe certa + IID errado: E_NOINTERFACE, sem fábrica. */
    {
        uint8_t wrong[16];
        memcpy(wrong, fm5_systemui_iid_statics, sizeof(wrong));
        wrong[15] ^= 0xff;
        factory = (void *)(uintptr_t)0xAAAAu;
        CHECK(fm5_systemui_try_activate(&ui, FM5_SYSTEMUI_CLASS_W, wrong,
                                        &factory, &hr) == 1);
        CHECK(hr == FM5_SYSTEMUI_E_NOINTERFACE);
        CHECK(factory == NULL);
    }

    /* Classe certa + out_factory NULL: E_POINTER (mas continua tratada). */
    hr = 0;
    CHECK(fm5_systemui_try_activate(&ui, FM5_SYSTEMUI_CLASS_W,
                                    fm5_systemui_iid_statics, NULL,
                                    &hr) == 1);
    CHECK(hr == FM5_SYSTEMUI_E_POINTER);

    /* Classe certa + IID correto: S_OK, NUNCA REGDB_E_CLASSNOTREG. */
    factory = NULL;
    hr = 0;
    CHECK(fm5_systemui_try_activate(&ui, FM5_SYSTEMUI_CLASS_W,
                                    fm5_systemui_iid_statics, &factory,
                                    &hr) == 1);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(hr != FM5_SYSTEMUI_REGDB_E_CLASSNOTREG);
    CHECK(factory != NULL);
    CHECK(ui.activations == 1);
    CHECK(ui.account_picker_calls == 0);
    if (factory) {
        fm5_systemui_statics_t *st = (fm5_systemui_statics_t *)factory;
        CHECK(st->vt->show_account_picker_async != NULL);
        CHECK(st->refcount == 1);
        CHECK(fm5_systemui_release_object(st) == 0);
    }

    /* IID NULL é tolerado (ativa como ISystemUIStatics). */
    factory = NULL;
    hr = 0;
    CHECK(fm5_systemui_try_activate(&ui, FM5_SYSTEMUI_CLASS_W, NULL, &factory,
                                    &hr) == 1);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(factory != NULL);
    if (factory) {
        fm5_systemui_release_object(factory);
    }

    /* Sem out_hr a ativação é ignorada com retorno 1 (sem crash). */
    factory = NULL;
    CHECK(fm5_systemui_try_activate(&ui, FM5_SYSTEMUI_CLASS_W,
                                    fm5_systemui_iid_statics, &factory,
                                    NULL) == 1);
    CHECK(factory == NULL);
}

/* ------------------------------------------------------------------------- */
/* 4/5/6) ShowAccountPickerAsync e IAsyncOperation                           */
/* ------------------------------------------------------------------------- */
static void test_async_operation(void)
{
    fm5_systemui_t ui;
    fm5_systemui_statics_t *st;
    fm5_async_op_t *op;
    void *out = NULL;
    int32_t hr;
    int32_t error = 0x7777;
    uint32_t op_id;

    fm5_systemui_init(&ui);
    st = make_statics(&ui);
    if (!st) {
        return;
    }

    /* out_async_op NULL -> E_POINTER e nenhuma chamada contabilizada. */
    hr = st->vt->show_account_picker_async(st, NULL, NULL, NULL);
    CHECK(hr == FM5_SYSTEMUI_E_POINTER);
    CHECK(ui.account_picker_calls == 0);

    op = make_op(&ui, st);
    if (!op) {
        return;
    }
    CHECK(ui.account_picker_calls == 1);
    CHECK(op->refcount == 1);
    CHECK(op->owner == &ui);
    CHECK(op->completed_handler == NULL);
    CHECK(op->result == NULL);
    CHECK(op->id == 1u);
    op_id = op->id;

    /* IAsyncInfo: já nasce Completed, sem erro. */
    CHECK(op->vt->get_id(op) == op_id);
    CHECK(op->vt->get_status(op) == FM5_ASYNC_STATUS_COMPLETED);
    CHECK(op->vt->get_error_code(op, &error) == FM5_SYSTEMUI_S_OK);
    CHECK(error == FM5_SYSTEMUI_S_OK);
    CHECK(op->vt->get_error_code(op, NULL) == FM5_SYSTEMUI_E_POINTER);
    CHECK(op->vt->cancel(op) == FM5_SYSTEMUI_S_OK);
    CHECK(op->vt->close(op) == FM5_SYSTEMUI_S_OK);
    CHECK(op->vt->get_status(op) == FM5_ASYNC_STATUS_COMPLETED);

    /* get_Completed sem handler registrado -> NULL. */
    out = (void *)(uintptr_t)0xBBBBu;
    CHECK(op->vt->get_completed(op, &out) == FM5_SYSTEMUI_S_OK);
    CHECK(out == NULL);
    CHECK(op->vt->get_completed(op, NULL) == FM5_SYSTEMUI_E_POINTER);

    /* put_Completed invoca Invoke(op, Completed) imediatamente. */
    {
        fake_handler_t handler;
        void *fetched = NULL;

        handler_init(&handler);
        CHECK(op->vt->put_completed(op, &handler) == FM5_SYSTEMUI_S_OK);
        CHECK(handler.invoke_count == 1);
        CHECK(handler.last_sender == op);
        CHECK(handler.last_status == FM5_ASYNC_STATUS_COMPLETED);
        CHECK(handler.refcount == 2); /* caller + operação */
        CHECK(op->completed_handler == &handler);

        CHECK(op->vt->get_completed(op, &fetched) == FM5_SYSTEMUI_S_OK);
        CHECK(fetched == &handler);
        CHECK(handler.refcount == 3); /* + referência da getter */
        CHECK(fm5_systemui_release_object(fetched) == 2);

        /* Substituir por NULL solta a referência guardada, sem invocar. */
        CHECK(op->vt->put_completed(op, NULL) == FM5_SYSTEMUI_S_OK);
        CHECK(op->completed_handler == NULL);
        CHECK(handler.refcount == 1);
        CHECK(handler.invoke_count == 1);
        CHECK(fm5_systemui_release_object(&handler) == 0);
    }

    CHECK(fm5_systemui_release_object(op) == 0);
    CHECK(fm5_systemui_release_object(st) == 0);
}

/* ------------------------------------------------------------------------- */
/* 7/8) GetResults e IAccountPickerResult                                    */
/* ------------------------------------------------------------------------- */
static void test_account_result(void)
{
    static provider_state_t state;
    fm5_systemui_t ui;
    fm5_systemui_statics_t *st;
    fm5_async_op_t *op;
    fm5_account_result_t *result = NULL;
    fm5_account_result_t *again = NULL;
    void *user = NULL;
    uint32_t operation = 0xFFFFu;
    int32_t hr;

    memset(&state, 0, sizeof(state));
    state.user = P2_SENTINEL;
    g_provider_state = &state;

    fm5_systemui_init(&ui);
    fm5_systemui_set_user_source(&ui, provider_get_user, &state, user_addref);
    st = make_statics(&ui);
    if (!st) {
        g_provider_state = NULL;
        return;
    }
    op = make_op(&ui, st);
    if (!op) {
        g_provider_state = NULL;
        return;
    }

    CHECK(op->vt->get_results(op, NULL) == FM5_SYSTEMUI_E_POINTER);

    hr = op->vt->get_results(op, (void **)&result);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(result != NULL);
    CHECK(op->result == result);
    /* Cache (1) + referência nova entregue ao chamador (2). */
    CHECK(result->refcount == 2);

    /* Segunda chamada devolve o MESMO objeto com nova referência. */
    hr = op->vt->get_results(op, (void **)&again);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(again == result);
    CHECK(result->refcount == 3);
    CHECK(fm5_systemui_release_object(again) == 2);

    /* get_User: Player 2 virtual, com AddRef contabilizado. */
    CHECK(result->vt->get_user(result, NULL) == FM5_SYSTEMUI_E_POINTER);
    CHECK(state.calls == 0);
    user = NULL;
    CHECK(result->vt->get_user(result, &user) == FM5_SYSTEMUI_S_OK);
    CHECK(user == P2_SENTINEL);
    CHECK(state.calls == 1);
    CHECK(state.addref_calls == 1);

    /* get_Operation: 0 == Completed. */
    CHECK(result->vt->get_operation(result, &operation) ==
          FM5_SYSTEMUI_S_OK);
    CHECK(operation == FM5_ACCOUNT_OPERATION_COMPLETED);
    CHECK(result->vt->get_operation(result, NULL) == FM5_SYSTEMUI_E_POINTER);

    /* Provider sem usuário -> E_FAIL e nenhum AddRef extra. */
    state.user = NULL;
    user = NULL;
    CHECK(result->vt->get_user(result, &user) == FM5_SYSTEMUI_E_FAIL);
    CHECK(user == NULL);
    CHECK(state.addref_calls == 1);
    state.user = P2_SENTINEL;

    /* Soltar a referência do chamador mantém o cache da operação vivo. */
    CHECK(fm5_systemui_release_object(result) == 1);
    /* Soltar a operação libera o cache (resultado + handler inexistente). */
    CHECK(fm5_systemui_release_object(op) == 0);
    CHECK(fm5_systemui_release_object(st) == 0);
    g_provider_state = NULL;
}

/* ------------------------------------------------------------------------- */
/* 9) Cadeia completa do lobby: ativar -> Show -> handler -> GetResults -> User */
/* ------------------------------------------------------------------------- */
static void test_full_chain(void)
{
    static provider_state_t state;
    fm5_systemui_t ui;
    void *factory = NULL;
    int32_t hr = 0;
    fm5_systemui_statics_t *st;
    fm5_async_op_t *op = NULL;
    fm5_account_result_t *result = NULL;
    fake_handler_t handler;
    void *user = NULL;

    memset(&state, 0, sizeof(state));
    state.user = P2_SENTINEL;
    g_provider_state = &state;

    fm5_systemui_init(&ui);
    fm5_systemui_set_user_source(&ui, provider_get_user, &state, user_addref);

    /* 1. O jogo pede a factory da classe. */
    CHECK(fm5_systemui_try_activate(&ui, L"Windows.Xbox.UI.SystemUI",
                                    fm5_systemui_iid_statics, &factory,
                                    &hr) == 1);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(factory != NULL);
    st = (fm5_systemui_statics_t *)factory;
    if (!st || hr != FM5_SYSTEMUI_S_OK) {
        g_provider_state = NULL;
        return;
    }

    /* 2. Start do P2 -> ShowAccountPickerAsync. */
    hr = st->vt->show_account_picker_async(st, (void *)0x1, (void *)0x2,
                                           (void **)&op);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(op != NULL);
    if (!op) {
        g_provider_state = NULL;
        return;
    }

    /* 3. O jogo registra o Completed e recebe o callback Completed. */
    handler_init(&handler);
    CHECK(op->vt->put_completed(op, &handler) == FM5_SYSTEMUI_S_OK);
    CHECK(handler.invoke_count == 1);
    CHECK(handler.last_status == FM5_ASYNC_STATUS_COMPLETED);

    /* 4. O jogo pede o resultado. */
    hr = op->vt->get_results(op, (void **)&result);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(result != NULL);
    if (!result) {
        g_provider_state = NULL;
        return;
    }

    /* 5. O jogo lê o Player 2 e a operação (Completed). */
    CHECK(result->vt->get_user(result, &user) == FM5_SYSTEMUI_S_OK);
    CHECK(user == P2_SENTINEL);
    CHECK(state.addref_calls == 1);
    {
        uint32_t operation = 0xFFFFu;
        CHECK(result->vt->get_operation(result, &operation) ==
              FM5_SYSTEMUI_S_OK);
        CHECK(operation == FM5_ACCOUNT_OPERATION_COMPLETED);
    }

    /* Nenhuma etapa devolveu REGDB_E_CLASSNOTREG. */
    CHECK(hr != FM5_SYSTEMUI_REGDB_E_CLASSNOTREG);
    CHECK(ui.activations == 1);
    CHECK(ui.account_picker_calls == 1);

    /* 6. Desmontagem na ordem inversa do COM. */
    CHECK(fm5_systemui_release_object(result) == 1); /* cache da operação */
    CHECK(fm5_systemui_release_object(op) == 0);     /* libera cache+handler */
    CHECK(handler.refcount == 1);
    CHECK(fm5_systemui_release_object(&handler) == 0);
    CHECK(st->refcount == 1);
    CHECK(fm5_systemui_release_object(st) == 0);
    g_provider_state = NULL;
}

/* ------------------------------------------------------------------------- */
/* 10) QueryInterface                                                        */
/* ------------------------------------------------------------------------- */
static void test_query_interface(void)
{
    fm5_systemui_t ui;
    fm5_systemui_statics_t *st;
    void *out = NULL;

    fm5_systemui_init(&ui);
    st = make_statics(&ui);
    if (!st) {
        return;
    }

    CHECK(st->vt->query_interface(st, fm5_systemui_iid_statics, NULL) ==
          FM5_SYSTEMUI_E_POINTER);
    CHECK(st->vt->query_interface(st, fm5_systemui_iid_statics, &out) ==
          FM5_SYSTEMUI_S_OK);
    CHECK(out == st);
    CHECK(st->refcount == 2);
    CHECK(fm5_systemui_release_object(out) == 1);
    CHECK(fm5_systemui_release_object(st) == 0);
}

/* ------------------------------------------------------------------------- */
/* 11) TICKET-HARNESS-166 — observador de ShowAccountPickerAsync             */
/* ------------------------------------------------------------------------- */
typedef struct controller_obs_state {
    int calls;
    void *last_ctx;
    void *last_controller;
} controller_obs_state_t;

static void controller_obs(void *ctx, void *controller)
{
    controller_obs_state_t *s = (controller_obs_state_t *)ctx;
    s->calls++;
    s->last_ctx = ctx;
    s->last_controller = controller;
}

static void test_controller_observer(void)
{
    static provider_state_t state;
    fm5_systemui_t ui;
    fm5_systemui_statics_t *st;
    controller_obs_state_t obs;
    void *op = NULL;
    int32_t hr;

    memset(&state, 0, sizeof(state));
    state.user = P2_SENTINEL;
    g_provider_state = &state;
    memset(&obs, 0, sizeof(obs));
    fm5_systemui_init(&ui);
    fm5_systemui_set_user_source(&ui, provider_get_user, &state, user_addref);
    fm5_systemui_set_controller_observer(&ui, controller_obs, &obs);
    st = make_statics(&ui);
    if (!st) {
        return;
    }

    /* controller presente (sentinela reconhecível) -> observador recebe o
     * MESMO ponteiro e o ctx registrado. */
    hr = st->vt->show_account_picker_async(st, (void *)(uintptr_t)0x1234u,
                                           NULL, &op);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(op != NULL);
    CHECK(obs.calls == 1);
    CHECK(obs.last_ctx == &obs);
    CHECK(obs.last_controller == (void *)(uintptr_t)0x1234u);
    if (op) {
        CHECK(fm5_systemui_release_object(op) == 0);
        op = NULL;
    }

    /* controller NULL -> observador NÃO é chamado (nada a eleger). */
    hr = st->vt->show_account_picker_async(st, NULL, NULL, &op);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(obs.calls == 1);
    if (op) {
        CHECK(fm5_systemui_release_object(op) == 0);
        op = NULL;
    }

    /* out_async_op NULL continua E_POINTER e não dispara o observador. */
    hr = st->vt->show_account_picker_async(st, (void *)(uintptr_t)0x9u, NULL,
                                           NULL);
    CHECK(hr == FM5_SYSTEMUI_E_POINTER);
    CHECK(obs.calls == 1);

    /* Desligar o observador (NULL) é seguro: nenhuma chamada. */
    fm5_systemui_set_controller_observer(&ui, NULL, NULL);
    hr = st->vt->show_account_picker_async(st, (void *)(uintptr_t)0x77u, NULL,
                                           &op);
    CHECK(hr == FM5_SYSTEMUI_S_OK);
    CHECK(obs.calls == 1);
    if (op) {
        CHECK(fm5_systemui_release_object(op) == 0);
    }

    CHECK(fm5_systemui_release_object(st) == 0);
    g_provider_state = NULL;
}

int main(void)
{
    test_constants();
    test_class_match();
    test_activation();
    test_async_operation();
    test_account_result();
    test_full_chain();
    test_query_interface();
    test_controller_observer();

    if (g_failures) {
        fprintf(stderr, "\n%d/%d verificacoes da bridge SystemUI FALHARAM\n",
                g_failures, g_checks);
        return 1;
    }
    printf("OK: %d verificacoes da bridge SystemUI passaram\n", g_checks);
    return 0;
}
