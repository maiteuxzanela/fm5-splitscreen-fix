/*
 * fm5_systemui.c — implementação portátil da bridge Windows.Xbox.UI.SystemUI.
 *
 * Sem <windows.h>, sem mocks: só a lógica determinística de ativação e as
 * vtables sintetizadas. A camada Windows apenas reconhece a classe no IAT de
 * RoGetActivationFactory e delega para fm5_systemui_try_activate().
 *
 * Layout de vtable seguido (ABI WinRT x86-64):
 *   slots 0..2  IUnknown    (QI, AddRef, Release)
 *   slots 3..5  IInspectable (GetIids, GetRuntimeClassName, GetTrustLevel)
 *   slot  8     ISystemUIStatics::ShowAccountPickerAsync
 *   slots 6..8  IAsyncOperation<AccountPickerResult*> (put/get Completed,
 *               GetResults) + 9..13 IAsyncInfo (Id, Status, ErrorCode, Cancel,
 *               Close)
 *   slots 6..7  IAccountPickerResult (User, Operation)
 *
 * Política de QueryInterface: os objetos são sínteses privadas do wrapper.
 * O jogo faz QI para as interfaces projetadas (IAsyncOperation<T>, IAsyncInfo,
 * IAccountPickerResult) cujos GUIDs são derivados do tipo e não são
 * reproduzíveis aqui; por isso a bridge aceita qualquer IID e devolve o mesmo
 * objeto com AddRef. riid/out inválidos continuam falhando com E_POINTER.
 */
#include "fm5_systemui.h"

#include <stdlib.h>
#include <string.h>

/* GUID ISystemUIStatics {1a0dd80e-3f9d-4cfa-8e50-0e2ebd1aa72f}
 * no layout de memória (little-endian nos três primeiros campos). */
const uint8_t fm5_systemui_iid_statics[16] = {
    0x0e, 0xd8, 0x0d, 0x1a, 0x9d, 0x3f, 0xfa, 0x4c,
    0x8e, 0x50, 0x0e, 0x2e, 0xbd, 0x1a, 0xa7, 0x2f
};

/* ------------------------------------------------------------------------- */
/* Forward declarations                                                      */
/* ------------------------------------------------------------------------- */
static int32_t statics_query_interface(void *self, const void *riid, void **out);
static uint32_t statics_add_ref(void *self);
static uint32_t statics_release(void *self);
static int32_t statics_get_iids(void *self, uint32_t *out_count,
                                void **out_iids);
static int32_t statics_get_runtime_class(void *self, void **out_name);
static int32_t statics_get_trust_level(void *self, int32_t *out_level);
static int32_t statics_slot6(void *self);
static int32_t statics_slot7(void *self);
static int32_t statics_show_account_picker_async(void *self, void *controller,
                                                 void *options,
                                                 void **out_async_op);

static int32_t async_query_interface(void *self, const void *riid, void **out);
static uint32_t async_add_ref(void *self);
static uint32_t async_release(void *self);
static int32_t async_get_iids(void *self, uint32_t *out_count, void **out_iids);
static int32_t async_get_runtime_class(void *self, void **out_name);
static int32_t async_get_trust_level(void *self, int32_t *out_level);
static int32_t async_put_completed(void *self, void *handler);
static int32_t async_get_completed(void *self, void **out);
static int32_t async_get_results(void *self, void **out);
static uint32_t async_get_id(void *self);
static int32_t async_get_status(void *self);
static int32_t async_get_error_code(void *self, int32_t *out);
static int32_t async_cancel(void *self);
static int32_t async_close(void *self);

static int32_t result_query_interface(void *self, const void *riid, void **out);
static uint32_t result_add_ref(void *self);
static uint32_t result_release(void *self);
static int32_t result_get_iids(void *self, uint32_t *out_count, void **out_iids);
static int32_t result_get_runtime_class(void *self, void **out_name);
static int32_t result_get_trust_level(void *self, int32_t *out_level);
static int32_t result_get_user(void *self, void **out_user);
static int32_t result_get_operation(void *self, uint32_t *out_op);

static fm5_async_op_t *async_create(fm5_systemui_t *owner);
static fm5_account_result_t *result_create(fm5_systemui_t *owner);

/* ------------------------------------------------------------------------- */
/* Vtables                                                                   */
/* ------------------------------------------------------------------------- */
static const fm5_systemui_statics_vt_t g_statics_vt = {
    .query_interface = statics_query_interface,
    .add_ref = statics_add_ref,
    .release = statics_release,
    .get_iids = statics_get_iids,
    .get_runtime_class = statics_get_runtime_class,
    .get_trust_level = statics_get_trust_level,
    .slot6 = statics_slot6,
    .slot7 = statics_slot7,
    .show_account_picker_async = statics_show_account_picker_async
};

static const fm5_async_op_vt_t g_async_vt = {
    .query_interface = async_query_interface,
    .add_ref = async_add_ref,
    .release = async_release,
    .get_iids = async_get_iids,
    .get_runtime_class = async_get_runtime_class,
    .get_trust_level = async_get_trust_level,
    .put_completed = async_put_completed,
    .get_completed = async_get_completed,
    .get_results = async_get_results,
    .get_id = async_get_id,
    .get_status = async_get_status,
    .get_error_code = async_get_error_code,
    .cancel = async_cancel,
    .close = async_close
};

static const fm5_account_result_vt_t g_result_vt = {
    .query_interface = result_query_interface,
    .add_ref = result_add_ref,
    .release = result_release,
    .get_iids = result_get_iids,
    .get_runtime_class = result_get_runtime_class,
    .get_trust_level = result_get_trust_level,
    .get_user = result_get_user,
    .get_operation = result_get_operation
};

/* ------------------------------------------------------------------------- */
/* AddRef/Release genéricos (vtable[1]/vtable[2])                            */
/* ------------------------------------------------------------------------- */
uint32_t fm5_systemui_addref_object(void *obj)
{
    const fm5_systemui_ref_fn *vt;

    if (!obj) {
        return 0;
    }
    vt = *(const fm5_systemui_ref_fn *const *)obj;
    if (!vt || !vt[FM5_SYSTEMUI_VT_ADDREF]) {
        return 0;
    }
    return vt[FM5_SYSTEMUI_VT_ADDREF](obj);
}

uint32_t fm5_systemui_release_object(void *obj)
{
    const fm5_systemui_ref_fn *vt;

    if (!obj) {
        return 0;
    }
    vt = *(const fm5_systemui_ref_fn *const *)obj;
    if (!vt || !vt[FM5_SYSTEMUI_VT_RELEASE]) {
        return 0;
    }
    return vt[FM5_SYSTEMUI_VT_RELEASE](obj);
}

/* ------------------------------------------------------------------------- */
/* Helpers internos                                                          */
/* ------------------------------------------------------------------------- */
static int32_t qi_accept_self(void *self, const void *riid, void **out)
{
    (void)riid; /* ver política de QI no cabeçalho do arquivo */
    if (!out) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    if (!self) {
        *out = NULL;
        return FM5_SYSTEMUI_E_UNEXPECTED;
    }
    *out = self;
    fm5_systemui_addref_object(self);
    return FM5_SYSTEMUI_S_OK;
}

static int32_t inspectable_get_iids(void *self, uint32_t *out_count,
                                    void **out_iids)
{
    (void)self;
    if (!out_count || !out_iids) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    *out_count = 0;
    *out_iids = NULL;
    return FM5_SYSTEMUI_E_NOTIMPL;
}

static int32_t inspectable_get_runtime_class(void *self, void **out_name)
{
    (void)self;
    if (!out_name) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    *out_name = NULL;
    return FM5_SYSTEMUI_E_NOTIMPL;
}

static int32_t inspectable_get_trust_level(void *self, int32_t *out_level)
{
    (void)self;
    if (!out_level) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    *out_level = FM5_TRUST_LEVEL_BASE;
    return FM5_SYSTEMUI_S_OK;
}

/* ------------------------------------------------------------------------- */
/* ISystemUIStatics                                                          */
/* ------------------------------------------------------------------------- */
static int32_t statics_query_interface(void *self, const void *riid, void **out)
{
    return qi_accept_self(self, riid, out);
}

static uint32_t statics_add_ref(void *self)
{
    fm5_systemui_statics_t *s = (fm5_systemui_statics_t *)self;

    if (!s) {
        return 0;
    }
    s->refcount++;
    return s->refcount;
}

static uint32_t statics_release(void *self)
{
    fm5_systemui_statics_t *s = (fm5_systemui_statics_t *)self;
    uint32_t remaining;

    if (!s) {
        return 0;
    }
    if (s->refcount == 0) {
        return 0; /* Release defensivo em objeto já destruído */
    }
    s->refcount--;
    remaining = s->refcount;
    if (remaining == 0) {
        free(s);
    }
    return remaining;
}

static int32_t statics_get_iids(void *self, uint32_t *out_count,
                                void **out_iids)
{
    return inspectable_get_iids(self, out_count, out_iids);
}

static int32_t statics_get_runtime_class(void *self, void **out_name)
{
    return inspectable_get_runtime_class(self, out_name);
}

static int32_t statics_get_trust_level(void *self, int32_t *out_level)
{
    return inspectable_get_trust_level(self, out_level);
}

/* Slots 6 e 7 de ISystemUIStatics não são usados pelo Forza; existem apenas
 * para preservar a posição de ShowAccountPickerAsync no slot 8 (offset 0x40). */
static int32_t statics_slot6(void *self)
{
    (void)self;
    return FM5_SYSTEMUI_E_NOTIMPL;
}

static int32_t statics_slot7(void *self)
{
    (void)self;
    return FM5_SYSTEMUI_E_NOTIMPL;
}

/*
 * slot 8 — HRESULT ShowAccountPickerAsync(self, controller, options, out_op).
 * O jogo espera uma IAsyncOperation<AccountPickerResult*> já concluída com o
 * Player 2; devolvemos a operação sintetizada e contabilizamos a chamada.
 */
static int32_t statics_show_account_picker_async(void *self, void *controller,
                                                 void *options,
                                                 void **out_async_op)
{
    fm5_systemui_statics_t *s = (fm5_systemui_statics_t *)self;
    fm5_async_op_t *op;

    (void)options;
    if (!out_async_op) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    *out_async_op = NULL;
    if (!s || !s->owner) {
        return FM5_SYSTEMUI_E_UNEXPECTED;
    }
    op = async_create(s->owner);
    if (!op) {
        return FM5_SYSTEMUI_E_OUTOFMEMORY;
    }
    s->owner->account_picker_calls++;
    /*
     * TICKET-HARNESS-166 — entrega o controller à camada Windows ANTES de
     * devolver a operação: o observador extrai *(controller+0x18) e garante a
     * eleição do Player 2 na máquina de cascata.
     */
    if (controller && s->owner->controller_observer) {
        s->owner->controller_observer(s->owner->controller_observer_ctx,
                                      controller);
    }
    *out_async_op = op;
    return FM5_SYSTEMUI_S_OK;
}

/* ------------------------------------------------------------------------- */
/* IAsyncOperation<AccountPickerResult*> + IAsyncInfo                        */
/* ------------------------------------------------------------------------- */
static int32_t async_query_interface(void *self, const void *riid, void **out)
{
    return qi_accept_self(self, riid, out);
}

static uint32_t async_add_ref(void *self)
{
    fm5_async_op_t *op = (fm5_async_op_t *)self;

    if (!op) {
        return 0;
    }
    op->refcount++;
    return op->refcount;
}

static uint32_t async_release(void *self)
{
    fm5_async_op_t *op = (fm5_async_op_t *)self;
    uint32_t remaining;
    void *handler;
    void *result;

    if (!op) {
        return 0;
    }
    if (op->refcount == 0) {
        return 0; /* Release defensivo em objeto já destruído */
    }
    op->refcount--;
    remaining = op->refcount;
    if (remaining == 0) {
        handler = op->completed_handler;
        result = op->result;
        op->completed_handler = NULL;
        op->result = NULL;
        if (handler) {
            fm5_systemui_release_object(handler);
        }
        if (result) {
            fm5_systemui_release_object(result);
        }
        free(op);
    }
    return remaining;
}

static int32_t async_get_iids(void *self, uint32_t *out_count, void **out_iids)
{
    return inspectable_get_iids(self, out_count, out_iids);
}

static int32_t async_get_runtime_class(void *self, void **out_name)
{
    return inspectable_get_runtime_class(self, out_name);
}

static int32_t async_get_trust_level(void *self, int32_t *out_level)
{
    return inspectable_get_trust_level(self, out_level);
}

/*
 * put_Completed: guarda o delegate (com AddRef) e, como a operação já nasceu
 * concluída, invoca handler->Invoke(self, AsyncStatus::Completed) na hora.
 * Handler NULL limpa o delegate sem invocar nada.
 */
static int32_t async_put_completed(void *self, void *handler)
{
    fm5_async_op_t *op = (fm5_async_op_t *)self;
    void *previous;
    const fm5_systemui_invoke_fn *vt;

    if (!op) {
        return FM5_SYSTEMUI_E_UNEXPECTED;
    }
    if (handler) {
        fm5_systemui_addref_object(handler);
    }
    previous = op->completed_handler;
    op->completed_handler = handler;
    if (previous) {
        fm5_systemui_release_object(previous);
    }
    if (handler) {
        vt = *(const fm5_systemui_invoke_fn *const *)handler;
        if (vt && vt[3]) {
            vt[3](handler, op,
                  (void *)(uintptr_t)FM5_ASYNC_STATUS_COMPLETED);
        }
    }
    return FM5_SYSTEMUI_S_OK;
}

static int32_t async_get_completed(void *self, void **out)
{
    fm5_async_op_t *op = (fm5_async_op_t *)self;

    if (!out) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    *out = op ? op->completed_handler : NULL;
    if (*out) {
        fm5_systemui_addref_object(*out);
    }
    return FM5_SYSTEMUI_S_OK;
}

/* GetResults entrega uma referência nova ao chamador. O cache da operação
 * mantém a sua própria referência, então o objeto sobrevive até o Release da
 * operação mesmo que o jogo solte o resultado imediatamente. */
static int32_t async_get_results(void *self, void **out)
{
    fm5_async_op_t *op = (fm5_async_op_t *)self;

    if (!out) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    *out = NULL;
    if (!op || !op->owner) {
        return FM5_SYSTEMUI_E_UNEXPECTED;
    }
    if (!op->result) {
        op->result = result_create(op->owner);
        if (!op->result) {
            return FM5_SYSTEMUI_E_OUTOFMEMORY;
        }
    }
    fm5_systemui_addref_object(op->result);
    *out = op->result;
    return FM5_SYSTEMUI_S_OK;
}

static uint32_t async_get_id(void *self)
{
    fm5_async_op_t *op = (fm5_async_op_t *)self;

    return op ? op->id : 0u;
}

static int32_t async_get_status(void *self)
{
    (void)self;
    return FM5_ASYNC_STATUS_COMPLETED;
}

static int32_t async_get_error_code(void *self, int32_t *out)
{
    (void)self;
    if (!out) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    *out = FM5_SYSTEMUI_S_OK;
    return FM5_SYSTEMUI_S_OK;
}

static int32_t async_cancel(void *self)
{
    (void)self;
    return FM5_SYSTEMUI_S_OK;
}

static int32_t async_close(void *self)
{
    (void)self;
    return FM5_SYSTEMUI_S_OK;
}

static fm5_async_op_t *async_create(fm5_systemui_t *owner)
{
    fm5_async_op_t *op;

    if (!owner) {
        return NULL;
    }
    op = (fm5_async_op_t *)malloc(sizeof(*op));
    if (!op) {
        return NULL;
    }
    owner->next_async_id++;
    op->vt = &g_async_vt;
    op->refcount = 1;
    op->owner = owner;
    op->completed_handler = NULL;
    op->result = NULL;
    op->id = owner->next_async_id;
    return op;
}

/* ------------------------------------------------------------------------- */
/* IAccountPickerResult                                                      */
/* ------------------------------------------------------------------------- */
static int32_t result_query_interface(void *self, const void *riid, void **out)
{
    return qi_accept_self(self, riid, out);
}

static uint32_t result_add_ref(void *self)
{
    fm5_account_result_t *r = (fm5_account_result_t *)self;

    if (!r) {
        return 0;
    }
    r->refcount++;
    return r->refcount;
}

static uint32_t result_release(void *self)
{
    fm5_account_result_t *r = (fm5_account_result_t *)self;
    uint32_t remaining;

    if (!r) {
        return 0;
    }
    if (r->refcount == 0) {
        return 0; /* Release defensivo em objeto já destruído */
    }
    r->refcount--;
    remaining = r->refcount;
    if (remaining == 0) {
        free(r);
    }
    return remaining;
}

static int32_t result_get_iids(void *self, uint32_t *out_count, void **out_iids)
{
    return inspectable_get_iids(self, out_count, out_iids);
}

static int32_t result_get_runtime_class(void *self, void **out_name)
{
    return inspectable_get_runtime_class(self, out_name);
}

static int32_t result_get_trust_level(void *self, int32_t *out_level)
{
    return inspectable_get_trust_level(self, out_level);
}

/* get_User: devolve o Player 2 virtual já materializado pelo wrapper, com
 * AddRef — exatamente o contrato que o jogo espera de AccountPickerResult. */
static int32_t result_get_user(void *self, void **out_user)
{
    fm5_account_result_t *r = (fm5_account_result_t *)self;
    void *user;

    if (!out_user) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    *out_user = NULL;
    if (!r || !r->owner) {
        return FM5_SYSTEMUI_E_UNEXPECTED;
    }
    user = r->owner->user_provider ? r->owner->user_provider(r->owner->user_ctx)
                                   : NULL;
    if (!user) {
        return FM5_SYSTEMUI_E_FAIL;
    }
    if (r->owner->user_addref) {
        r->owner->user_addref(user);
    }
    *out_user = user;
    return FM5_SYSTEMUI_S_OK;
}

static int32_t result_get_operation(void *self, uint32_t *out_op)
{
    (void)self;
    if (!out_op) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    *out_op = FM5_ACCOUNT_OPERATION_COMPLETED;
    return FM5_SYSTEMUI_S_OK;
}

static fm5_account_result_t *result_create(fm5_systemui_t *owner)
{
    fm5_account_result_t *r;

    if (!owner) {
        return NULL;
    }
    r = (fm5_account_result_t *)malloc(sizeof(*r));
    if (!r) {
        return NULL;
    }
    r->vt = &g_result_vt;
    r->refcount = 1;
    r->owner = owner;
    return r;
}

/* ------------------------------------------------------------------------- */
/* API pública                                                               */
/* ------------------------------------------------------------------------- */
void fm5_systemui_init(fm5_systemui_t *ui)
{
    if (!ui) {
        return;
    }
    memset(ui, 0, sizeof(*ui));
}

void fm5_systemui_set_user_source(fm5_systemui_t *ui,
                                  fm5_systemui_user_provider provider,
                                  void *ctx,
                                  fm5_systemui_addref_fn addref)
{
    if (!ui) {
        return;
    }
    ui->user_provider = provider;
    ui->user_ctx = ctx;
    ui->user_addref = addref;
}

void fm5_systemui_set_controller_observer(
    fm5_systemui_t *ui, fm5_systemui_controller_observer cb, void *ctx)
{
    if (!ui) {
        return;
    }
    ui->controller_observer = cb;
    ui->controller_observer_ctx = ctx;
}

int fm5_systemui_class_matches(const wchar_t *class_name)
{
    if (!class_name) {
        return 0;
    }
    return wcscmp(class_name, FM5_SYSTEMUI_CLASS_W) == 0 ? 1 : 0;
}

int fm5_systemui_iid_matches(const void *iid)
{
    if (!iid) {
        return 1; /* tolerância: sem riid explícito, assume a interface-alvo */
    }
    return memcmp(iid, fm5_systemui_iid_statics,
                  sizeof(fm5_systemui_iid_statics)) == 0
               ? 1
               : 0;
}

int32_t fm5_systemui_create_statics(fm5_systemui_t *ui, const void *iid,
                                    void **out_factory)
{
    fm5_systemui_statics_t *statics;

    if (!out_factory) {
        return FM5_SYSTEMUI_E_POINTER;
    }
    *out_factory = NULL;
    if (!ui) {
        return FM5_SYSTEMUI_E_UNEXPECTED;
    }
    if (!fm5_systemui_iid_matches(iid)) {
        return FM5_SYSTEMUI_E_NOINTERFACE;
    }
    statics = (fm5_systemui_statics_t *)malloc(sizeof(*statics));
    if (!statics) {
        return FM5_SYSTEMUI_E_OUTOFMEMORY;
    }
    statics->vt = &g_statics_vt;
    statics->refcount = 1;
    statics->owner = ui;
    ui->activations++;
    *out_factory = statics;
    return FM5_SYSTEMUI_S_OK;
}

int fm5_systemui_try_activate(fm5_systemui_t *ui, const wchar_t *class_name,
                              const void *iid, void **out_factory,
                              int32_t *out_hr)
{
    if (!fm5_systemui_class_matches(class_name)) {
        return 0;
    }
    if (!out_hr) {
        return 1;
    }
    *out_hr = fm5_systemui_create_statics(ui, iid, out_factory);
    return 1;
}
