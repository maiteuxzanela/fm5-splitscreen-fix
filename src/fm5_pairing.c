/*
 * fm5_pairing.c — objeto COM sintetizado para
 *                 Windows.Xbox.Input.ControllerPairingChangedEventArgs.
 *
 * Portátil (Linux/gcc nos testes, mingw/zig cc na DLL): só <stdlib.h> e
 * <string.h>. Nenhum mock: os testes chamam os slots pelo endereço publicado
 * na vtable, como o delegate do jogo faz.
 */
#include "fm5_pairing.h"

#include <stdlib.h>
#include <string.h>

/* IUnknown {00000000-0000-0000-C000-000000000046} */
const uint8_t fm5_pairing_iid_iunknown[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};

/* IInspectable {AF86E2E0-B12D-4C6A-9C5A-D7AA65101E90} */
const uint8_t fm5_pairing_iid_iinspectable[16] = {
    0xe0, 0xe2, 0x86, 0xaf, 0x2d, 0xb1, 0x6a, 0x4c,
    0x9c, 0x5a, 0xd7, 0xaa, 0x65, 0x10, 0x1e, 0x90
};

/* ------------------------------------------------------------------------- */
/* Forward declarations                                                      */
/* ------------------------------------------------------------------------- */
static int32_t args_query_interface(void *self, const void *riid, void **out);
static uint32_t args_add_ref(void *self);
static uint32_t args_release(void *self);
static int32_t args_get_iids(void *self, uint32_t *out_count, void **out_iids);
static int32_t args_get_runtime_class(void *self, void **out_name);
static int32_t args_get_trust_level(void *self, int32_t *out_level);
static int32_t args_get_user(void *self, void **out);
static int32_t args_get_previous_user(void *self, void **out);
static int32_t args_get_controller(void *self, void **out);
static int32_t args_stub(void *self, void *a, void *b);
static void args_heap_destroy(fm5_pairing_args_t *self);

/* ------------------------------------------------------------------------- */
/* Vtable (13 slots, ordem exata da ABI)                                     */
/* ------------------------------------------------------------------------- */
static const fm5_pairing_args_vt_t g_args_vt = {
    .query_interface = args_query_interface,         /* 0 */
    .add_ref = args_add_ref,                         /* 1 */
    .release = args_release,                         /* 2 */
    .get_iids = args_get_iids,                       /* 3 */
    .get_runtime_class = args_get_runtime_class,     /* 4 */
    .get_trust_level = args_get_trust_level,         /* 5 */
    .get_controller = args_get_controller,           /* 6 */
    .get_user = args_get_user,                       /* 7 */
    .get_previous_user = args_get_previous_user,     /* 8 */
    .slot9 = args_stub,                              /* 9  */
    .slot10 = args_stub,                             /* 10 */
    .slot11 = args_stub,                             /* 11 */
    .slot12 = args_stub                              /* 12 */
};

const fm5_pairing_args_vt_t *fm5_pairing_args_vtbl(void)
{
    return &g_args_vt;
}

/* ------------------------------------------------------------------------- */
/* Ciclo de vida                                                             */
/* ------------------------------------------------------------------------- */
fm5_pairing_args_t *fm5_pairing_args_init(fm5_pairing_args_t *args,
                                          void *user, void *previous_user,
                                          void *controller,
                                          fm5_pairing_addref_fn addref)
{
    if (!args) {
        return NULL;
    }
    memset(args, 0, sizeof(*args));
    args->vt = &g_args_vt;
    args->refcount = 1;
    args->user = user;
    args->previous_user = previous_user;
    args->controller = controller;
    args->addref = addref;
    args->destroy = NULL; /* memória do chamador: Release não libera */
    return args;
}

fm5_pairing_args_t *fm5_pairing_args_create(void *user, void *previous_user,
                                            void *controller,
                                            fm5_pairing_addref_fn addref)
{
    fm5_pairing_args_t *args;

    if (!addref) {
        /* Sem AddRef não há como entregar User/Controller com ownership
         * correto ao jogo: falhar fechado em vez de publicar um objeto
         * que devolveria ponteiros sem referência. */
        return NULL;
    }
    args = (fm5_pairing_args_t *)calloc(1, sizeof(*args));
    if (!args) {
        return NULL;
    }
    fm5_pairing_args_init(args, user, previous_user, controller, addref);
    args->destroy = args_heap_destroy;
    return args;
}

static void args_heap_destroy(fm5_pairing_args_t *self)
{
    free(self);
}

uint32_t fm5_pairing_args_addref(fm5_pairing_args_t *args)
{
    if (!args) {
        return 0;
    }
    return __atomic_add_fetch(&args->refcount, 1u, __ATOMIC_ACQ_REL);
}

uint32_t fm5_pairing_args_release(fm5_pairing_args_t *args)
{
    uint32_t remaining;

    if (!args) {
        return 0;
    }
    remaining = __atomic_sub_fetch(&args->refcount, 1u, __ATOMIC_ACQ_REL);
    if (remaining == 0 && args->destroy) {
        args->destroy(args);
    }
    return remaining;
}

/* ------------------------------------------------------------------------- */
/* IUnknown / IInspectable                                                   */
/* ------------------------------------------------------------------------- */
static int32_t args_query_interface(void *self, const void *riid, void **out)
{
    if (!out) {
        return FM5_PAIRING_E_POINTER;
    }
    if (!self) {
        *out = NULL;
        return FM5_PAIRING_E_FAIL;
    }
    if (!riid) {
        *out = NULL;
        return FM5_PAIRING_E_POINTER;
    }
    /* Este objeto é uma síntese privada do wrapper: só IUnknown e
     * IInspectable têm identidade conhecida. Qualquer outro IID devolve
     * E_NOINTERFACE com *out = NULL (nunca um ponteiro inválido). */
    if (memcmp(riid, fm5_pairing_iid_iunknown, 16) == 0 ||
        memcmp(riid, fm5_pairing_iid_iinspectable, 16) == 0) {
        args_add_ref(self);
        *out = self;
        return FM5_PAIRING_S_OK;
    }
    *out = NULL;
    return FM5_PAIRING_E_NOINTERFACE;
}

static uint32_t args_add_ref(void *self)
{
    return fm5_pairing_args_addref((fm5_pairing_args_t *)self);
}

static uint32_t args_release(void *self)
{
    return fm5_pairing_args_release((fm5_pairing_args_t *)self);
}

static int32_t args_get_iids(void *self, uint32_t *out_count, void **out_iids)
{
    (void)self;
    if (!out_count || !out_iids) {
        return FM5_PAIRING_E_POINTER;
    }
    /* Nenhum IID é afirmado (objeto privado do wrapper). Devolver S_OK com
     * lista vazia é o contrato mais benigno para um chamador que itere. */
    *out_count = 0;
    *out_iids = NULL;
    return FM5_PAIRING_S_OK;
}

static int32_t args_get_runtime_class(void *self, void **out_name)
{
    (void)self;
    if (!out_name) {
        return FM5_PAIRING_E_POINTER;
    }
    *out_name = NULL; /* sem nome de classe: objeto de runtime sintetizado */
    return FM5_PAIRING_S_OK;
}

static int32_t args_get_trust_level(void *self, int32_t *out_level)
{
    (void)self;
    if (!out_level) {
        return FM5_PAIRING_E_POINTER;
    }
    *out_level = FM5_PAIRING_TRUST_LEVEL_BASE;
    return FM5_PAIRING_S_OK;
}

/* ------------------------------------------------------------------------- */
/* Propriedades da interface                                                */
/* ------------------------------------------------------------------------- */
/* Contrato comum: out NULL -> E_POINTER; objeto ausente -> S_OK + NULL
 * (controle rebaixado / sem Controller); objeto presente -> S_OK + AddRef. */
static int32_t serve_object(fm5_pairing_args_t *args, void *object, void **out)
{
    if (!out) {
        return FM5_PAIRING_E_POINTER;
    }
    if (!object) {
        *out = NULL;
        return FM5_PAIRING_S_OK;
    }
    if (args->addref) {
        args->addref(object);
    }
    *out = object;
    return FM5_PAIRING_S_OK;
}

static int32_t args_get_user(void *self, void **out)
{
    fm5_pairing_args_t *args = (fm5_pairing_args_t *)self;
    if (!args) {
        return FM5_PAIRING_E_FAIL;
    }
    return serve_object(args, args->user, out);
}

static int32_t args_get_previous_user(void *self, void **out)
{
    fm5_pairing_args_t *args = (fm5_pairing_args_t *)self;
    if (!args) {
        return FM5_PAIRING_E_FAIL;
    }
    return serve_object(args, args->previous_user, out);
}

static int32_t args_get_controller(void *self, void **out)
{
    fm5_pairing_args_t *args = (fm5_pairing_args_t *)self;
    if (!args) {
        return FM5_PAIRING_E_FAIL;
    }
    return serve_object(args, args->controller, out);
}

/* ------------------------------------------------------------------------- */
/* Stub dos slots não declarados (9..12)                                     */
/* ------------------------------------------------------------------------- */
static int32_t args_stub(void *self, void *a, void *b)
{
    /* Não escreve nos parâmetros: a assinatura real do slot desconhecido pode
     * receber escalares. Devolver E_NOTIMPL é suficiente para o chamador
     * desistir sem corromper a pilha. */
    (void)self;
    (void)a;
    (void)b;
    return FM5_PAIRING_E_NOTIMPL;
}

/* ------------------------------------------------------------------------- */
/* Exports de conveniência (mesmo código publicado na vtable)                */
/* ------------------------------------------------------------------------- */
int32_t fm5_pairing_args_query_interface(void *self, const void *riid,
                                         void **out)
{
    return args_query_interface(self, riid, out);
}

int32_t fm5_pairing_args_get_user(void *self, void **out)
{
    return args_get_user(self, out);
}

int32_t fm5_pairing_args_get_previous_user(void *self, void **out)
{
    return args_get_previous_user(self, out);
}

int32_t fm5_pairing_args_get_controller(void *self, void **out)
{
    return args_get_controller(self, out);
}

int32_t fm5_pairing_args_get_iids(void *self, uint32_t *out_count,
                                  void **out_iids)
{
    return args_get_iids(self, out_count, out_iids);
}

int32_t fm5_pairing_args_get_runtime_class(void *self, void **out_name)
{
    return args_get_runtime_class(self, out_name);
}

int32_t fm5_pairing_args_get_trust_level(void *self, int32_t *out_level)
{
    return args_get_trust_level(self, out_level);
}

int32_t fm5_pairing_args_stub(void *self, void *a, void *b)
{
    return args_stub(self, a, b);
}
