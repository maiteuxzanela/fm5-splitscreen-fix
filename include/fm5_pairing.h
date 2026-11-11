/*
 * fm5_pairing.h — objeto COM sintetizado para
 *                 Windows.Xbox.Input.ControllerPairingChangedEventArgs
 *                 (Forza Motorsport 5 / split-screen Player 2).
 *
 * PROBLEMA RAIZ (TICKET-HARNESS-169)
 *   O evento ControllerPairingChanged era disparado passando o PRÓPRIO
 *   `sender` (singleton de ControllerStatics) no lugar do `args`:
 *
 *       ((invoke_fn)vt[3])(handler, sender, sender);
 *
 *   Quando o handler do Forza consulta `args` ele resolve a vtable de
 *   `ControllerStatics` sobre um ponteiro que o jogo espera ser
 *   IControllerPairingChangedEventArgs: o primeiro método cai num thunk com
 *   assinatura incompatível e o processo morre com STATUS_ACCESS_VIOLATION.
 *   Suprimir o evento (FM5_P2_DISABLE_PAIRING_EVENT=1) também não resolve: sem
 *   o evento o Forza mantém o `User` CACHEADO do Player 1 nos controles
 *   rebaixados, funde os dois jogadores na Home e volta ao menu quando o P2
 *   aperta Start no lobby (o jogo não aceita P1 contra P1).
 *
 * SOLUÇÃO
 *   Esta unidade PORTÁTIL (sem <windows.h>) sintetiza um objeto COM legítimo
 *   com o layout de vtable da interface (ABI WinRT x86-64):
 *
 *     slots 0..2   IUnknown     (QueryInterface, AddRef, Release)
 *     slots 3..5   IInspectable (GetIids, GetRuntimeClassName, GetTrustLevel)
 *     slot  6      get_Controller    -> Controller* (ponteiro REAL do device)
 *     slot  7      get_User          -> User* novo (NULL no rebaixamento)
 *     slot  8      get_PreviousUser  -> User* anterior (Player 1 nativo)
 *     slots 9..12  stubs seguros que devolvem E_NOTIMPL (nunca estouram a
 *                  vtable se o jogo chamar um método além dos declarados)
 *
 *   A ordem 6/7/8 foi CONFIRMADA por desmontagem do
 *   forza_durango_release_final.exe (TICKET-HARNESS-170):
 *
 *     - 0x140675e10 (handler de Pairing): chama args->vtable[6] (+0x30) em
 *       0x140675e81 e guarda o retorno em [event+0x18]; chama args->vtable[7]
 *       (+0x38) em 0x140675e36/0x140675e66 e guarda o retorno em [event+0x20].
 *     - 0x140675880 (despachante): passa [event+0x18] em rdx como CONTROLLER e
 *       [event+0x20] em r8 como USER para 0x1406763a0(InputManager,
 *       Controller*, User*).
 *     - 0x1406763a0 compara [slot+0x70] com o Controller* recebido e, só em
 *       caso de correspondência, grava o User* em [slot+0x78].
 *
 *   Logo o slot 6 entrega Controller*, o slot 7 entrega o User* novo e o slot
 *   8 o PreviousUser — inverter 6/7 faz o jogo tratar um User* como Controller*
 *   e abortar a atualização do slot de controle.
 *
 *   Toda propriedade que devolve ponteiro faz AddRef no objeto entregue (via
 *   callback injetado, pois a camada Windows usa a vtable do próprio jogo) e
 *   devolve S_OK + NULL para controle rebaixado — o contrato do console para
 *   "controle sem perfil". Nenhum caminho devolve ponteiro não nulo sem
 *   AddRef, e nenhum caminho retorna lixo para `out == NULL` (E_POINTER).
 *
 *   QueryInterface é ESTRITO: só IUnknown e IInspectable respondem S_OK. Um
 *   IID desconhecido devolve E_NOINTERFACE com *out = NULL — e isso é
 *   proposital. A causa do crash original foi exatamente CONFUSÃO DE TIPOS
 *   (o jogo tratou o sender como se fosse o args); aceitar qualquer IID
 *   permitiria que o args sintetizado fosse confundido com outra interface
 *   (p.ex. IController) e reintroduziria a mesma classe de falha.
 *
 *   Os testes nativos (tests/test_fm5_pairing.c, Linux/gcc) exercitam ESTA
 *   MESMA unidade sem mocks: os objetos User/Controller sentinela têm vtables
 *   reais de AddRef/Release e cada slot é chamado pelo endereço publicado na
 *   vtable, exatamente como o jogo faz.
 */
#ifndef FM5_PAIRING_H
#define FM5_PAIRING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HRESULTs (portáveis, sem depender de <winerror.h>). */
#define FM5_PAIRING_S_OK            ((int32_t)0)
#define FM5_PAIRING_S_FALSE         ((int32_t)1)
#define FM5_PAIRING_E_NOTIMPL       ((int32_t)0x80004001u)
#define FM5_PAIRING_E_NOINTERFACE   ((int32_t)0x80004002u)
#define FM5_PAIRING_E_POINTER       ((int32_t)0x80004003u)
#define FM5_PAIRING_E_FAIL          ((int32_t)0x80004005u)
#define FM5_PAIRING_E_OUTOFMEMORY   ((int32_t)0x8007000Eu)
#define FM5_PAIRING_E_INVALIDARG    ((int32_t)0x80070057u)

/* Slots da vtable (ABI WinRT x86-64). */
#define FM5_PAIRING_VT_QI               0u
#define FM5_PAIRING_VT_ADDREF           1u
#define FM5_PAIRING_VT_RELEASE          2u
#define FM5_PAIRING_VT_GET_IIDS         3u
#define FM5_PAIRING_VT_RUNTIME_NAME     4u
#define FM5_PAIRING_VT_TRUST_LEVEL      5u
#define FM5_PAIRING_VT_GET_CONTROLLER   6u
#define FM5_PAIRING_VT_GET_USER         7u
#define FM5_PAIRING_VT_GET_PREV_USER    8u
#define FM5_PAIRING_VT_FIRST_STUB       9u
#define FM5_PAIRING_VT_SLOTS            13u

/* Trust level (BaseTrust) devolvido por IInspectable::GetTrustLevel. */
#define FM5_PAIRING_TRUST_LEVEL_BASE    0

/* IIDs conhecidos, em layout de memória (Data1/Data2/Data3 little-endian).
 * IUnknown    {00000000-0000-0000-C000-000000000046}
 * IInspectable {AF86E2E0-B12D-4C6A-9C5A-D7AA65101E90} */
extern const uint8_t fm5_pairing_iid_iunknown[16];
extern const uint8_t fm5_pairing_iid_iinspectable[16];

/* AddRef dos objetos entregues por get_User/get_PreviousUser/get_Controller.
 * A camada Windows injeta com_addref (vtable[1] do próprio objeto do jogo);
 * em teste é o AddRef real do objeto sentinela. */
typedef void (*fm5_pairing_addref_fn)(void *obj);

typedef int32_t (*fm5_pairing_qi_fn)(void *self, const void *riid, void **out);
typedef uint32_t (*fm5_pairing_ref_fn)(void *self);
typedef int32_t (*fm5_pairing_get_iids_fn)(void *self, uint32_t *out_count,
                                            void **out_iids);
typedef int32_t (*fm5_pairing_get_name_fn)(void *self, void **out_name);
typedef int32_t (*fm5_pairing_get_trust_fn)(void *self, int32_t *out_level);
/* get_User / get_PreviousUser / get_Controller compartilham a mesma ABI. */
typedef int32_t (*fm5_pairing_prop_fn)(void *self, void **out_obj);
typedef int32_t (*fm5_pairing_stub_fn)(void *self, void *a, void *b);

/*
 * Vtable da interface. Os 13 slots são listados na ordem exata da ABI; o
 * endereço do primeiro membro é o `vfptr` publicado ao jogo.
 */
typedef struct fm5_pairing_args_vt {
    fm5_pairing_qi_fn          query_interface;   /* 0 */
    fm5_pairing_ref_fn         add_ref;           /* 1 */
    fm5_pairing_ref_fn         release;           /* 2 */
    fm5_pairing_get_iids_fn    get_iids;          /* 3 */
    fm5_pairing_get_name_fn    get_runtime_class; /* 4 */
    fm5_pairing_get_trust_fn   get_trust_level;   /* 5 */
    fm5_pairing_prop_fn        get_controller;    /* 6 */
    fm5_pairing_prop_fn        get_user;          /* 7 */
    fm5_pairing_prop_fn        get_previous_user; /* 8 */
    fm5_pairing_stub_fn        slot9;             /* 9  */
    fm5_pairing_stub_fn        slot10;            /* 10 */
    fm5_pairing_stub_fn        slot11;            /* 11 */
    fm5_pairing_stub_fn        slot12;            /* 12 */
} fm5_pairing_args_vt_t;

/*
 * O objeto entregue ao delegate. `vt` PRECISA ser o primeiro campo: o jogo lê
 * `*(void ***)args` para resolver a vtable.
 */
typedef struct fm5_pairing_args {
    const fm5_pairing_args_vt_t *vt;
    uint32_t                     refcount;
    void                        *user;          /* novo User (NULL = rebaixado) */
    void                        *previous_user; /* User anterior (P1 nativo)  */
    void                        *controller;    /* Controller*, se conhecido  */
    fm5_pairing_addref_fn        addref;        /* AddRef dos objetos acima   */
    /* Libera o próprio objeto quando o refcount chega a zero. NULL quando o
     * armazenamento pertence ao chamador (pilha) — ver fm5_pairing_args_init. */
    void                       (*destroy)(struct fm5_pairing_args *self);
} fm5_pairing_args_t;

/*
 * Preenche um objeto JÁ alocado pelo chamador (pilha/campo). Não libera nada
 * no Release: ownership é do chamador. Devolve o próprio `args`.
 */
fm5_pairing_args_t *fm5_pairing_args_init(fm5_pairing_args_t *args,
                                          void *user, void *previous_user,
                                          void *controller,
                                          fm5_pairing_addref_fn addref);

/*
 * Aloca o objeto no heap com refcount 1. O Release final libera a memória.
 * Devolve NULL se `addref` for NULL ou se a alocação falhar.
 */
fm5_pairing_args_t *fm5_pairing_args_create(void *user, void *previous_user,
                                            void *controller,
                                            fm5_pairing_addref_fn addref);

/* Endereço da vtable publicada (13 slots; nunca NULL). */
const fm5_pairing_args_vt_t *fm5_pairing_args_vtbl(void);

/* Acesso direto aos slots (o mesmo código que a vtable publica). */
uint32_t fm5_pairing_args_addref(fm5_pairing_args_t *args);
uint32_t fm5_pairing_args_release(fm5_pairing_args_t *args);
int32_t fm5_pairing_args_query_interface(void *self, const void *riid,
                                         void **out);
int32_t fm5_pairing_args_get_user(void *self, void **out);
int32_t fm5_pairing_args_get_previous_user(void *self, void **out);
int32_t fm5_pairing_args_get_controller(void *self, void **out);
int32_t fm5_pairing_args_get_iids(void *self, uint32_t *out_count,
                                  void **out_iids);
int32_t fm5_pairing_args_get_runtime_class(void *self, void **out_name);
int32_t fm5_pairing_args_get_trust_level(void *self, int32_t *out_level);
/* Stub seguro para os slots 9..12: preenche ponteiros com NULL e devolve
 * E_NOTIMPL — jamais escreve fora do parâmetro entregue. */
int32_t fm5_pairing_args_stub(void *self, void *a, void *b);

#ifdef __cplusplus
}
#endif

#endif /* FM5_PAIRING_H */
