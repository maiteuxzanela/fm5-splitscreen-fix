/*
 * fm5_systemui.h — bridge WinRT sintetizada para
 *                  Windows.Xbox.UI.SystemUI (Forza Motorsport 5 / split-screen).
 *
 * PROBLEMA RAIZ (TICKET-HARNESS-165)
 *   No lobby de split-screen o Start do segundo controle faz o jogo invocar
 *   ShowAccountPickerAsync (RVA 0x332bc0 do exe). A implementação passa por
 *   RoGetActivationFactory("Windows.Xbox.UI.SystemUI") e o Azimuth 1.0.4 não
 *   conhece essa classe: devolve REGDB_E_CLASSNOTREG (0x80040154), o que
 *   dispara __abi_ThrowIfFailed / Platform::COMException e aborta a entrada do
 *   Player 2 (efeito visual de "Back").
 *
 * SOLUÇÃO
 *   Esta unidade portátil (sem <windows.h>) contém TODA a lógica determinística
 *   da bridge:
 *     - reconhecimento exato do nome de classe;
 *     - GUID de ISystemUIStatics em layout de memória;
 *     - fábrica virtual ISystemUIStatics (vtable[8] = ShowAccountPickerAsync);
 *     - IAsyncOperation<AccountPickerResult*> sintetizada (IAsyncOperation +
 *       IAsyncInfo), que já nasce Completed;
 *     - IAccountPickerResult sintetizada, cuja get_User devolve o Player 2
 *       virtual materializado (ID 2, GamerTag "Player 2") com AddRef.
 *
 *   A camada Windows (fm5_hooks.c) apenas patcheia o slot IAT de
 *   RoGetActivationFactory (RVA 0x68e8c0 do azimuth.exe), lê a HSTRING da
 *   classe e delega para fm5_systemui_try_activate(); qualquer outra classe
 *   continua seguindo para a função original.
 *
 *   Os testes nativos (tests/test_fm5_systemui.c, Linux/gcc) exercitam esta
 *   MESMA unidade sem mocks: os colaboradores (providers/addref) são contratos
 *   públicos injetados e devolvem sentinelas determinísticos.
 */
#ifndef FM5_SYSTEMUI_H
#define FM5_SYSTEMUI_H

#include <stdint.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Nome de classe procurado pelo jogo em RoGetActivationFactory. */
#define FM5_SYSTEMUI_CLASS_W L"Windows.Xbox.UI.SystemUI"

/* HRESULTs usados pela bridge (portáveis, sem depender de <winerror.h>). */
#define FM5_SYSTEMUI_S_OK                 ((int32_t)0)
#define FM5_SYSTEMUI_S_FALSE              ((int32_t)1)
#define FM5_SYSTEMUI_E_NOTIMPL            ((int32_t)0x80004001u)
#define FM5_SYSTEMUI_E_NOINTERFACE        ((int32_t)0x80004002u)
#define FM5_SYSTEMUI_E_POINTER            ((int32_t)0x80004003u)
#define FM5_SYSTEMUI_E_FAIL               ((int32_t)0x80004005u)
#define FM5_SYSTEMUI_E_OUTOFMEMORY        ((int32_t)0x8007000Eu)
#define FM5_SYSTEMUI_E_UNEXPECTED         ((int32_t)0x8000FFFFu)
/* Exatamente o código que o Azimuth devolvia e que abortava o lobby. */
#define FM5_SYSTEMUI_REGDB_E_CLASSNOTREG  ((int32_t)0x80040154u)

/* Slots de vtable (0..2 IUnknown, 3..5 IInspectable em todos os objetos). */
#define FM5_SYSTEMUI_VT_QI                 0u
#define FM5_SYSTEMUI_VT_ADDREF             1u
#define FM5_SYSTEMUI_VT_RELEASE            2u
#define FM5_SYSTEMUI_VT_GET_IIDS           3u
#define FM5_SYSTEMUI_VT_RUNTIME_NAME       4u
#define FM5_SYSTEMUI_VT_TRUST_LEVEL        5u
/* ISystemUIStatics: slot 8 (offset 0x40) é ShowAccountPickerAsync. */
#define FM5_SYSTEMUI_VT_SHOW_ACCOUNT_PICKER 8u
/* IAsyncOperation<AccountPickerResult*>. */
#define FM5_ASYNC_VT_PUT_COMPLETED         6u
#define FM5_ASYNC_VT_GET_COMPLETED         7u
#define FM5_ASYNC_VT_GET_RESULTS           8u
#define FM5_ASYNC_VT_GET_ID                9u
#define FM5_ASYNC_VT_GET_STATUS            10u
#define FM5_ASYNC_VT_GET_ERROR_CODE        11u
#define FM5_ASYNC_VT_CANCEL                12u
#define FM5_ASYNC_VT_CLOSE                 13u
/* IAccountPickerResult. */
#define FM5_RESULT_VT_GET_USER             6u
#define FM5_RESULT_VT_GET_OPERATION        7u

/* Valores de convenção WinRT espelhados pela bridge. */
#define FM5_ASYNC_STATUS_COMPLETED         1
#define FM5_ACCOUNT_OPERATION_COMPLETED    0u
#define FM5_TRUST_LEVEL_BASE               0

/* GUID ISystemUIStatics {1a0dd80e-3f9d-4cfa-8e50-0e2ebd1aa72f} em layout de
 * memória (Data1/Data2/Data3 little-endian). */
extern const uint8_t fm5_systemui_iid_statics[16];

typedef void (*fm5_systemui_addref_fn)(void *obj);

/* Provider do User nativo do Player 2 (materializado sob demanda pela camada
 * Windows). Em teste devolve sentinela determinístico. */
typedef void *(*fm5_systemui_user_provider)(void *ctx);

/*
 * TICKET-HARNESS-166 — observador da chamada ShowAccountPickerAsync.
 *
 * Recebe o `controller` exatamente como o jogo entregou. A camada Windows usa
 * esse gancho para extrair a chave canônica (`*(controller + 0x18)`) e marcar
 * o dispositivo como Player 2 na máquina de cascata, logando a decisão em
 * fm5_p2_hook.log.
 */
typedef void (*fm5_systemui_controller_observer)(void *ctx, void *controller);

/* Assinaturas genéricas de IUnknown/IInspectable, compartilhadas pelas três
 * vtables (o layout de function pointers é idêntico). */
typedef int32_t (*fm5_systemui_qi_fn)(void *self, const void *riid, void **out);
typedef uint32_t (*fm5_systemui_ref_fn)(void *self);
typedef int32_t (*fm5_systemui_get_iids_fn)(void *self, uint32_t *out_count,
                                            void **out_iids);
typedef int32_t (*fm5_systemui_get_name_fn)(void *self, void **out_name);
typedef int32_t (*fm5_systemui_get_trust_fn)(void *self, int32_t *out_level);
/* Invoke de um delegate WinRT (IUnknown ocupa 0..2; Invoke é o slot 3). */
typedef int32_t (*fm5_systemui_invoke_fn)(void *self, void *sender,
                                          void *args);

/* ------------------------------------------------------------------------- */
/* Vtables sintetizadas                                                      */
/* ------------------------------------------------------------------------- */

typedef struct fm5_systemui_statics_vt {
    fm5_systemui_qi_fn        query_interface;      /* 0 */
    fm5_systemui_ref_fn       add_ref;              /* 1 */
    fm5_systemui_ref_fn       release;              /* 2 */
    fm5_systemui_get_iids_fn  get_iids;             /* 3 */
    fm5_systemui_get_name_fn  get_runtime_class;    /* 4 */
    fm5_systemui_get_trust_fn get_trust_level;      /* 5 */
    int32_t (*slot6)(void *self);                   /* 6 (reservado) */
    int32_t (*slot7)(void *self);                   /* 7 (reservado) */
    int32_t (*show_account_picker_async)(void *self, void *controller,
                                         void *options, void **out_async_op);
} fm5_systemui_statics_vt_t;

typedef struct fm5_async_op_vt {
    fm5_systemui_qi_fn        query_interface;      /* 0 */
    fm5_systemui_ref_fn       add_ref;              /* 1 */
    fm5_systemui_ref_fn       release;              /* 2 */
    fm5_systemui_get_iids_fn  get_iids;             /* 3 */
    fm5_systemui_get_name_fn  get_runtime_class;    /* 4 */
    fm5_systemui_get_trust_fn get_trust_level;      /* 5 */
    int32_t (*put_completed)(void *self, void *handler);   /* 6 */
    int32_t (*get_completed)(void *self, void **out);      /* 7 */
    int32_t (*get_results)(void *self, void **out);        /* 8 */
    uint32_t (*get_id)(void *self);                        /* 9 */
    int32_t (*get_status)(void *self);                     /* 10 */
    int32_t (*get_error_code)(void *self, int32_t *out);   /* 11 */
    int32_t (*cancel)(void *self);                         /* 12 */
    int32_t (*close)(void *self);                          /* 13 */
} fm5_async_op_vt_t;

typedef struct fm5_account_result_vt {
    fm5_systemui_qi_fn        query_interface;      /* 0 */
    fm5_systemui_ref_fn       add_ref;              /* 1 */
    fm5_systemui_ref_fn       release;              /* 2 */
    fm5_systemui_get_iids_fn  get_iids;             /* 3 */
    fm5_systemui_get_name_fn  get_runtime_class;    /* 4 */
    fm5_systemui_get_trust_fn get_trust_level;      /* 5 */
    int32_t (*get_user)(void *self, void **out_user);      /* 6 */
    int32_t (*get_operation)(void *self, uint32_t *out_op);/* 7 */
} fm5_account_result_vt_t;

/* ------------------------------------------------------------------------- */
/* Objetos e estado da bridge                                                */
/* ------------------------------------------------------------------------- */

typedef struct fm5_systemui {
    fm5_systemui_user_provider user_provider;
    void                      *user_ctx;
    fm5_systemui_addref_fn     user_addref;
    fm5_systemui_controller_observer controller_observer;
    void                      *controller_observer_ctx;
    uint32_t                   next_async_id;
    uint32_t                   activations;          /* fábricas entregues */
    uint32_t                   account_picker_calls; /* ShowAccountPickerAsync */
} fm5_systemui_t;

typedef struct fm5_systemui_statics {
    const fm5_systemui_statics_vt_t *vt;
    uint32_t                         refcount;
    fm5_systemui_t                  *owner;
} fm5_systemui_statics_t;

typedef struct fm5_async_op {
    const fm5_async_op_vt_t *vt;
    uint32_t                 refcount;
    fm5_systemui_t          *owner;
    void                    *completed_handler;
    void                    *result;   /* IAccountPickerResult em cache */
    uint32_t                 id;
} fm5_async_op_t;

typedef struct fm5_account_result {
    const fm5_account_result_vt_t *vt;
    uint32_t                       refcount;
    fm5_systemui_t                *owner;
} fm5_account_result_t;

/* ------------------------------------------------------------------------- */
/* API                                                                       */
/* ------------------------------------------------------------------------- */

/* Zera o estado da bridge. Idempotente. */
void fm5_systemui_init(fm5_systemui_t *ui);

/* Liga a fonte do User do Player 2 (provider + AddRef). `addref` pode ser NULL
 * em teste quando não se deseja contabilizar referências. */
void fm5_systemui_set_user_source(fm5_systemui_t *ui,
                                  fm5_systemui_user_provider provider,
                                  void *ctx,
                                  fm5_systemui_addref_fn addref);

/* TICKET-HARNESS-166 — registra o observador de ShowAccountPickerAsync (pode
 * ser NULL para desligar). `ctx` é repassado a cada chamada. */
void fm5_systemui_set_controller_observer(
    fm5_systemui_t *ui, fm5_systemui_controller_observer cb, void *ctx);

/* 1 quando `class_name` é exatamente "Windows.Xbox.UI.SystemUI". */
int fm5_systemui_class_matches(const wchar_t *class_name);

/* 1 quando `iid` é o GUID de ISystemUIStatics ou NULL (tolerância de ABI). */
int fm5_systemui_iid_matches(const void *iid);

/*
 * Tenta ativar a classe.
 *   - 0 => não é Windows.Xbox.UI.SystemUI: o chamador DEVE delegar à função
 *          original de RoGetActivationFactory;
 *   - 1 => é a classe: *out_hr recebe o HRESULT final e, quando S_OK,
 *          *out_factory recebe a ISystemUIStatics virtual.
 * `out_hr` é obrigatório (sem ele a ativação é ignorada com retorno 1).
 */
int fm5_systemui_try_activate(fm5_systemui_t *ui, const wchar_t *class_name,
                              const void *iid, void **out_factory,
                              int32_t *out_hr);

/* Cria a fábrica ISystemUIStatics (assume classe/IID já validados). */
int32_t fm5_systemui_create_statics(fm5_systemui_t *ui, const void *iid,
                                    void **out_factory);

/* AddRef/Release genéricos de um objeto COM (usam vtable[1]/vtable[2]). */
uint32_t fm5_systemui_addref_object(void *obj);
uint32_t fm5_systemui_release_object(void *obj);

#ifdef __cplusplus
}
#endif

#endif /* FM5_SYSTEMUI_H */
