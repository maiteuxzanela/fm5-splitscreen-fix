/*
 * fm5_hooks.c — hooks WinRT do Azimuth 1.0.4 para habilitar Player 2.
 *
 * Alvos (VA = image base 0x140000000 + RVA):
 *   Controller::get_User              RVA 0x19a4c0  (patch 14, rel32 @ 9)
 *   UserStatics::get_Users            RVA 0x0424a0  (patch 15)
 *   UserDisplayInfo::get_DisplayName  RVA 0x041d10  (patch 16)
 *   UserStatics::GetUserById          RVA 0x042580  (patch 15)
 *   UserStatics vtable[6] (contagem)  RVA 0x042480  (patch 17) -> devolve N
 *   UserStatics vtable[7] (add evt)   RVA 0x0425c0  (patch 16, rel32 @ -1)
 *   UserStatics vtable[8] (del evt)   RVA 0x0425e0  (patch 18, rel32 @ 13)
 *   User vtable[6] (get_Id)           RVA 0x041f70  (patch 20) -> id 1-based
 *   GamepadReading (comum)            RVA 0x04b18c0 (patch 15) -> Menu/View
 *
 *   (TICKET-HARNESS-160) 0x19a5c0 e 0x19a690 (as duas variantes de
 *   Gamepad::GetCurrentReading) convergem para 0x4b18c0, que preenche a
 *   leitura via conversão DirectInput 0x4b0c40. O hook recompõe Buttons.
 *
 * Helpers do exe reutilizados (mesma ABI, mesma alocação):
 *   UserStatics singleton    RVA 0x42980
 *   operator new             RVA 0x6057e4
 *   operator new[]           RVA 0xdf90
 *   User factory             RVA 0x41f00
 *   HSTRING maker            RVA 0x17f310
 *
 * O build 1.0.4 responde GetUserById SOMENTE para id == 1 e devolve o literal
 * 1 nos dois slots 6 (UserStatics e User). Para o Player 2 existir de verdade
 * o hook: (a) serve o virtual em GetUserById(id>=2); (b) expõe a contagem;
 * (c) faz User::get_Id devolver o id 1-based correto da instância; (d) dispara
 * os handlers de UserAdded capturados da vtable[7] (e removidos na vtable[8]).
 *
 * Tudo fail-closed: assinatura divergente => hook ignorado, jogo intacto.
 */
#include "fm5_hooks.h"
#include "fm5_buttons.h"
#include "fm5_detour.h"
#include "fm5_event_shield.h"
#include "fm5_event_shield_encode.h"
#include "fm5_visibility_shield.h"
#include "fm5_visibility_shield_encode.h"
#include "fm5_patch_bytes.h"
#include "fm5_identity.h"
#include "fm5_native_user.h"
#include "fm5_pairing.h"
#include "fm5_systemui.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* ------------------------------------------------------------------------- */
/* RVAs do azimuth.exe 1.0.4                                                 */
/* ------------------------------------------------------------------------- */
#define RVA_GET_USER           0x19a4c0u
#define RVA_GET_USERS          0x0424a0u
#define RVA_GET_DISPLAY_NAME   0x041d10u
#define RVA_GET_USER_BY_ID     0x042580u
#define RVA_USER_COUNT         0x042480u
#define RVA_USER_ADDED_ADD     0x0425c0u
#define RVA_USER_ADDED_REMOVE  0x0425e0u
#define RVA_USER_GET_ID        0x041f70u

/* TICKET-HARNESS-160: leitura de Gamepad. 0x19a5c0 e 0x19a690 (as duas
 * variantes de Gamepad::GetCurrentReading) convergem para 0x4b18c0, que
 * preenche um GamepadReading com o resultado da conversão DirectInput
 * (0x4b0c40). Hookamos o ponto comum para recompor Buttons (Menu/View). */
#define RVA_GET_READING        0x04b18c0u

/* ------------------------------------------------------------------------- */
/* Blindagem do carregamento de corrida (crash 0xC0000005 em 0x140687f4c)    */
/* ------------------------------------------------------------------------- */
/*
 * Forense (logs/steam-0.log, 2026-11-10, Azimuth 1.0.4 + título 1.0.0.20):
 *   WndProc (WM_ACTIVATE) -> CoreWindow::WindowActivated -> handler do Forza
 *   em 0x1405d7500 (RVA 0x5d7500) -> EventQueue::PostEvent(25, 6, event)
 *   -> 0x140687f4c, com rax == 0:
 *       0x140687f48: 48 8b 41 08   mov rax,[rcx+8]
 *       0x140687f4c: 48 89 08      mov [rax],rcx     ; escrita em 0x0
 *
 * MÓDULO ALVO: o rip do crash NÃO pertence ao azimuth.exe (wrapper), e sim ao
 * executável do TÍTULO — Game/Mount/forza_durango_release_final.exe — que o
 * Azimuth mapeia em memória na base preferida 0x140000000 (mapa manual: não
 * aparece em GetModuleHandle/EnumProcessModules). Os bytes do arquivo do título
 * batem byte-a-byte com a instrução do crash e com o unwind info registrado:
 *   RVA 0x5d7500..0x5d75d8  (unwind em 0x2024bf4)  -> handler WindowActivated
 *   RVA 0x687e20..0x687f96  (unwind em 0x204673c)  -> EventQueue::PostEvent
 *
 * O carregamento da corrida não pode ser desestabilizado por uma notificação
 * de ativação de janela: o Azimuth é um wrapper de jogo de console e o título
 * não depende de WM_ACTIVATE no meio da transição. O hook devolve S_OK (0) e
 * NÃO chama o trampolim, portanto o evento 25/6 nunca é postado na fila.
 */
#define RVA_WINDOW_ACTIVATED   0x5d7500u   /* handler WindowActivated        */
#define RVA_EVENT_QUEUE_LINK   0x687f48u   /* mov rax,[rcx+8]; mov [rax],rcx */

/* ------------------------------------------------------------------------- */
/* Blindagem da Visibility Thread (crash 0xC0000005 em 0x1408595e0, T0344)    */
/* ------------------------------------------------------------------------- */
/*
 * Forense (logs/steam-0.log, 2026-11-10, título 1.0.0.20):
 *   28122.039:0154:0344 c0000005 addr=0x1408595e0; info[1]=0x3FFFFFFFFF0
 *   rdx=0x40000000018 (_Mylast) r8=0x40000101410 (where > _Mylast)
 *   unwind func 859500-859637 (vector::insert)
 * Em split-screen a quantidade de modelos visíveis satura o vetor global de
 * visibilidade (0x1424717d0). O descarte do pior item deixa where > _Mylast;
 * `_Mylast - where` fica negativo e o `jae` (unsigned) em 0x859516 salta para
 * o laço de cópia para trás (0x8595e0), que desce 16 bytes por iteração até o
 * piso 0x40000000000-0x10 e derruba 4 threads em cadeia.
 *
 * RVA_VISIBILITY_INSERT: fronteira da função e 8-byte aligned — o E9 da trava
 *   where/_Mylast é publicado com um único store de 64 bits (sem patch rasgado).
 * RVA_VISIBILITY_BRANCH: `0f 83` (JAE unsigned) -> `0f 8d` (JGE signed) com
 *   store atômico de 16 bits.
 */
#define RVA_VISIBILITY_INSERT  0x859500u
#define RVA_VISIBILITY_BRANCH  0x859516u

/* Base preferida do executável do título (PE ImageBase = 0x140000000). O
 * Azimuth o mapeia manualmente nessa base; o override FM5_P2_GAME_BASE cobre
 * um mapa realocado (diagnóstico de campo). */
#define FM5_GAME_PREFERRED_BASE 0x140000000ULL
#define FM5_GAME_MODULE_NAME    "forza_durango_release_final.exe"

/* TICKET-HARNESS-165: slot da IAT de RoGetActivationFactory no azimuth.exe
 * 1.0.4 (importado de api-ms-win-core-winrt-l1-1-0.dll). O jogo chama
 * ShowAccountPickerAsync -> RoGetActivationFactory("Windows.Xbox.UI.SystemUI")
 * e o Azimuth devolve REGDB_E_CLASSNOTREG, abortando a entrada do Player 2. */
#define RVA_IAT_ROGETACTIVATIONFACTORY 0x68e8c0u

#define RVA_USER_STATICS       0x042980u

#define RVA_OPERATOR_NEW       0x6057e4u
#define RVA_OPERATOR_NEW_ARR   0x00df90u
#define RVA_USER_FACTORY       0x041f00u
#define RVA_MAKE_HSTRING       0x17f310u

#define RVA_VT_VIEW_MAIN       0x6c09d0u  /* Azimuth.OfflineUserView        */
#define RVA_VT_VIEW_ITER       0x6c0720u  /* iterator view interface        */
#define RVA_STR_VIEW_CLASS     0x6c0638u  /* "Azimuth.OfflineUserView"      */
#define RVA_STR_ITER_CLASS     0x6c0668u  /* "Azimuth.OfflineUserIterator"  */

/* ------------------------------------------------------------------------- */
/* TICKET-HARNESS-168 — identidade Guest + ControllerPairingChanged          */
/* ------------------------------------------------------------------------- */
/* vtable de User (0x6c0b48) do build 1.0.4: slots 10/14/15 são, na ordem,
 * get_IsGuest, get_XboxUserHash e get_XboxUserId. Patchamos os SLOTS (e não os
 * corpos das funções) porque são propriedades puras da interface: o corpo
 * nativo continua intacto e é chamado pelo nosso handler para o Player 1. */
#define RVA_VT_USER             0x6c0b48u
#define RVA_USER_IS_GUEST       0x042080u
#define RVA_USER_XBOX_USER_HASH 0x042100u
#define RVA_USER_XBOX_USER_ID   0x042150u
#define USER_VT_IS_GUEST        10
#define USER_VT_XBOX_USER_HASH  14
#define USER_VT_XBOX_USER_ID    15

/* vtable de ControllerStatics (0x6ed8b8): slots 7..12 são add/remove de
 * ControllerAdded (7/8), ControllerRemoved (9/10) e ControllerPairingChanged
 * (11/12). Os add thunks têm ABI (self, handler, token*) e os remove
 * (self, token) — verificados no desmonte do exe. */
#define RVA_VT_CONTROLLER_STATICS 0x6ed8b8u
#define RVA_CTRL_STATICS_SINGLETON 0x19be70u
#define RVA_CTRL_ADDED_ADD        0x19b9c0u
#define RVA_CTRL_ADDED_REMOVE     0x19b9e0u
#define RVA_CTRL_REMOVED_ADD      0x19ba00u
#define RVA_CTRL_REMOVED_REMOVE   0x19ba20u
#define RVA_CTRL_PAIRING_ADD      0x19ba40u
#define RVA_CTRL_PAIRING_REMOVE   0x19ba60u

/* User* UserStatics::MakeAccountPickerUser(void) — devolve em RAX o User do
 * Player 1 nativo já com AddRef (vt[1]) e prologue de 16 bytes. */
#define RVA_MAKE_ACCOUNT_PICKER_USER 0x4c8030u

#define USER_REFCOUNT_OFFSET   0x08u
#define USER_CLASSNAME_OFFSET  0x10u
#define USER_INNER_OFFSET      0x18u
#define STATICS_USER_OFFSET    0x18u
#define VIEW_REFCOUNT_OFFSET   0x10u
#define VIEW_CLASSNAME_OFFSET  0x18u

#define FM5_P2_MAX_EVENT_HANDLERS 16

/* Assinaturas dos prologues (bytes reais do build 1.0.4). */
static const uint8_t EXPECT_GET_USER[14] = {
    0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xda, 0xe8, 0xb2, 0x84,
    0xea, 0xff
};
static const uint8_t EXPECT_GET_USERS[15] = {
    0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89,
    0x7c, 0x24, 0x20
};
static const uint8_t EXPECT_DISPLAY_NAME[16] = {
    0x48, 0x89, 0x5c, 0x24, 0x10, 0x48, 0x89, 0x7c, 0x24, 0x18, 0x41, 0x56,
    0x48, 0x83, 0xec, 0x20
};
/* sub rsp,0x28; cmp edx,1; jne +6; mov rcx,[rcx+0x18]; jmp +2 */
static const uint8_t EXPECT_GET_USER_BY_ID[15] = {
    0x48, 0x83, 0xec, 0x28, 0x83, 0xfa, 0x01, 0x75, 0x06, 0x48, 0x8b, 0x49,
    0x18, 0xeb, 0x02
};
/* test rdx,rdx; jne +6; mov eax,E_POINTER; ret; mov dword [rdx],1 */
static const uint8_t EXPECT_USER_COUNT[17] = {
    0x48, 0x85, 0xd2, 0x75, 0x06, 0xb8, 0x03, 0x40, 0x00, 0x80, 0xc3, 0xc7,
    0x02, 0x01, 0x00, 0x00, 0x00
};
/* sub rsp,0x28; add rcx,0x20; mov r9,r8; mov r8,rdx; xor edx,edx */
static const uint8_t EXPECT_USER_ADDED_ADD[16] = {
    0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xc1, 0x20, 0x4d, 0x8b, 0xc8, 0x4c,
    0x8b, 0xc2, 0x33, 0xd2
};
/* sub rsp,0x28; add rcx,0x20; mov r8,rdx; xor edx,edx; call rel32 */
static const uint8_t EXPECT_USER_ADDED_REMOVE[18] = {
    0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xc1, 0x20, 0x4c, 0x8b, 0xc2, 0x33,
    0xd2, 0xe8, 0xae, 0x11, 0x00, 0x00
};
/* test rdx,rdx; jne +6; mov eax,E_POINTER; ret; mov dword [rdx],1; xor; ret */
static const uint8_t EXPECT_USER_GET_ID[20] = {
    0x48, 0x85, 0xd2, 0x75, 0x06, 0xb8, 0x03, 0x40, 0x00, 0x80, 0xc3, 0xc7,
    0x02, 0x01, 0x00, 0x00, 0x00, 0x33, 0xc0, 0xc3
};
/* TICKET-HARNESS-160: prologue de GamepadReading comum (0x4b18c0).
 * 15 bytes = mov [rsp+0x10],rbx; push rbp; push rsi; push rdi; push r14;
 * push r15; mov rbp,rsp — termina em fronteira de instrução exata (o byte
 * seguinte é `sub rsp,0x70`), sem rel32/rel8 nem RIP-relativo no trecho. */
static const uint8_t EXPECT_GET_READING[15] = {
    0x48, 0x89, 0x5c, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8b, 0xec
};

/* TICKET-HARNESS-168: prologue de UserStatics::MakeAccountPickerUser
 * (0x4c8030) — push rbx; sub rsp,0x20; call rel32(UserStatics);
 * nop; mov rbx,[rax+0x18]. 16 bytes terminam em fronteira de instrução e o
 * retry point (target+16) é `test rbx,rbx`, então o rel32 em +6 é o único
 * elemento relocável do trecho. */
static const uint8_t EXPECT_MAKE_ACCOUNT_PICKER[16] = {
    0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0xe8, 0x45, 0xa9, 0xb7, 0xff, 0x90,
    0x48, 0x8b, 0x58, 0x18
};

/* Blindagem do carregamento: prologue REAL do handler WindowActivated do
 * título (Game/Mount/forza_durango_release_final.exe, RVA 0x5d7500):
 *   push rdi; sub rsp,0x50;
 *   mov qword [rsp+0x30],-2; mov [rsp+0x60],rbx
 * 15 bytes = fronteira de instrução exata (o byte +15 é `mov [rsp+0x60],rbx`),
 * então o trampolim, se um dia usado, retomaria em código válido. */
static const uint8_t EXPECT_WINDOW_ACTIVATED[15] = {
    0x40, 0x57, 0x48, 0x83, 0xEC, 0x50, 0x48, 0xC7, 0x44, 0x24, 0x30, 0xFE,
    0xFF, 0xFF, 0xFF
};

/* ------------------------------------------------------------------------- */
/* Estado global                                                             */
/* ------------------------------------------------------------------------- */
static uint8_t        *g_base;       /* azimuth.exe (wrapper)                  */
static uint8_t        *g_game_base;  /* executavel do TITULO (mapa manual)     */
static fm5_identity_t  g_identity;
static wchar_t         g_p2_tag_w[FM5_P2_TAG_MAX];
static int             g_ready;

/* TICKET-HARNESS-165 — estado da bridge Windows.Xbox.UI.SystemUI. */
static fm5_systemui_t g_systemui;
static void         **g_ro_factory_slot;     /* endereço do slot IAT */
static void          *g_orig_ro_factory;     /* RoGetActivationFactory real */
/* WindowsGetStringRawBuffer, resolvida em combase.dll em runtime. */
typedef const wchar_t *(*get_string_raw_fn)(void *hstring, uint32_t *length);
static get_string_raw_fn g_get_string_raw;

static fm5_hook_t      g_hook_get_user;
static fm5_hook_t      g_hook_get_users;
static fm5_hook_t      g_hook_display_name;
static fm5_hook_t      g_hook_get_user_by_id;
static fm5_hook_t      g_hook_user_count;
static fm5_hook_t      g_hook_user_get_id;
static fm5_hook_t      g_hook_user_added_add;
static fm5_hook_t      g_hook_user_added_remove;
static fm5_hook_t      g_hook_get_reading;
/* Blindagem do carregamento: handler WindowActivated neutralizado + guarda
 * anti-NULL da fila de eventos (rearme se o decriptador sobrescrever). */
static fm5_hook_t      g_hook_window_activated;
/* 0 = primeira tentativa, 1 = "assinatura rejeitada" já logado, 2 = ativo. */
static volatile LONG   g_loading_shield_logged;
/* Mesma semântica para a blindagem de visibilidade (Thread 0344). */
static volatile LONG   g_visibility_shield_logged;
/* Limite de rearmes do handler (cada fm5_hook_install aloca um trampolim):
 * mapeador patológico que reescreve a cada frame não pode virar vazamento. */
#define FM5_WINDOW_REARM_MAX 8
static int             g_window_rearm_count;

typedef HRESULT (*get_user_fn)(void *self, void **out);
typedef HRESULT (*get_users_fn)(void *self, void **out);
typedef HRESULT (*get_name_fn)(void *self, void **out);
typedef HRESULT (*get_user_by_id_fn)(void *self, uint32_t user_id, void **out);
typedef HRESULT (*user_count_fn)(void *self, uint32_t *out);
typedef HRESULT (*get_id_fn)(void *self, uint32_t *out);
typedef HRESULT (*event_add_fn)(void *self, void *handler, uint64_t *token);
typedef HRESULT (*event_remove_fn)(void *self, uint64_t token);
/* 0x4b18c0 devolve o GamepadReading por ponteiro oculto (rcx) e o dispositivo
 * em rdx; retorna o próprio ponteiro da leitura em rax. */
typedef void *(*get_reading_fn)(void *retbuf, void *device);

static get_user_fn  g_orig_get_user;
static get_users_fn g_orig_get_users;
static get_name_fn  g_orig_display_name;
/* Só os dois thunks de evento precisam do original (o resto é self-contained). */
static event_add_fn    g_orig_user_added_add;
static event_remove_fn g_orig_user_added_remove;
static get_reading_fn  g_orig_get_reading;

/* TICKET-HARNESS-168 — vtable de User (propriedades Guest). */
typedef HRESULT (*bool_getter_fn)(void *self, uint8_t *out);
typedef HRESULT (*hstring_getter_fn)(void *self, void **out);
typedef void *(*make_picker_user_fn)(void);

static bool_getter_fn    g_orig_user_is_guest;
static hstring_getter_fn g_orig_user_xbox_user_hash;
static hstring_getter_fn g_orig_user_xbox_user_id;
static int               g_user_vt_patched;

/* TICKET-HARNESS-168 — captura dos eventos de ControllerStatics. */
enum {
    FM5_CTRL_EV_ADDED = 0,
    FM5_CTRL_EV_REMOVED = 1,
    FM5_CTRL_EV_PAIRING = 2,
    FM5_CTRL_EV_COUNT = 3
};

static SRWLOCK  g_ctrl_evt_lock = SRWLOCK_INIT;
static void    *g_ctrl_evt_handler[FM5_CTRL_EV_COUNT][FM5_P2_MAX_EVENT_HANDLERS];
static uint64_t g_ctrl_evt_token[FM5_CTRL_EV_COUNT][FM5_P2_MAX_EVENT_HANDLERS];
static int      g_ctrl_evt_count[FM5_CTRL_EV_COUNT];
static int      g_ctrl_vt_patched;
static int      g_pairing_event_disabled;

/*
 * TICKET-HARNESS-170 — tabela dev_key -> Controller* REAL.
 *
 * O handler do exe lê `args->vtable[6]` e trata o retorno como Controller*
 * (0x140675e81 -> [event+0x18]); o despachante 0x140675880 entrega esse value
 * em rdx para 0x1406763a0, que percorre os 8 slots do Forza (stride 0x1300),
 * compara [slot+0x70] com o Controller* e só então grava o User* em
 * [slot+0x78]. Ou seja: sem o Controller* REAL do dispositivo o evento não
 * atualiza nada (aborta quando rdx é NULL/sem correspondência).
 *
 * A fonte do ponteiro é o próprio `self` de hook_get_user (Controller* do
 * Forza) e o `controller` de ShowAccountPickerAsync. Guardamos a associação
 * por chave canônica de device com uma referência forte (AddRef) e devolvemos
 * uma referência nova a cada consulta (Release obrigatório pelo chamador).
 */
#define FM5_CTRL_BINDINGS 32
typedef struct fm5_ctrl_binding {
    void *dev_key;     /* chave canônica: *(controller + 0x18)            */
    void *controller;  /* Controller* REAL (referência forte nossa)       */
} fm5_ctrl_binding_t;

static fm5_ctrl_binding_t g_ctrl_binding[FM5_CTRL_BINDINGS];
static int                g_ctrl_binding_count;
static SRWLOCK            g_ctrl_binding_lock = SRWLOCK_INIT;

/* TICKET-HARNESS-168 — hook de UserStatics::MakeAccountPickerUser. */
static fm5_hook_t        g_hook_account_picker;
static make_picker_user_fn g_orig_account_picker;

/* TICKET-HARNESS-160: correção do bitmask de botões. */
static int g_swap_start_back;

#define FM5_BTN_TRACK 16
typedef struct fm5_btn_state {
    void    *device;
    uint32_t last;
} fm5_btn_state_t;
static fm5_btn_state_t g_btn_state[FM5_BTN_TRACK];
static SRWLOCK         g_btn_lock = SRWLOCK_INIT;

/* Handlers WinRT de UserAdded capturados da vtable[7] (+0x20 do UserStatics). */
static SRWLOCK   g_evt_lock = SRWLOCK_INIT;
static void     *g_evt_handler[FM5_P2_MAX_EVENT_HANDLERS];
static uint64_t  g_evt_token[FM5_P2_MAX_EVENT_HANDLERS];
static int       g_evt_count;
static int       g_evt_hooks_ok;      /* add E remove instalados */
static int       g_user_added_disabled;

/*
 * TICKET-HARNESS-166 — chave canônica de dispositivo.
 *
 * Diagnóstico forense (azimuth.exe 1.0.4): Controller::get_Id (RVA 0x19a420) e
 * o construtor em 0x19a8a6 mostram que `*(void **)((uint8_t *)self + 0x18)`
 * dentro do IController* recebido por get_User é EXATAMENTE o mesmo `void
 * *device` (1, 2, 3...) que o jogo passa em rdx para GamepadReading
 * (RVA 0x4b18c0). O jogo, porém, instancia NOVOS wrappers COM `Controller*` a
 * cada consulta de Gamepad::get_Gamepads (5+ ponteiros para os mesmos 3
 * devices), então parear por ordem de aparição (controller_rank vs.
 * device_rank) misturava os controles. Usamos o device id como chave
 * canônica nos dois hooks.
 *
 * A atribuição em CASCATA (TICKET-HARNESS-163) vive no núcleo de identidade:
 * todo controle nasce Player 1 (índice 0), o primeiro A elege o P1 definitivo e
 * promove o secundário a Player 2 VIRTUAL (índice 1, TICKET-HARNESS-171), e o
 * primeiro Start no lobby confirma o P2 definitivo (User virtual + UserAdded),
 * movendo os demais para os índices 2, 3, ...
 */
#define FM5_CONTROLLER_DEVICE_OFFSET 0x18u

/* Dispositivos donos de cada vaga (espelho de diagnóstico da máquina). */
static void    *g_p1_device;
static void    *g_p2_device;
static SRWLOCK  g_join_lock = SRWLOCK_INIT;


/* ------------------------------------------------------------------------- */
/* Logging mínimo                                                            */
/* ------------------------------------------------------------------------- */
static void fm5_log(const char *fmt, ...)
{
    char path[MAX_PATH];
    char line[512];
    DWORD len;
    HANDLE f;
    va_list ap;
    DWORD n;

    if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
        return;
    }
    {
        char *slash = strrchr(path, '\\');
        if (slash) {
            slash[1] = '\0';
        }
    }
    if (strlen(path) + 14 >= sizeof(path)) {
        return;
    }
    strcat(path, "fm5_p2_hook.log");

    va_start(ap, fmt);
    vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    len = (DWORD)strlen(line);
    line[len++] = '\r';
    line[len++] = '\n';

    f = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        return;
    }
    SetFilePointer(f, 0, NULL, FILE_END);
    WriteFile(f, line, len, &n, NULL);
    CloseHandle(f);
}

/* ------------------------------------------------------------------------- */
/* Blindagem do carregamento de corrida                                      */
/* ------------------------------------------------------------------------- */
/*
 * Handler substituto de 0x1405d7500 (WindowActivated do TÍTULO). O jogo
 * original monta o evento 25/6 e chama EventQueue::PostEvent, que durante a
 * reciclagem da fila pode encontrar `next == NULL` e escrever em 0x0 (crash
 * EXCEPTION_ACCESS_VIOLATION em 0x140687f4c). Como o Azimuth não depende da
 * ativação de janela durante o carregamento, o handler apenas devolve S_OK —
 * sem trampolim e sem postar nada.
 */
static int32_t hook_window_activated(void *self, void *args)
{
    (void)self;
    (void)args;
    /* Defesa em profundidade: garante a guarda anti-NULL da fila e a
     * blindagem da Visibility Thread (ambas idempotentes/fail-closed). */
    if (g_game_base) {
        (void)fm5_event_shield_install(g_game_base);
        (void)fm5_visibility_shield_install(g_game_base);
    }
    return 0; /* S_OK */
}

/* A página precisa estar legível para o memcmp de assinatura (a base do
 * título é um mapa manual: nunca leia às cegas). */
static int page_is_readable(void *addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    DWORD prot;

    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) {
        return 0;
    }
    if (mbi.State != MEM_COMMIT) {
        return 0;
    }
    prot = mbi.Protect & 0xFFu;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
        return 0;
    }
    return prot == PAGE_READONLY || prot == PAGE_READWRITE ||
           prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
           prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
}

/* A base candidata é MESMO o título? Exige as duas assinaturas do build
 * 1.0.0.20: o prologue do handler e a sequência do crash na fila. */
static int game_signature_ok(uint8_t *base)
{
    if (!base) {
        return 0;
    }
    if (!page_is_readable(base + RVA_EVENT_QUEUE_LINK) ||
        !page_is_readable(base + RVA_WINDOW_ACTIVATED)) {
        return 0;
    }
    if (!fm5_shield_is_original(base + RVA_EVENT_QUEUE_LINK)) {
        return 0;
    }
    return memcmp(base + RVA_WINDOW_ACTIVATED, EXPECT_WINDOW_ACTIVATED,
                  sizeof(EXPECT_WINDOW_ACTIVATED)) == 0;
}

/*
 * Resolve a base do executável do título (mapa manual do Azimuth, invisível
 * para GetModuleHandle). Ordem: override de campo -> módulo real (caso algum
 * dia seja carregado por LoadLibrary) -> base preferida 0x140000000.
 * Fail-closed: só devolve uma base cujas assinaturas batem.
 */
static uint8_t *resolve_game_base(void)
{
    const char *env;
    HMODULE mod;
    uint8_t *cand;

    env = getenv("FM5_P2_GAME_BASE");
    if (env && env[0]) {
        uintptr_t v = (uintptr_t)strtoull(env, NULL, 0);
        cand = (uint8_t *)v;
        if (game_signature_ok(cand)) {
            return cand;
        }
        fm5_log("P2: FM5_P2_GAME_BASE=%s nao contem as assinaturas do titulo "
                "1.0.0.20 — ignorado (fail-closed)", env);
    }

    mod = GetModuleHandleA(FM5_GAME_MODULE_NAME);
    if (mod && game_signature_ok((uint8_t *)mod)) {
        return (uint8_t *)mod;
    }

    cand = (uint8_t *)(uintptr_t)FM5_GAME_PREFERRED_BASE;
    if (game_signature_ok(cand)) {
        return cand;
    }
    return NULL;
}

/*
 * Estado do salto do handler:
 *   1  = salto de 14 bytes instalado e íntegro (destino == hook_window_activated);
 *   0  = prologue sobrescrito (rearmar);
 *  -1  = base ausente/ilegível (não ler, não patchear).
 *
 * O salto REALMENTE instalado por fm5_hook_install é o `jmp qword ptr [rip+0]`
 * de fm5_encode_abs_jmp (FF 25 00 00 00 00 + endereço absoluto), NUNCA um E9:
 * a sonda antiga (0xE9) dava "sobrescrito" sempre e queimava o rearme.
 * A comparação usa o MESMO encoder da instalação, então não há sentinela
 * duplicado para divergir. A leitura exige página legível (mapa manual).
 */
static int window_hook_state(void)
{
    uint8_t expected[FM5_ABS_JMP_LEN];
    const uint8_t *p;

    if (!g_game_base) {
        return -1;
    }
    p = g_game_base + RVA_WINDOW_ACTIVATED;
    if (!page_is_readable((void *)p)) {
        return -1;
    }
    fm5_encode_abs_jmp(expected,
                       (uint64_t)(uintptr_t)g_hook_window_activated.hook_fn);
    return memcmp(p, expected, FM5_ABS_JMP_LEN) == 0;
}

/*
 * Configura (uma vez) e instala/rearma o hook do WindowActivated.
 *
 * PREMISSA DE ATOMICIDADE: fm5_hook_install publica o prologue de 15 bytes por
 * memcpy (motor pré-existente, não-atômico). Aqui isso é seguro porque o
 * dispatch de WindowActivated e a chamada de GamepadReading que rearma rodam na
 * MESMA thread de UI do Azimuth (WM_ACTIVATE chega pelo WndProc dessa thread);
 * nenhuma outra thread executa a entrada de 0x5d7500. Além disso a assinatura
 * é validada ANTES de escrever e a sonda window_hook_state exige o salto de 14
 * bytes completo com o destino correto, refazendo qualquer publicação
 * interrompida. (A guarda da fila 0x687f48 usa store atômico de 8 bytes.)
 */
static int ensure_window_hook(void)
{
    if (!g_game_base) {
        g_game_base = resolve_game_base();
        if (!g_game_base) {
            return -1; /* título ainda não mapeado pelo Azimuth */
        }
        fm5_log("P2: executavel do titulo resolvido em %p "
                "(base preferida 0x%llx)", (void *)g_game_base,
                (unsigned long long)FM5_GAME_PREFERRED_BASE);
        g_hook_window_activated.target = g_game_base + RVA_WINDOW_ACTIVATED;
    }
    if (!g_hook_window_activated.installed) {
        if (fm5_hook_install(&g_hook_window_activated) != 0) {
            return -2;
        }
        fm5_log("P2: handler WindowActivated neutralizado (S_OK sem "
                "EventQueue::PostEvent)");
        return 0;
    }
    /* O mapeador pode ter escrito por cima do salto: rearma. */
    switch (window_hook_state()) {
    case 0:
        if (g_window_rearm_count >= FM5_WINDOW_REARM_MAX) {
            break; /* desiste: evita vazamento de trampolins em loop */
        }
        if (fm5_hook_install(&g_hook_window_activated) == 0) {
            g_window_rearm_count++;
            fm5_log("P2: handler WindowActivated rearmado (mapeador "
                    "sobrescreveu o salto)");
        }
        break;
    case -1:
    default:
        /* Base ausente/ilegível: não insiste nem lê às cegas. */
        break;
    }
    return 0;
}

/*
 * Rearme barato (chamado a cada leitura de gamepad, alta frequência):
 *   - resolve a base do título no primeiro frame em que ela existe;
 *   - instala/rearma o handler WindowActivated;
 *   - instala a guarda anti-NULL da fila (independente do handler).
 * A sonda de byte do handler tem orçamento limitado: depois dos primeiros
 * frames ela para, para não ler uma base que o jogo possa desmapear no exit.
 */
static void rearm_loading_hooks(void)
{
    int hook_rc;

    if (!g_base) {
        return;
    }
    hook_rc = ensure_window_hook();
    if (hook_rc == -1) {
        return; /* título ainda não mapeado; tenta no próximo frame */
    }
    if (!g_game_base) {
        return;
    }
    /* Ativa OU sobrescrita pelo mapeador: install() reaplica o E9 na mesma
     * cave quando o alvo voltou à sequência original (re-detecção barata). */
    if (!fm5_event_shield_active() || !fm5_event_shield_intact()) {
        int rc = fm5_event_shield_install(g_game_base);
        if (rc == 0 || rc == 1) {
            if (InterlockedExchange(&g_loading_shield_logged, 2) != 2) {
                fm5_log("P2: blindagem do carregamento ativa — handler "
                        "WindowActivated (0x%05x) em S_OK e guarda NULL da "
                        "fila (0x%05x) instalada",
                        (unsigned)RVA_WINDOW_ACTIVATED,
                        (unsigned)RVA_EVENT_QUEUE_LINK);
            }
        } else if (rc == -2) {
            /* Loga só na transição para "rejeitada" (nunca a cada frame). */
            if (InterlockedExchange(&g_loading_shield_logged, 1) != 1) {
                fm5_log("P2: guarda NULL (0x%05x) rejeitada — assinatura "
                        "viva divergente do titulo 1.0.0.20 (fail-closed)",
                        (unsigned)RVA_EVENT_QUEUE_LINK);
            }
        }
    }
    /* Blindagem da Visibility Thread (crash 0x1408595e0): ativa OU reaplica
     * se o mapeador devolver os bytes originais em 0x859500/0x859516. */
    if (!fm5_visibility_shield_active() || !fm5_visibility_shield_intact()) {
        int vrc = fm5_visibility_shield_install(g_game_base);
        if (vrc == 0 || vrc == 1) {
            if (InterlockedExchange(&g_visibility_shield_logged, 2) != 2) {
                fm5_log("P2: blindagem de visibilidade ativa — vector::insert "
                        "(0x%05x) JGE assinado + trava where/_Mylast em "
                        "0x%05x (%s)",
                        (unsigned)RVA_VISIBILITY_BRANCH,
                        (unsigned)RVA_VISIBILITY_INSERT,
                        fm5_visibility_shield_guard_active()
                            ? "guarda armada" : "guarda indisponivel");
            }
        } else if (vrc == -2) {
            if (InterlockedExchange(&g_visibility_shield_logged, 1) != 1) {
                fm5_log("P2: blindagem de visibilidade (0x%05x) rejeitada — "
                        "assinatura viva divergente do titulo 1.0.0.20 "
                        "(fail-closed)", (unsigned)RVA_VISIBILITY_BRANCH);
            }
        }
    }
}

/* ------------------------------------------------------------------------- */
/* ABI helpers do exe                                                        */
/* ------------------------------------------------------------------------- */
static void *exe_operator_new(size_t size)
{
    typedef void *(*fn_t)(size_t);
    return ((fn_t)(g_base + RVA_OPERATOR_NEW))(size);
}

static void *exe_operator_new_arr(size_t size)
{
    typedef void *(*fn_t)(size_t);
    return ((fn_t)(g_base + RVA_OPERATOR_NEW_ARR))(size);
}

static void com_addref(void *obj)
{
    void **vt;
    if (!obj) {
        return;
    }
    vt = *(void ***)obj;
    if (vt && vt[1]) {
        typedef uint32_t (*addref_t)(void *);
        ((addref_t)vt[1])(obj);
    }
}

static void com_release(void *obj)
{
    void **vt;
    if (!obj) {
        return;
    }
    vt = *(void ***)obj;
    if (vt && vt[2]) {
        typedef uint32_t (*release_t)(void *);
        ((release_t)vt[2])(obj);
    }
}

static void *statics_singleton(void)
{
    typedef void *(*fn_t)(void);
    if (!g_base) {
        return NULL;
    }
    return ((fn_t)(g_base + RVA_USER_STATICS))();
}

/* TICKET-HARNESS-168 — singleton de ControllerStatics (RVA 0x19be70). É a
 * fonte dos eventos ControllerAdded/Removed/PairingChanged e o `sender` que os
 * delegates recebem. */
static void *statics_controller_singleton(void)
{
    typedef void *(*fn_t)(void);
    if (!g_base) {
        return NULL;
    }
    return ((fn_t)(g_base + RVA_CTRL_STATICS_SINGLETON))();
}

/* TICKET-HARNESS-170 — associa o Controller* REAL ao device dono dele.
 * AddRef SEMPRE antes de publicar na tabela (o objeto é COM e o jogo pode
 * soltar a referência dele a qualquer momento); a referência anterior do
 * mesmo device é liberada fora do lock. Nunca guarda ponteiro NULL. */
static void remember_controller_for_device(void *dev_key, void *controller)
{
    void *old = NULL;
    int i;
    int overflow = 0;

    if (!dev_key || !controller) {
        return;
    }
    com_addref(controller);
    AcquireSRWLockExclusive(&g_ctrl_binding_lock);
    for (i = 0; i < g_ctrl_binding_count; i++) {
        if (g_ctrl_binding[i].dev_key == dev_key) {
            old = g_ctrl_binding[i].controller;
            g_ctrl_binding[i].controller = controller;
            break;
        }
    }
    if (i == g_ctrl_binding_count) {
        if (g_ctrl_binding_count < FM5_CTRL_BINDINGS) {
            g_ctrl_binding[g_ctrl_binding_count].dev_key = dev_key;
            g_ctrl_binding[g_ctrl_binding_count].controller = controller;
            g_ctrl_binding_count++;
        } else {
            /* Tabela cheia: não publica em estado inconsistente; devolve a
             * referência recém-tomada em vez de vazar. */
            old = controller;
            overflow = 1;
        }
    }
    ReleaseSRWLockExclusive(&g_ctrl_binding_lock);
    com_release(old);
    if (overflow) {
        fm5_log("P2: tabela Controller*/device cheia; device=%p ignorado",
                dev_key);
    }
}

/* Controller* REAL associado a `dev_key` com uma referência NOVA (AddRef) ou
 * NULL quando o dispositivo ainda não foi visto por get_User/AccountPicker. */
static void *controller_for_device_ref(void *dev_key)
{
    void *controller = NULL;
    int i;

    if (!dev_key) {
        return NULL;
    }
    AcquireSRWLockExclusive(&g_ctrl_binding_lock);
    for (i = 0; i < g_ctrl_binding_count; i++) {
        if (g_ctrl_binding[i].dev_key == dev_key) {
            controller = g_ctrl_binding[i].controller;
            if (controller) {
                com_addref(controller);
            }
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_ctrl_binding_lock);
    return controller;
}

/* Caminho NATIVO do Player 1: lê o User do singleton em +0x18, reproduzindo o
 * corpo original de Controller::get_User (call; mov 0x18(%rax),%rcx; AddRef). */
static HRESULT serve_native_user(void **out)
{
    return (HRESULT)fm5_native_user_serve(statics_singleton(), out, com_addref);
}

/*
 * TICKET-HARNESS-169 — User NATIVO do Player 1 (UserStatics+0x18) com um
 * AddRef, ou NULL. É o `PreviousUser` de ControllerPairingChanged: os
 * controles rebaixados tinham exatamente esse User em cache, e é ele que o
 * jogo precisa descartar quando recebe o evento.
 */
static void *p1_native_user_ref(void)
{
    void *mgr = statics_singleton();
    void *user;

    if (!mgr) {
        return NULL;
    }
    user = *(void **)((uint8_t *)mgr + STATICS_USER_OFFSET);
    if (!user) {
        return NULL;
    }
    com_addref(user);
    return user;
}

/* Cria (uma única vez) o User WinRT virtual para `index` usando a factory
 * nativa do exe. Mantém uma referência permanente (a identidade é dona do
 * objeto) para que o ponteiro cacheado nunca dê dangling. */
static void *materialize_virtual_user(void *ctx, fm5_identity_t *id, int index)
{
    const fm5_user_t *u;
    void *mem;
    void *user;
    void *inner;

    (void)ctx;
    if (!g_base || index <= 0) {
        return NULL;
    }
    u = fm5_identity_user(id, index);
    if (!u) {
        return NULL;
    }
    if (u->native_user) {
        return u->native_user;
    }

    mem = exe_operator_new(0x20);
    if (!mem) {
        fm5_log("P2: operator new(0x20) falhou para User virtual %d", index);
        return NULL;
    }
    {
        typedef void *(*factory_t)(void *);
        user = ((factory_t)(g_base + RVA_USER_FACTORY))(mem);
    }
    if (!user) {
        fm5_log("P2: factory de User falhou para indice %d", index);
        return NULL;
    }
    inner = *(void **)((uint8_t *)user + USER_INNER_OFFSET);
    fm5_identity_bind_native(id, index, user, inner);
    fm5_log("P2: User virtual %d materializado (%s) user=%p inner=%p",
            index, u->gamer_tag, user, inner);
    return user;
}

/* Constrói uma IVectorView<User> replicando byte-a-byte o layout que o exe
 * usa em UserStatics::get_Users (0x1400424a0). */
static void *build_user_view(void **users, int n)
{
    uint8_t *obj;
    void **arr;
    int i;

    obj = (uint8_t *)exe_operator_new(0x40);
    if (!obj) {
        return NULL;
    }
    arr = (void **)exe_operator_new_arr(sizeof(void *) * (size_t)n);
    if (!arr) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        arr[i] = users[i];
        com_addref(users[i]);
    }

    *(uint32_t *)(obj + VIEW_REFCOUNT_OFFSET) = 1;
    *(void **)(obj + VIEW_CLASSNAME_OFFSET) = (void *)(g_base + RVA_STR_VIEW_CLASS);
    *(void **)obj = (void *)(g_base + RVA_VT_VIEW_MAIN);
    *(void **)(obj + 0x08) = (void *)(g_base + RVA_VT_VIEW_ITER);
    *(void **)(obj + 0x20) = arr;
    *(void **)(obj + 0x28) = arr + n;
    *(void **)(obj + 0x30) = arr + n;
    *(void **)(obj + 0x38) = (void *)(g_base + RVA_STR_ITER_CLASS);
    return obj;
}

/* ------------------------------------------------------------------------- */
/* UserAdded: captura, remoção e disparo dos delegates WinRT                 */
/* ------------------------------------------------------------------------- */
static int have_user_added_handlers(void)
{
    int n;
    if (!g_evt_hooks_ok) {
        /* Sem o hook de remove nao ha como soltar referencias com seguranca:
         * fail-closed, nenhum delegate e capturado/disparado. */
        return 0;
    }
    AcquireSRWLockShared(&g_evt_lock);
    n = g_evt_count;
    ReleaseSRWLockShared(&g_evt_lock);
    return n;
}

/*
 * Despacha UserAdded para os handlers que o PRÓPRIO jogo registrou. Cada
 * handler é um delegate COM (IUnknown ocupa os slots 0..2), portanto Invoke
 * é o slot 3 (offset 0x18) — ABI padrão de delegate WinRT.
 *
 * O evento do wrapper é TypedEventHandler<UserStatics, User>: o segundo
 * argumento é o User virtual do Player 2, exatamente como o jogo espera.
 */
static void win_user_added_observer(void *observer_ctx, void *sender, int index)
{
    void *handlers[FM5_P2_MAX_EVENT_HANDLERS];
    int n;
    int i;
    void *user;

    (void)observer_ctx;
    if (g_user_added_disabled) {
        fm5_log("P2: UserAdded suprimido por FM5_P2_DISABLE_USER_ADDED");
        return;
    }

    user = materialize_virtual_user(NULL, &g_identity, index);
    if (!user) {
        fm5_log("P2: UserAdded indice %d sem User materializado", index);
        return;
    }
    if (!sender) {
        sender = statics_singleton();
    }

    AcquireSRWLockExclusive(&g_evt_lock);
    n = g_evt_count;
    if (n > FM5_P2_MAX_EVENT_HANDLERS) {
        n = FM5_P2_MAX_EVENT_HANDLERS;
    }
    for (i = 0; i < n; i++) {
        handlers[i] = g_evt_handler[i];
        com_addref(handlers[i]);
    }
    ReleaseSRWLockExclusive(&g_evt_lock);

    com_addref(user);
    for (i = 0; i < n; i++) {
        void **vt = *(void ***)handlers[i];
        if (vt && vt[3]) {
            typedef HRESULT (*invoke_fn)(void *, void *, void *);
            HRESULT hr = ((invoke_fn)vt[3])(handlers[i], sender, user);
            fm5_log("P2: UserAdded handler %p invocado hr=0x%08lx",
                    handlers[i], (unsigned long)hr);
        }
        com_release(handlers[i]);
    }
    com_release(user);

    fm5_log("P2: UserAdded disparado para indice %d (%d handlers)", index, n);
}

/* Notifica o índice virtual SOMENTE se o jogo já assinou UserAdded; assim o
 * mascara de idempotência do núcleo não é consumida antes da assinatura. */
static void notify_virtual_user(int index)
{
    if (index <= 0) {
        return;
    }
    if (!have_user_added_handlers()) {
        return;
    }
    if (fm5_identity_notify_user_added(&g_identity, NULL, index) > 0) {
        fm5_log("P2: notificacao UserAdded emitida (indice %d)", index);
    }
}

/* ------------------------------------------------------------------------- */
/* TICKET-HARNESS-162/166 — atribuição dinâmica P1 (A) / P2 (Start)          */
/* ------------------------------------------------------------------------- */
/*
 * Extrai a chave canônica de dispositivo de um `Controller*`/`IController*`.
 * `*(self + 0x18)` é o mesmo void *device de GamepadReading; quando o jogo
 * entrega um ponteiro sem o campo preenchido (ou NULL), caímos no próprio
 * ponteiro para nunca devolver uma chave nula a um controle válido.
 */
static void *device_key_for_controller(void *self)
{
    void *dev_key;

    if (!self) {
        return NULL;
    }
    dev_key = *(void **)((uint8_t *)self + FM5_CONTROLLER_DEVICE_OFFSET);
    return dev_key ? dev_key : self;
}

/* Loga UMA vez por device novo (chave canônica) para o operador confirmar o
 * nascimento em índice 0 antes do primeiro A. */
static void log_device_seen(void *device)
{
    static SRWLOCK lock = SRWLOCK_INIT;
    static void   *seen[FM5_BTN_TRACK];
    static int     seen_count;
    int i;

    if (!device) {
        return;
    }
    AcquireSRWLockExclusive(&lock);
    for (i = 0; i < seen_count; i++) {
        if (seen[i] == device) {
            ReleaseSRWLockExclusive(&lock);
            return;
        }
    }
    if (seen_count < FM5_BTN_TRACK) {
        seen[seen_count++] = device;
    }
    ReleaseSRWLockExclusive(&lock);
    fm5_log("P2: device %p registrado (boot como Player 1/indice 0 ate o "
            "primeiro A)", device);
}

/* Materializa o User virtual reivindicado e dispara UserAdded (idempotente). */
static void announce_player2(int index)
{
    void *user = materialize_virtual_user(NULL, &g_identity, index);
    fm5_log("P2: Player 2 (indice %d) reivindicado por Start no lobby "
            "(user=%p)", index, user);
    /* Materializa ANTES de notificar: o dispatch e a reprodução feita por
     * hook_user_added_add dependem de u->native_user != NULL. */
    notify_virtual_user(index);
}

/* ------------------------------------------------------------------------- */
/* TICKET-HARNESS-168 — identidade Guest (vtable de User) e evento de        */
/* pareamento de controles (vtable de ControllerStatics)                     */
/* ------------------------------------------------------------------------- */

/*
 * Resolve o índice de identidade de um objeto User* recebido por get_IsGuest /
 * get_XboxUserHash / get_XboxUserId. Os User virtuais são rastreados pelo
 * núcleo (native_user); o User nativo do Player 1 vive em UserStatics+0x18 e
 * nunca é materializado pelo wrapper.
 */
static int index_for_user_object(void *self)
{
    int index;
    void *mgr;

    if (!self) {
        return -1;
    }
    index = fm5_identity_index_for_native_user(&g_identity, self);
    if (index >= 0) {
        return index;
    }
    mgr = statics_singleton();
    if (mgr && self == *(void **)((uint8_t *)mgr + STATICS_USER_OFFSET)) {
        return 0;
    }
    return -1;
}

/* Cria uma HSTRING UTF-16 a partir de uma string ASCII estritamente numérica
 * (XUID/hash), usando a MESMA rotina nativa de hook_display_name. */
static HRESULT serve_virtual_hstring(const char *ascii, void **out)
{
    wchar_t wide[24];
    uint32_t len;
    uint32_t i;
    void *h;
    typedef void *(*make_t)(uint32_t);

    if (!out) {
        return (HRESULT)0x80070057; /* E_INVALIDARG, igual ao original */
    }
    len = (uint32_t)strlen(ascii);
    if (len >= (uint32_t)(sizeof(wide) / sizeof(wide[0]))) {
        return (HRESULT)0x80070057;
    }
    for (i = 0; i < len; i++) {
        wide[i] = (wchar_t)(unsigned char)ascii[i];
    }
    h = ((make_t)(g_base + RVA_MAKE_HSTRING))(len);
    if (!h) {
        return (HRESULT)0x8007000E;
    }
    if (len) {
        void *buf = *(void **)((uint8_t *)h + 0x10);
        if (!buf) {
            return (HRESULT)0x8007000E;
        }
        memcpy(buf, wide, (size_t)len * sizeof(wchar_t));
        ((wchar_t *)buf)[len] = L'\0'; /* folga de 2 bytes na alocação */
    }
    *out = h;
    return S_OK;
}

/* User::get_IsGuest (vtable slot 10). O Player 2 virtual é sempre Convidado;
 * o Player 1 (e qualquer objeto desconhecido) segue para o corpo nativo. */
static HRESULT hook_user_is_guest(void *self, uint8_t *out)
{
    int index = index_for_user_object(self);

    if (index >= 1 && fm5_identity_is_guest(&g_identity, index)) {
        if (!out) {
            return (HRESULT)0x80004003; /* E_POINTER */
        }
        *out = 1;
        return S_OK;
    }
    if (!g_orig_user_is_guest) {
        return (HRESULT)0x80004005;
    }
    return g_orig_user_is_guest(self, out);
}

/* User::get_XboxUserHash (vtable slot 14): "1" para o P1 nativo, "N+1" para o
 * virtual de índice N. */
static HRESULT hook_user_xbox_user_hash(void *self, void **out)
{
    int index = index_for_user_object(self);
    char text[24];

    if (index >= 1 &&
        fm5_identity_xbox_user_hash(&g_identity, index, text, sizeof(text))) {
        return serve_virtual_hstring(text, out);
    }
    if (!g_orig_user_xbox_user_hash) {
        return (HRESULT)0x80004005;
    }
    return g_orig_user_xbox_user_hash(self, out);
}

/* User::get_XboxUserId (vtable slot 15): XUID decimal base+índice. */
static HRESULT hook_user_xbox_user_id(void *self, void **out)
{
    int index = index_for_user_object(self);
    char text[24];

    if (index >= 1 &&
        fm5_identity_xbox_user_id(&g_identity, index, text, sizeof(text))) {
        return serve_virtual_hstring(text, out);
    }
    if (!g_orig_user_xbox_user_id) {
        return (HRESULT)0x80004005;
    }
    return g_orig_user_xbox_user_id(self, out);
}

/* Escreve `count` slots consecutivos da vtable em `vt_rva`, a partir de
 * `first_slot`. Protege exatamente as páginas alcançadas. */
static int write_vtable_range(uint32_t vt_rva, int first_slot,
                              void *const *values, int count)
{
    void **base;
    uintptr_t start;
    uintptr_t end;
    uintptr_t page_start;
    uintptr_t page_end;
    DWORD old_protect = 0;
    int i;

    if (!g_base || count <= 0 || first_slot < 0) {
        return -1;
    }
    base = (void **)(g_base + vt_rva) + first_slot;
    start = (uintptr_t)base;
    end = start + (uintptr_t)count * sizeof(void *);
    page_start = start & ~(uintptr_t)0xFFFu;
    page_end = (end + 0xFFFu) & ~(uintptr_t)0xFFFu;
    if (!VirtualProtect((void *)page_start, page_end - page_start,
                        PAGE_READWRITE, &old_protect)) {
        return -2;
    }
    for (i = 0; i < count; i++) {
        base[i] = values[i];
    }
    VirtualProtect((void *)page_start, page_end - page_start, old_protect,
                   &old_protect);
    return 0;
}

/* Confere ANTES de escrever que cada slot ainda aponta para o RVA esperado do
 * build 1.0.4. Qualquer divergência aborta o patch inteiro (fail-closed). */
static int check_vtable_range(uint32_t vt_rva, int first_slot,
                              const uint32_t *want_rvas, int count)
{
    void **base;
    int i;

    if (!g_base) {
        return -1;
    }
    base = (void **)(g_base + vt_rva) + first_slot;
    for (i = 0; i < count; i++) {
        void *want = (void *)(g_base + want_rvas[i]);
        if (base[i] != want) {
            fm5_log("P2: vtable 0x%x slot %d divergente (%p != %p) — patch "
                    "cancelado", (unsigned)vt_rva, first_slot + i, base[i],
                    want);
            return -2;
        }
    }
    return 0;
}

static int install_user_guest_vtable(void)
{
    static const int slots[3] = {
        USER_VT_IS_GUEST, USER_VT_XBOX_USER_HASH, USER_VT_XBOX_USER_ID
    };
    static const uint32_t want[3] = {
        RVA_USER_IS_GUEST, RVA_USER_XBOX_USER_HASH, RVA_USER_XBOX_USER_ID
    };
    void *orig[3];
    int done = 0;
    int i;

    g_orig_user_is_guest = NULL;
    g_orig_user_xbox_user_hash = NULL;
    g_orig_user_xbox_user_id = NULL;

    for (i = 0; i < 3; i++) {
        void *handler;
        if (i == 0) {
            handler = (void *)hook_user_is_guest;
        } else if (i == 1) {
            handler = (void *)hook_user_xbox_user_hash;
        } else {
            handler = (void *)hook_user_xbox_user_id;
        }
        orig[i] = NULL;
        if (check_vtable_range(RVA_VT_USER, slots[i], &want[i], 1) != 0 ||
            write_vtable_range(RVA_VT_USER, slots[i], &handler, 1) != 0) {
            /* Rollback dos slots já trocados. */
            while (done > 0) {
                done--;
                write_vtable_range(RVA_VT_USER, slots[done], &orig[done], 1);
            }
            return -2;
        }
        orig[i] = (void *)(g_base + want[i]);
        done++;
    }

    g_orig_user_is_guest = (bool_getter_fn)orig[0];
    g_orig_user_xbox_user_hash = (hstring_getter_fn)orig[1];
    g_orig_user_xbox_user_id = (hstring_getter_fn)orig[2];
    g_user_vt_patched = 1;
    return 0;
}

static void uninstall_user_guest_vtable(void)
{
    static const int slots[3] = {
        USER_VT_IS_GUEST, USER_VT_XBOX_USER_HASH, USER_VT_XBOX_USER_ID
    };
    void *orig[3];
    int i;

    if (!g_user_vt_patched) {
        return;
    }
    orig[0] = (void *)g_orig_user_is_guest;
    orig[1] = (void *)g_orig_user_xbox_user_hash;
    orig[2] = (void *)g_orig_user_xbox_user_id;
    for (i = 0; i < 3; i++) {
        if (orig[i]) {
            write_vtable_range(RVA_VT_USER, slots[i], &orig[i], 1);
        }
    }
    g_orig_user_is_guest = NULL;
    g_orig_user_xbox_user_hash = NULL;
    g_orig_user_xbox_user_id = NULL;
    g_user_vt_patched = 0;
}

/* Add/remove dos eventos de ControllerStatics: chama o thunk nativo e guarda
 * uma referência própria do handler para poder invocá-lo depois. */
static const uint32_t k_ctrl_add_rva[FM5_CTRL_EV_COUNT] = {
    RVA_CTRL_ADDED_ADD, RVA_CTRL_REMOVED_ADD, RVA_CTRL_PAIRING_ADD
};
static const uint32_t k_ctrl_remove_rva[FM5_CTRL_EV_COUNT] = {
    RVA_CTRL_ADDED_REMOVE, RVA_CTRL_REMOVED_REMOVE, RVA_CTRL_PAIRING_REMOVE
};

static HRESULT ctrl_event_add(int kind, void *self, void *handler,
                              uint64_t *token)
{
    event_add_fn orig;
    HRESULT hr;
    int count = 0;

    if (!g_base) {
        return (HRESULT)0x80004005;
    }
    orig = (event_add_fn)(g_base + k_ctrl_add_rva[kind]);
    hr = orig(self, handler, token);
    if (FAILED(hr) || !handler) {
        return hr;
    }
    AcquireSRWLockExclusive(&g_ctrl_evt_lock);
    if (g_ctrl_evt_count[kind] < FM5_P2_MAX_EVENT_HANDLERS) {
        com_addref(handler);
        g_ctrl_evt_handler[kind][g_ctrl_evt_count[kind]] = handler;
        g_ctrl_evt_token[kind][g_ctrl_evt_count[kind]] =
            token ? *token : 0;
        g_ctrl_evt_count[kind]++;
        count = g_ctrl_evt_count[kind];
    }
    ReleaseSRWLockExclusive(&g_ctrl_evt_lock);

    fm5_log("P2: handler de ControllerStatics[%d] registrado (token=%llu, "
            "total=%d)", kind,
            (unsigned long long)(token ? *token : 0), count);
    return hr;
}

static HRESULT ctrl_event_remove(int kind, void *self, uint64_t token)
{
    event_remove_fn orig;
    HRESULT hr;
    void *dropped = NULL;
    int i;

    if (!g_base) {
        return (HRESULT)0x80004005;
    }
    orig = (event_remove_fn)(g_base + k_ctrl_remove_rva[kind]);
    hr = orig(self, token);
    if (FAILED(hr)) {
        return hr;
    }
    AcquireSRWLockExclusive(&g_ctrl_evt_lock);
    for (i = 0; i < g_ctrl_evt_count[kind]; i++) {
        if (g_ctrl_evt_token[kind][i] == token) {
            int last = g_ctrl_evt_count[kind] - 1;
            dropped = g_ctrl_evt_handler[kind][i];
            g_ctrl_evt_handler[kind][i] = g_ctrl_evt_handler[kind][last];
            g_ctrl_evt_token[kind][i] = g_ctrl_evt_token[kind][last];
            g_ctrl_evt_count[kind]--;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_ctrl_evt_lock);
    com_release(dropped);
    fm5_log("P2: handler de ControllerStatics[%d] removido (token=%llu)",
            kind, (unsigned long long)token);
    return hr;
}

static HRESULT hook_ctrl_added_add(void *self, void *handler, uint64_t *token)
{
    return ctrl_event_add(FM5_CTRL_EV_ADDED, self, handler, token);
}

static HRESULT hook_ctrl_added_remove(void *self, uint64_t token)
{
    return ctrl_event_remove(FM5_CTRL_EV_ADDED, self, token);
}

static HRESULT hook_ctrl_removed_add(void *self, void *handler, uint64_t *token)
{
    return ctrl_event_add(FM5_CTRL_EV_REMOVED, self, handler, token);
}

static HRESULT hook_ctrl_removed_remove(void *self, uint64_t token)
{
    return ctrl_event_remove(FM5_CTRL_EV_REMOVED, self, token);
}

static HRESULT hook_ctrl_pairing_add(void *self, void *handler, uint64_t *token)
{
    return ctrl_event_add(FM5_CTRL_EV_PAIRING, self, handler, token);
}

static HRESULT hook_ctrl_pairing_remove(void *self, uint64_t token)
{
    return ctrl_event_remove(FM5_CTRL_EV_PAIRING, self, token);
}

static int install_controller_event_vtable(void)
{
    static const uint32_t want[6] = {
        RVA_CTRL_ADDED_ADD, RVA_CTRL_ADDED_REMOVE,
        RVA_CTRL_REMOVED_ADD, RVA_CTRL_REMOVED_REMOVE,
        RVA_CTRL_PAIRING_ADD, RVA_CTRL_PAIRING_REMOVE
    };
    void *handlers[6];

    handlers[0] = (void *)hook_ctrl_added_add;
    handlers[1] = (void *)hook_ctrl_added_remove;
    handlers[2] = (void *)hook_ctrl_removed_add;
    handlers[3] = (void *)hook_ctrl_removed_remove;
    handlers[4] = (void *)hook_ctrl_pairing_add;
    handlers[5] = (void *)hook_ctrl_pairing_remove;

    if (check_vtable_range(RVA_VT_CONTROLLER_STATICS, 7, want, 6) != 0) {
        return -2;
    }
    if (write_vtable_range(RVA_VT_CONTROLLER_STATICS, 7, handlers, 6) != 0) {
        return -3;
    }
    g_ctrl_vt_patched = 1;
    return 0;
}

static void uninstall_controller_event_vtable(void)
{
    void *orig[6];
    int i;

    if (!g_ctrl_vt_patched || !g_base) {
        return;
    }
    for (i = 0; i < 6; i++) {
        if (i % 2 == 0) {
            orig[i] = (void *)(g_base + k_ctrl_add_rva[i / 2]);
        } else {
            orig[i] = (void *)(g_base + k_ctrl_remove_rva[i / 2]);
        }
    }
    write_vtable_range(RVA_VT_CONTROLLER_STATICS, 7, orig, 6);
    g_ctrl_vt_patched = 0;
}

/*
 * TICKET-HARNESS-169 — entrega UM evento ControllerPairingChanged com um
 * objeto `args` COM legítimo (IControllerPairingChangedEventArgs sintetizado
 * em fm5_pairing.c).
 *
 * O bug original passava o próprio `sender` no lugar de `args`:
 *
 *     ((invoke_fn)vt[3])(handler, sender, sender);
 *
 * O handler do Forza resolve `args` e acaba chamando os slots da vtable de
 * ControllerStatics como se fossem os de ControllerPairingChangedEventArgs —
 * o primeiro método cai num thunk com assinatura incompatível e o processo
 * morre com STATUS_ACCESS_VIOLATION. Aqui o delegate recebe `args` de
 * verdade: slots 6/7 devolvem o User novo (NULL no rebaixamento) e o
 * PreviousUser (P1 nativo) com AddRef, exatamente o par que invalida o cache
 * de identidade do jogo.
 *
 * Devolve quantos handlers foram invocados (0 = fail-closed).
 */
static int dispatch_pairing_changed(void *new_user, void *controller)
{
    void *handlers[FM5_P2_MAX_EVENT_HANDLERS];
    fm5_pairing_args_t *args;
    void *previous_user;
    void *sender;
    int n;
    int i;
    int invoked = 0;

    AcquireSRWLockExclusive(&g_ctrl_evt_lock);
    n = g_ctrl_evt_count[FM5_CTRL_EV_PAIRING];
    if (n > FM5_P2_MAX_EVENT_HANDLERS) {
        n = FM5_P2_MAX_EVENT_HANDLERS;
    }
    for (i = 0; i < n; i++) {
        handlers[i] = g_ctrl_evt_handler[FM5_CTRL_EV_PAIRING][i];
        com_addref(handlers[i]);
    }
    ReleaseSRWLockExclusive(&g_ctrl_evt_lock);

    if (n <= 0) {
        fm5_log("P2: nenhum handler de ControllerPairingChanged capturado — o "
                "cache de User do jogo nao sera invalidado por evento "
                "(fail-closed; get_User ja devolve NULL)");
        return 0;
    }
    /* Sender = singleton de ControllerStatics: é a fonte do evento (o objeto
     * em cujo container o jogo registrou o delegate). */
    sender = statics_controller_singleton();
    if (!sender) {
        /* Sem o singleton não há sender válido: melhor não invocar um
         * delegate do jogo com ponteiro nulo (fail-closed). */
        for (i = 0; i < n; i++) {
            com_release(handlers[i]);
        }
        fm5_log("P2: ControllerPairingChanged nao disparado (singleton "
                "indisponivel) — fail-closed");
        return 0;
    }
    /* PreviousUser = User nativo do Player 1 (com AddRef nosso; solto ao
     * final — o args só faz AddRef quando o handler pede). */
    previous_user = p1_native_user_ref();
    args = fm5_pairing_args_create(new_user, previous_user, controller,
                                   com_addref);
    if (!args) {
        com_release(previous_user);
        for (i = 0; i < n; i++) {
            com_release(handlers[i]);
        }
        fm5_log("P2: ControllerPairingChanged sem args sintetizado — "
                "fail-closed (alocacao falhou)");
        return 0;
    }
    fm5_log("P2: ControllerPairingChanged args=%p user=%p previous_user=%p "
            "controller=%p", (void *)args, new_user, previous_user,
            controller);
    for (i = 0; i < n; i++) {
        void **vt = *(void ***)handlers[i];
        if (vt && vt[3]) {
            typedef HRESULT (*invoke_fn)(void *, void *, void *);
            HRESULT hr;
            /* O 3o argumento é o NOSSO args (nunca o sender): o handler
             * consulta slots da interface de argumentos, não da fonte. */
            hr = ((invoke_fn)vt[3])(handlers[i], sender, args);
            fm5_log("P2: ControllerPairingChanged handler %p invocado "
                    "hr=0x%08lx (user=%p previous_user=%p)", handlers[i],
                    (unsigned long)hr, new_user, previous_user);
            invoked++;
        }
        com_release(handlers[i]);
    }
    com_release(previous_user);
    fm5_pairing_args_release(args);
    return invoked;
}

/*
 * TICKET-HARNESS-171 — dispara UM evento ControllerPairingChanged por chave de
 * device da lista, entregando o Controller* REAL de cada device (resgatado da
 * tabela device -> Controller* com referência própria) e o `user` informado.
 *
 * Devolve quantas invocações de handler aconteceram (0 = fail-closed).
 */
static int dispatch_pairing_for_keys(void *const *keys, int total, void *user)
{
    int invoked = 0;
    int i;

    for (i = 0; i < total; i++) {
        void *controller = controller_for_device_ref(keys[i]);

        if (!controller) {
            /* Sem o Controller* real o exe não localiza o slot interno
             * (0x1406763a0 compara [slot+0x70]) e o evento não surte efeito;
             * logar é a única evidência disponível nesse caminho. */
            fm5_log("P2: device %p ainda nao visto por get_User — evento de "
                    "pareamento sem Controller* real", keys[i]);
        }
        invoked += dispatch_pairing_changed(user, controller);
        com_release(controller);
    }
    return invoked;
}

/*
 * TICKET-HARNESS-168/169/171 — avisa o jogo que o pareamento/atribuição de
 * usuário dos controles mudou. Sem esse evento o Forza continua servindo o User
 * CACHEADO do Player 1 para os controles secundários, funde os dois jogadores
 * na Home e recusa o split-screen (P1 contra P1).
 *
 * Dois cenários:
 *   1. FASE 2 (primeiro A): o controle secundário JÁ é o Player 2 virtual
 *      (índice 1). O evento leva `User = User virtual materializado` e
 *      `PreviousUser = P1 nativo`. Um `User = NULL` NÃO serve: a rotina
 *      0x140675e10 do Forza aborta o evento imediatamente quando
 *      `args->get_User() == NULL` (140675e3e: je 0x140675f67), então o
 *      rebaixamento nunca chegava a atualizar o slot do controle. Com um User
 *      VÁLIDO o jogo processa o evento e grava o Player 2 no slot interno.
 *      Controles em índice >= 2 não têm canal e recebem `User = NULL`.
 *   2. FASE 3 (Start do P2): UM evento para o Player 2 eleito, com
 *      `User = User virtual do índice 1` e `PreviousUser = P1 nativo`.
 */
static void notify_pairing_changed(void)
{
    void *keys[FM5_P2_MAX_CONTROLLERS];
    int total;
    int invoked = 0;

    if (g_pairing_event_disabled) {
        fm5_log("P2: ControllerPairingChanged suprimido por "
                "FM5_P2_DISABLE_PAIRING_EVENT");
        return;
    }

    if (fm5_identity_p2_locked(&g_identity)) {
        /* FASE 3 — o controle que apertou Start ganhou o User virtual. O
         * get_Controller do args devolve o Controller* REAL desse device
         * (associado por hook_get_user / ShowAccountPickerAsync), nunca NULL
         * quando o ponteiro já foi visto. */
        void *new_user = materialize_virtual_user(NULL, &g_identity, 1);
        void *p2_device;
        void *controller;

        AcquireSRWLockExclusive(&g_join_lock);
        p2_device = g_p2_device;
        ReleaseSRWLockExclusive(&g_join_lock);
        controller = controller_for_device_ref(p2_device);

        invoked = dispatch_pairing_changed(new_user, controller);
        com_release(controller);
        fm5_log("P2: ControllerPairingChanged disparado para o Player 2 "
                "(user=%p device=%p controller=%p, invocacoes=%d)", new_user,
                p2_device, controller, invoked);
        return;
    }

    /* FASE 2 — pós-A: o secundário é o Player 2 VIRTUAL (índice 1). Só há
     * evento se o User virtual foi materializado; sem ele o Forza abortaria o
     * evento em 140675e3e, então falhamos fechado e logamos. */
    total = fm5_identity_controllers_for_index(&g_identity, 1, keys,
                                               FM5_P2_MAX_CONTROLLERS);
    if (total > FM5_P2_MAX_CONTROLLERS) {
        total = FM5_P2_MAX_CONTROLLERS;
    }
    if (total > 0) {
        void *new_user = materialize_virtual_user(NULL, &g_identity, 1);

        if (!new_user) {
            fm5_log("P2: ControllerPairingChanged do secundario abortado — "
                    "User virtual do indice 1 nao materializado");
            return;
        }
        invoked = dispatch_pairing_for_keys(keys, total, new_user);
        fm5_log("P2: ControllerPairingChanged disparado para o Player 2 "
                "virtual (user=%p, %d controle(s), %d invocacoes)", new_user,
                total, invoked);
    }

    /* Índices >= 2 (Player 3+) — sem canal de usuário. O evento leva
     * `User = NULL` para o jogo descartar o User CACHEADO do Player 1. */
    total = fm5_identity_demoted_controllers(&g_identity, keys,
                                             FM5_P2_MAX_CONTROLLERS);
    if (total > FM5_P2_MAX_CONTROLLERS) {
        total = FM5_P2_MAX_CONTROLLERS;
    }
    if (total > 0) {
        invoked += dispatch_pairing_for_keys(keys, total, NULL);
        fm5_log("P2: ControllerPairingChanged disparado (%d controle(s) sem "
                "canal de usuario, %d invocacoes)", total, invoked);
    }
}

/*
 * Substituto de UserStatics::MakeAccountPickerUser (0x4c8030). Depois que o
 * Player 1 foi eleito, a tela de conta do jogador 2 deve receber o User
 * VIRTUAL (e não o nativo do P1), senão o Forza reatribui o perfil do jogador
 * 1 ao segundo controle. Devolve o ponteiro já com AddRef, como o original.
 */
static void *hook_make_account_picker_user(void)
{
    void *user;

    if (g_orig_account_picker && fm5_identity_p1_locked(&g_identity)) {
        user = materialize_virtual_user(NULL, &g_identity, 1);
        if (user) {
            static int logged;
            com_addref(user);
            if (!logged) {
                logged = 1;
                fm5_log("P2: MakeAccountPickerUser servindo o User virtual do "
                        "Player 2 (user=%p)", user);
            }
            return user;
        }
        fm5_log("P2: MakeAccountPickerUser sem User virtual; delegando ao "
                "nativo");
    }
    return g_orig_account_picker ? g_orig_account_picker() : NULL;
}

/* Aplica a máquina de estados em CASCATA (TICKET-HARNESS-163) a uma chave de
 * dispositivo (TICKET-HARNESS-166: o device id é a chave canônica).
 *
 * FASE 1: todo controle nasce no índice 0 (Player 1) e get_User serve o nativo.
 * FASE 2: o primeiro A elege o P1 definitivo e promove o secundário a Player 2
 *         virtual (índice 1, TICKET-HARNESS-171).
 * FASE 3: o primeiro Start de um secundário confirma o P2 definitivo,
 *         materializa o User virtual, emite UserAdded e move os demais para 2+.
 */
static void claim_controller(void *dev_key, uint32_t buttons)
{
    int index = -1;
    int event;

    if (!dev_key) {
        return;
    }
    event = fm5_identity_cascade_claim(&g_identity, dev_key, buttons,
                                       &index);
    if (event == FM5_CASCADE_P1_ELECTED) {
        AcquireSRWLockExclusive(&g_join_lock);
        g_p1_device = dev_key;
        ReleaseSRWLockExclusive(&g_join_lock);
        fm5_log("P2: Player 1 DEFINITIVO eleito por A no splash (device=%p); "
                "secundario(s) promovido(s) a Player 2 virtual (indice 1)",
                dev_key);
        /* TICKET-HARNESS-171: o evento de pareamento leva o User VIRTUAL do
         * Player 2 (nunca NULL) para o Forza atualizar o slot interno do
         * segundo controle — 0x140675e10 aborta quando get_User() == NULL. */
        notify_pairing_changed();
        return;
    }
    if (event == FM5_CASCADE_P2_ELECTED) {
        AcquireSRWLockExclusive(&g_join_lock);
        g_p2_device = dev_key;
        ReleaseSRWLockExclusive(&g_join_lock);
        fm5_log("P2: Player 2 DEFINITIVO eleito por Start no lobby "
                "(device=%p indice=%d); demais -> Player 3 (indice 2)",
                dev_key, index);
        announce_player2(index);
        /* TICKET-HARNESS-169/171: o evento de pareamento também precisa sair na
         * confirmação do P2 (User virtual), não só na promoção pós-A: é o
         * PreviousUser = P1 que o jogo usa para trocar o dono do controle. */
        notify_pairing_changed();
        return;
    }
    fm5_log("P2: reivindicacao sem efeito (device=%p buttons=0x%04x) — "
            "P1/P2 ja eleitos ou botao sem posse", dev_key,
            (unsigned)buttons);
}

/* ------------------------------------------------------------------------- */
/* Handlers                                                                  */
/* ------------------------------------------------------------------------- */
static HRESULT hook_get_user(void *self, void **out)
{
    fm5_status_t st;
    void *dev_key;

    if (!g_orig_get_user) {
        return (HRESULT)0x80004005; /* E_FAIL */
    }
    /* TICKET-HARNESS-166 — chave canônica: `self + 0x18` guarda o MESMO device
     * id que o hook de leitura recebe em rdx. Como o jogo recria wrappers
     * Controller* a cada enumeração, dois ponteiros distintos apontam para o
     * mesmo dispositivo e DEVEM resolver o mesmo usuário. */
    dev_key = device_key_for_controller(self);
    /* Registra a chave no pool de identidade desde o primeiro get_User. */
    (void)fm5_identity_index_for_controller(&g_identity, dev_key);
    /* TICKET-HARNESS-170 — `self` É o Controller* do Forza. Guarda o ponteiro
     * real (com AddRef) para o evento de pareamento entregar em get_Controller
     * (slot 6 do args), que é o objeto que o exe usa para achar o slot interno
     * e gravar o User* em [slot+0x78]. */
    remember_controller_for_device(dev_key, self);
    st = fm5_resolve_get_user(&g_identity, dev_key, out, NULL,
                              materialize_virtual_user, NULL);
    switch (st) {
    case FM5_DELEGATE:
        /* Índice 0 e controle provisório antes do primeiro A: servimos o User
         * nativo diretamente pelo singleton, sem trampolim de retorno. */
        return serve_native_user(out);
    case FM5_HANDLED:
        /* Player 2: o índice 1 recebe o User virtual materializado
         * (TICKET-HARNESS-164) e nunca mais a identidade de P1 — o secundário
         * já cai aqui no MESMO 'A' que elege o P1 (TICKET-HARNESS-171). */
        com_addref(*out);
        return S_OK;
    case FM5_SERVED_NULL:
        /* Sentinela NEUTRO ou índice >= 2 (Player 3 em diante): sem canal. */
        if (out) {
            *out = NULL;
        }
        return S_OK;
    case FM5_E_POINTER:
        return (HRESULT)0x80004003; /* E_POINTER */
    case FM5_E_OUTOFMEMORY:
    default:
        return (HRESULT)0x8007000E; /* E_OUTOFMEMORY */
    }
}

static HRESULT hook_get_users(void *self, void **out)
{
    static int logged_view;
    void *p1;
    void *users[FM5_P2_MAX_USERS];
    int n;
    int i;

    if (!g_orig_get_users) {
        return (HRESULT)0x80004005;
    }
    if (!out) {
        return (HRESULT)0x80004003;
    }
    p1 = *(void **)((uint8_t *)self + STATICS_USER_OFFSET);
    n = fm5_resolve_get_users(&g_identity, p1, users, FM5_P2_MAX_USERS,
                              materialize_virtual_user, NULL);
    if (n <= 1) {
        return g_orig_get_users(self, out);
    }
    if (!logged_view) {
        logged_view = 1;
        fm5_log("P2: get_Users expondo %d usuarios ao jogo", n);
    }
    {
        void *view = build_user_view(users, n);
        if (!view) {
            fm5_log("P2: falha ao construir IVectorView com %d usuarios", n);
            return (HRESULT)0x8007000E;
        }
        *out = view;
    }
    /* TICKET-HARNESS-162/163: expor 2 perfis no boot NÃO significa anunciá-los.
     * UserAdded só é disparado após o Start eleger o Player 2 definitivo
     * (fm5_identity_index_claimed). */
    for (i = 1; i < n; i++) {
        if (fm5_identity_index_claimed(&g_identity, i)) {
            notify_virtual_user(i);
        }
    }
    return S_OK;
}

static HRESULT hook_display_name(void *self, void **out)
{
    static int logged_tag;
    if (!g_orig_display_name) {
        return (HRESULT)0x80004005;
    }
    if (out && fm5_identity_is_virtual_inner(&g_identity, self)) {
        uint32_t len = (uint32_t)wcslen(g_p2_tag_w);
        void *h;
        typedef void *(*make_t)(uint32_t);
        if (!logged_tag) {
            logged_tag = 1;
            fm5_log("P2: display name virtual servido ao jogo");
        }
        h = ((make_t)(g_base + RVA_MAKE_HSTRING))(len);
        if (!h) {
            return (HRESULT)0x8007000E;
        }
        if (len) {
            void *buf = *(void **)((uint8_t *)h + 0x10);
            if (!buf) {
                return (HRESULT)0x8007000E;
            }
            memcpy(buf, g_p2_tag_w, (size_t)len * sizeof(wchar_t));
            ((wchar_t *)buf)[len] = L'\0'; /* folga de 2 bytes na alocação */
        }
        *out = h;
        return S_OK;
    }
    return g_orig_display_name(self, out);
}

/*
 * UserStatics::GetUserById (0x140042580):
 *   HRESULT (UserStatics *self, uint32_t id, User **out)
 * O original só aceita id == 1. Aqui o Player 1 continua nativo e o Player 2
 * (id 2..max) é materializado sob demanda e devolvido com AddRef.
 */
static HRESULT hook_get_user_by_id(void *self, uint32_t user_id, void **out)
{
    fm5_status_t st;

    st = fm5_resolve_get_user_by_id(&g_identity, user_id, out,
                                    materialize_virtual_user, NULL);
    switch (st) {
    case FM5_DELEGATE:
        return (HRESULT)fm5_native_user_serve(self, out, com_addref);
    case FM5_HANDLED: {
        int index = fm5_identity_index_for_id(&g_identity, user_id);
        com_addref(*out);
        notify_virtual_user(index);
        return S_OK;
    }
    case FM5_SERVED_NULL:
        return S_OK;
    case FM5_E_POINTER:
        return (HRESULT)0x80004003;
    case FM5_E_OUTOFMEMORY:
    default:
        return (HRESULT)0x8007000E;
    }
}

/*
 * UserStatics vtable[6] (0x140042480): HRESULT (self, uint32_t *out).
 * O original grava o literal 1. Aqui devolvemos a contagem efetiva
 * do console (mínimo 2, respeitando FM5_P2_MAX_USERS).
 */
static HRESULT hook_user_count(void *self, uint32_t *out)
{
    (void)self;
    if (!out) {
        return (HRESULT)0x80004003;
    }
    *out = (uint32_t)fm5_identity_console_count(&g_identity);
    return S_OK;
}

/*
 * User vtable[6] (0x140041f70): get_Id. O original devolve o literal 1 para
 * QUALQUER instância, o que faria o Player 2 se apresentar como Player 1.
 * Devolvemos o id de console 1-based do objeto (Player 1 = 1, Player 2 = 2).
 */
static HRESULT hook_user_get_id(void *self, uint32_t *out)
{
    int index;
    if (!out) {
        return (HRESULT)0x80004003;
    }
    /* TICKET-HARNESS-168: mesma resolução de identidade usada pelos getters de
     * guest (User virtual pelo núcleo; P1 nativo pelo singleton). */
    index = index_for_user_object(self);
    *out = (uint32_t)(index >= 0 ? index + 1 : 1);
    return S_OK;
}

/*
 * TICKET-HARNESS-160/161 — correção do mapeamento de botões.
 *
 * 0x4b18c0 recebe em rcx o ponteiro da GamepadReading (retorno oculto) e em
 * rdx o dispositivo; preenche a leitura chamando a conversão DirectInput
 * 0x4b0c40. Depois de executar o original, recompomos o campo Buttons em
 * retbuf+8 (offset 8 = GamepadButtons, logo após o Timestamp de 8 bytes):
 * Menu (Start) e View (Back) passam a ser emitidos e os bits espúrios que o
 * `shl $2` criava são removidos. O TICKET-HARNESS-161 (log real) provou que o
 * volante entrega Start/Back em 0x0080/0x0040 — ambos aceitos e consumidos.
 * TICKET-HARNESS-163: Start/Menu na borda de subida dispara a eleição em
 * cascata do Player 2 (o primeiro controle secundário vira P2 definitivo).
 */
/* Atualiza o estado observado do dispositivo e devolve a leitura ANTERIOR
 * (0 para dispositivo novo). A diferença permite detectar a BORDA de
 * pressionamento, para a máquina P1/P2 não ser reexecutada a cada frame. */
static uint32_t log_buttons(void *device, uint32_t raw_shifted, uint32_t fixed)
{
    int i;
    int slot = -1;

    AcquireSRWLockExclusive(&g_btn_lock);
    for (i = 0; i < FM5_BTN_TRACK; i++) {
        if (g_btn_state[i].device == device) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        for (i = 0; i < FM5_BTN_TRACK; i++) {
            if (g_btn_state[i].device == NULL) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0) {
        slot = 0; /* cache cheio: reusa o primeiro slot (só afeta o log) */
    }
    /*
     * TICKET-HARNESS-166 — PRIMEIRO frame de um device: grava a leitura como
     * baseline e devolve a MESMA leitura. Assim `pressed = raw & ~prev` é 0 e
     * um pacote inicial sujo (ex.: device=4 directinput=0x10d4) não elege um
     * controle fantasma como Player 1. Vale também quando o slot é reciclado
     * por um device diferente.
     */
    if (g_btn_state[slot].device != device) {
        g_btn_state[slot].device = device;
        g_btn_state[slot].last = raw_shifted;
        ReleaseSRWLockExclusive(&g_btn_lock);

        fm5_log("P2: botoes device=%p raw=0x%04x gamepad=0x%04x "
                "(Menu=%d View=%d) [baseline]",
                device, (unsigned)raw_shifted, (unsigned)fixed,
                (fixed & FM5_GB_MENU) ? 1 : 0, (fixed & FM5_GB_VIEW) ? 1 : 0);
        return raw_shifted;
    }
    if (g_btn_state[slot].last == raw_shifted) {
        ReleaseSRWLockExclusive(&g_btn_lock);
        return raw_shifted;
    }
    {
        uint32_t prev = g_btn_state[slot].last;
        g_btn_state[slot].last = raw_shifted;
        ReleaseSRWLockExclusive(&g_btn_lock);

        fm5_log("P2: botoes device=%p raw=0x%04x gamepad=0x%04x "
                "(Menu=%d View=%d)",
                device, (unsigned)raw_shifted, (unsigned)fixed,
                (fixed & FM5_GB_MENU) ? 1 : 0, (fixed & FM5_GB_VIEW) ? 1 : 0);
        return prev;
    }
}

static void *hook_get_reading(void *retbuf, void *device)
{
    void *ret;
    uint32_t *buttons;
    uint32_t raw_shifted;
    uint32_t fixed;
    uint32_t prev;
    uint32_t pressed;
    uint32_t claim_bits = 0;

    /* Blindagem do carregamento: rearme barato a cada leitura (ver
     * rearm_loading_hooks). Roda também quando g_orig_get_reading é NULL. */
    rearm_loading_hooks();

    if (!g_orig_get_reading) {
        return retbuf;
    }
    ret = g_orig_get_reading(retbuf, device);
    if (!retbuf) {
        return ret;
    }
    buttons = (uint32_t *)((uint8_t *)retbuf + 8);
    raw_shifted = *buttons;
    fixed = fm5_buttons_recompose(raw_shifted, g_swap_start_back);
    if (fixed != raw_shifted) {
        *buttons = fixed;
    }
    prev = log_buttons(device, raw_shifted, fixed);

    /* TICKET-HARNESS-166 — registra a chave canônica no pool de identidade
     * antes de qualquer eleição: o MESMO `device` que chega em rdx é o valor
     * lido de Controller+0x18 em get_User. */
    log_device_seen(device);
    (void)fm5_identity_index_for_controller(&g_identity, device);

    /*
     * TICKET-HARNESS-163 — máquina de estados em cascata, disparada na BORDA
     * (0 -> 1) para não reexecutar a eleição a cada frame com o botão
     * segurado:
     *   - A (0x0010 no enum Xbox One ERA) no splash elege o Player 1
     *     definitivo e promove o secundário a Player 2 virtual (índice 1);
     *   - Start/Menu (0x0004) no lobby confirma o Player 2 definitivo (demais
     *     -> índices 2, 3, ...), desde que outro controle já seja o Player 1.
     * TICKET-HARNESS-166: DPadUp (0x0100) e DPadDown (0x0200) NÃO são
     * Start/Back e nunca disparam eleição. A borda Menu+View simultânea é
     * ruído de pacote inicial (XInput reporta os dois no primeiro frame) e
     * não elege ninguém.
     */
    pressed = raw_shifted & ~prev;
    if (pressed & FM5_GB_A) {
        claim_bits |= FM5_IDENTITY_BUTTON_A;
    }
    if ((pressed & FM5_GB_SYSTEM_MASK) == FM5_GB_MENU) {
        claim_bits |= FM5_IDENTITY_BUTTON_MENU;
    }
    if (claim_bits) {
        claim_controller(device, claim_bits);
    }
    return ret;
}

/* vtable[7]: registra o handler de UserAdded no container do exe e guarda o
 * delegate para despertá-lo quando o Player 2 for registrado. */
static HRESULT hook_user_added_add(void *self, void *handler, uint64_t *token)
{
    HRESULT hr;
    int first = 0;
    int count = 0;
    int i;

    if (!g_orig_user_added_add) {
        return (HRESULT)0x80004005;
    }
    hr = g_orig_user_added_add(self, handler, token);
    if (FAILED(hr) || !handler || !g_evt_hooks_ok) {
        return hr;
    }

    AcquireSRWLockExclusive(&g_evt_lock);
    if (g_evt_count < FM5_P2_MAX_EVENT_HANDLERS) {
        com_addref(handler);
        first = (g_evt_count == 0);
        g_evt_handler[g_evt_count] = handler;
        g_evt_token[g_evt_count] = token ? *token : 0;
        g_evt_count++;
        count = g_evt_count;
    }
    ReleaseSRWLockExclusive(&g_evt_lock);

    fm5_log("P2: handler UserAdded registrado (token=%llu, total=%d)",
            (unsigned long long)(token ? *token : 0), count);

    if (first) {
        /* Se o Player 2 já foi REIVINDICADO antes da assinatura, notifica
         * agora (o jogo só passou a observar depois do fato). A mera exposição
         * em get_Users no boot não dispara UserAdded (TICKET-HARNESS-162). */
        for (i = 1; i < FM5_P2_MAX_USERS; i++) {
            if (fm5_identity_index_claimed(&g_identity, i)) {
                notify_virtual_user(i);
            }
        }
    }
    return hr;
}

/* vtable[8]: remove o handler pelo token; solta a referência que guardamos. */
static HRESULT hook_user_added_remove(void *self, uint64_t token)
{
    HRESULT hr;
    int i;
    void *dropped = NULL;

    if (!g_orig_user_added_remove) {
        return (HRESULT)0x80004005;
    }
    hr = g_orig_user_added_remove(self, token);
    if (FAILED(hr)) {
        return hr;
    }
    AcquireSRWLockExclusive(&g_evt_lock);
    for (i = 0; i < g_evt_count; i++) {
        if (g_evt_token[i] == token) {
            dropped = g_evt_handler[i];
            g_evt_handler[i] = g_evt_handler[g_evt_count - 1];
            g_evt_token[i] = g_evt_token[g_evt_count - 1];
            g_evt_count--;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_evt_lock);
    com_release(dropped);
    fm5_log("P2: handler UserAdded removido (token=%llu)",
            (unsigned long long)token);
    return hr;
}

/* ------------------------------------------------------------------------- */
/* TICKET-HARNESS-165 — bridge Windows.Xbox.UI.SystemUI                      */
/* ------------------------------------------------------------------------- */

/* Provider do User do Player 2 para a AccountPickerResult sintetizada. A
 * materialização é a mesma já usada por get_User/GetUserById (factory nativa
 * do exe + identidade virtual), portanto o User devolvido ao jogo é o MESMO
 * objeto do split-screen (ID 2, GamerTag "Player 2"). */
static void *systemui_player2_user(void *ctx)
{
    (void)ctx;
    return materialize_virtual_user(NULL, &g_identity, 1);
}

/*
 * TICKET-HARNESS-166 — o jogo chamou ShowAccountPickerAsync com o controller
 * do jogador 2. Extrai a chave canônica (*(controller + 0x18)) e garante a
 * eleição do Player 2 na cascata. Se o P1 ainda não foi eleito ou o device já
 * tem posse, a cascata devolve NONE e nada muda (idempotente).
 */
static void systemui_claim_controller(void *ctx, void *controller)
{
    void *dev_key;
    int index = -1;
    int event;

    (void)ctx;
    dev_key = device_key_for_controller(controller);
    if (!dev_key) {
        fm5_log("P2: ShowAccountPickerAsync sem chave de device "
                "(controller=%p)", controller);
        return;
    }
    (void)fm5_identity_index_for_controller(&g_identity, dev_key);
    event = fm5_identity_cascade_claim(&g_identity, dev_key,
                                       FM5_IDENTITY_BUTTON_MENU, &index);
    fm5_log("P2: ShowAccountPickerAsync controller=%p device=%p evento=%d "
            "indice=%d", controller, dev_key, event, index);
    if (event == FM5_CASCADE_P2_ELECTED) {
        /* Controller* real do P2: fica guardado (com AddRef) por device para
         * o get_Controller (slot 6) do args de pareamento. */
        remember_controller_for_device(dev_key, controller);
        AcquireSRWLockExclusive(&g_join_lock);
        g_p2_device = dev_key;
        ReleaseSRWLockExclusive(&g_join_lock);
        announce_player2(index);
        /* TICKET-HARNESS-169: mesmo evento de pareamento da eleição por Start
         * quando o P2 entra pelo AccountPicker. */
        notify_pairing_changed();
    }
}

/*
 * Substituto do slot IAT de RoGetActivationFactory.
 *
 * Lê a HSTRING da classe; se for exatamente "Windows.Xbox.UI.SystemUI" entrega
 * a ISystemUIStatics sintetizada (S_OK). Qualquer outra classe — e qualquer
 * falha ao ler a HSTRING — segue para a função original, preservando o
 * comportamento do Azimuth para todo o resto do jogo.
 */
static HRESULT WINAPI hook_ro_get_activation_factory(void *class_name,
                                                     const void *iid,
                                                     void **factory)
{
    typedef HRESULT (WINAPI *ro_factory_fn)(void *, const void *, void **);
    int32_t hr = 0;
    const wchar_t *raw;

    if (class_name && g_get_string_raw) {
        raw = g_get_string_raw(class_name, NULL);
        if (raw && fm5_systemui_class_matches(raw)) {
            static int logged;
            if (fm5_systemui_try_activate(&g_systemui, raw, iid, factory,
                                          &hr)) {
                if (!logged) {
                    logged = 1;
                    fm5_log("P2: SystemUI ativado para "
                            "\"Windows.Xbox.UI.SystemUI\" "
                            "(ShowAccountPickerAsync -> Player 2 virtual)");
                }
                return (HRESULT)hr;
            }
        }
    }
    if (!g_orig_ro_factory) {
        return (HRESULT)0x80004005; /* E_FAIL: fail-closed */
    }
    return ((ro_factory_fn)g_orig_ro_factory)(class_name, iid, factory);
}

/* Resolve WindowsGetStringRawBuffer em combase.dll (a HSTRING é opaca; ler o
 * layout interno seria frágil entre versões do Windows). */
static int resolve_hstring_api(void)
{
    HMODULE combase = GetModuleHandleA("combase.dll");
    HMODULE strmod;

    if (!combase) {
        combase = LoadLibraryA("combase.dll");
    }
    if (combase) {
        g_get_string_raw = (get_string_raw_fn)GetProcAddress(
            combase, "WindowsGetStringRawBuffer");
    }
    if (!g_get_string_raw) {
        /* O exe já importa api-ms-win-core-winrt-string-l1-1-0.dll; nela a
         * função costuma estar encaminhada para combase. */
        strmod = GetModuleHandleA(
            "api-ms-win-core-winrt-string-l1-1-0.dll");
        if (!strmod) {
            strmod = LoadLibraryA(
                "api-ms-win-core-winrt-string-l1-1-0.dll");
        }
        if (strmod) {
            g_get_string_raw = (get_string_raw_fn)GetProcAddress(
                strmod, "WindowsGetStringRawBuffer");
        }
    }
    return g_get_string_raw ? 0 : -1;
}

/*
 * Instala a bridge patcheando o slot IAT. A validação é fail-closed: o slot
 * precisa apontar para a exportação real RoGetActivationFactory do módulo que
 * o fornece; caso contrário nada é alterado.
 */
static int install_ro_factory_iat(void)
{
    typedef HRESULT (WINAPI *ro_factory_fn)(void *, const void *, void **);
    void **slot;
    void *orig;
    HMODULE module = NULL;
    ro_factory_fn exported;
    DWORD old_protect = 0;

    if (!g_base) {
        return -1;
    }
    slot = (void **)(g_base + RVA_IAT_ROGETACTIVATIONFACTORY);
    orig = *slot;
    if (!orig) {
        return -2;
    }
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)orig, &module) ||
        !module) {
        return -3;
    }
    exported = (ro_factory_fn)GetProcAddress(module,
                                             "RoGetActivationFactory");
    if (!exported || (void *)exported != orig) {
        return -4;
    }
    if (!g_get_string_raw) {
        return -5;
    }
    if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old_protect)) {
        return -6;
    }
    g_orig_ro_factory = orig;
    g_ro_factory_slot = slot;
    *slot = (void *)hook_ro_get_activation_factory;
    VirtualProtect(slot, sizeof(void *), old_protect, &old_protect);
    return 0;
}

static void uninstall_ro_factory_iat(void)
{
    DWORD old_protect = 0;

    if (!g_ro_factory_slot || !g_orig_ro_factory) {
        return;
    }
    if (VirtualProtect(g_ro_factory_slot, sizeof(void *), PAGE_READWRITE,
                       &old_protect)) {
        *g_ro_factory_slot = g_orig_ro_factory;
        VirtualProtect(g_ro_factory_slot, sizeof(void *), old_protect,
                       &old_protect);
    }
    g_ro_factory_slot = NULL;
    g_orig_ro_factory = NULL;
}

/* ------------------------------------------------------------------------- */
/* Init / shutdown                                                           */
/* ------------------------------------------------------------------------- */
static void read_config(char *tag, size_t tag_cap, int *max_users)
{
    const char *env;

    *max_users = 2;
    strncpy(tag, "Player 2", tag_cap - 1);
    tag[tag_cap - 1] = '\0';

    env = getenv("FM5_P2_GAMERTAG");
    if (env && env[0]) {
        strncpy(tag, env, tag_cap - 1);
        tag[tag_cap - 1] = '\0';
    }
    env = getenv("FM5_P2_MAX_USERS");
    if (env && env[0]) {
        int v = atoi(env);
        if (v >= 2 && v <= FM5_P2_MAX_USERS) {
            *max_users = v;
        }
    }
    env = getenv("FM5_P2_DISABLE_USER_ADDED");
    if (env && env[0] && env[0] != '0') {
        g_user_added_disabled = 1;
    }
    /* TICKET-HARNESS-168: escape hatch de campo. Se o disparo de
     * ControllerPairingChanged derrubar alguma build do jogo, o operador
     * desliga SÓ o evento (a demissão para NULL em get_User continua). */
    env = getenv("FM5_P2_DISABLE_PAIRING_EVENT");
    if (env && env[0] && env[0] != '0') {
        g_pairing_event_disabled = 1;
    }
    /* TICKET-HARNESS-160: alguns dispositivos reportam Back/Start em ordem
     * invertida na ordem DirectInput; o override permite corrigir sem rebuild. */
    env = getenv("FM5_P2_SWAP_START_BACK");
    if (env && env[0] && env[0] != '0') {
        g_swap_start_back = 1;
    }
}

static void setup_hook(fm5_hook_t *h, uint32_t rva, size_t patch_len,
                       const uint8_t *expect, size_t expect_len,
                       int rel32_off, void *fn)
{
    h->target = g_base + rva;
    h->patch_len = patch_len;
    h->expect = expect;
    h->expect_len = expect_len;
    h->rel32_offset = rel32_off;
    h->hook_fn = fn;
}

void fm5_hooks_init(void)
{
    char tag[FM5_P2_TAG_MAX];
    int max_users;
    int i;
    int ok = 0;

    if (g_ready) {
        return;
    }
    g_base = (uint8_t *)GetModuleHandleA(NULL);
    if (!g_base) {
        return;
    }
    read_config(tag, sizeof(tag), &max_users);
    fm5_identity_init(&g_identity, max_users, tag);

    for (i = 0; i < FM5_P2_TAG_MAX - 1 && tag[i]; i++) {
        g_p2_tag_w[i] = (wchar_t)(unsigned char)tag[i];
    }
    g_p2_tag_w[i] = L'\0';

    /* Observador do núcleo -> despachante dos delegates WinRT. */
    if (fm5_identity_add_observer(&g_identity, win_user_added_observer, NULL) ==
        0) {
        fm5_log("P2: observador de UserAdded registrado no nucleo");
    }

    setup_hook(&g_hook_get_user, RVA_GET_USER, 14, EXPECT_GET_USER,
               sizeof(EXPECT_GET_USER), 9, (void *)hook_get_user);
    setup_hook(&g_hook_get_users, RVA_GET_USERS, 15, EXPECT_GET_USERS,
               sizeof(EXPECT_GET_USERS), -1, (void *)hook_get_users);
    setup_hook(&g_hook_display_name, RVA_GET_DISPLAY_NAME, 16,
               EXPECT_DISPLAY_NAME, sizeof(EXPECT_DISPLAY_NAME), -1,
               (void *)hook_display_name);
    setup_hook(&g_hook_get_user_by_id, RVA_GET_USER_BY_ID, 15,
               EXPECT_GET_USER_BY_ID, sizeof(EXPECT_GET_USER_BY_ID), -1,
               (void *)hook_get_user_by_id);
    setup_hook(&g_hook_user_count, RVA_USER_COUNT, 17, EXPECT_USER_COUNT,
               sizeof(EXPECT_USER_COUNT), -1, (void *)hook_user_count);
    setup_hook(&g_hook_user_get_id, RVA_USER_GET_ID, 20, EXPECT_USER_GET_ID,
               sizeof(EXPECT_USER_GET_ID), -1, (void *)hook_user_get_id);
    setup_hook(&g_hook_user_added_add, RVA_USER_ADDED_ADD, 16,
               EXPECT_USER_ADDED_ADD, sizeof(EXPECT_USER_ADDED_ADD), -1,
               (void *)hook_user_added_add);
    setup_hook(&g_hook_user_added_remove, RVA_USER_ADDED_REMOVE, 18,
               EXPECT_USER_ADDED_REMOVE, sizeof(EXPECT_USER_ADDED_REMOVE), 13,
               (void *)hook_user_added_remove);
    /* TICKET-HARNESS-160: patch de 15 bytes (fronteira de instrução exata). */
    setup_hook(&g_hook_get_reading, RVA_GET_READING, 15, EXPECT_GET_READING,
               sizeof(EXPECT_GET_READING), -1, (void *)hook_get_reading);
    /* Blindagem do carregamento (crash 0xC0000005 em 0x140687f4c): o handler
     * WindowActivated do TÍTULO devolve S_OK e não posta o evento 25/6.
     * O alvo vive no executável do jogo (mapa manual do Azimuth em
     * 0x140000000), não no wrapper: o `target` é resolvido no primeiro frame
     * em que o módulo existe (ensure_window_hook/rearm_loading_hooks). As
     * assinaturas são as do arquivo real do título 1.0.0.20. */
    g_hook_window_activated.patch_len = 15;
    g_hook_window_activated.expect = EXPECT_WINDOW_ACTIVATED;
    g_hook_window_activated.expect_len = sizeof(EXPECT_WINDOW_ACTIVATED);
    g_hook_window_activated.rel32_offset = -1;
    g_hook_window_activated.hook_fn = (void *)hook_window_activated;
    g_game_base = resolve_game_base();
    if (g_game_base) {
        g_hook_window_activated.target = g_game_base + RVA_WINDOW_ACTIVATED;
    }
    /* TICKET-HARNESS-168: UserStatics::MakeAccountPickerUser — devolve o User
     * virtual do Player 2 quando o P1 já foi eleito. */
    setup_hook(&g_hook_account_picker, RVA_MAKE_ACCOUNT_PICKER_USER, 16,
               EXPECT_MAKE_ACCOUNT_PICKER, sizeof(EXPECT_MAKE_ACCOUNT_PICKER),
               6, (void *)hook_make_account_picker_user);

    /* TICKET-HARNESS-165: bridge Windows.Xbox.UI.SystemUI via slot IAT de
     * RoGetActivationFactory. Sem a API de HSTRING a bridge fica desligada
     * (fail-closed), mas o resto dos hooks de identidade continua ativo. */
    fm5_systemui_init(&g_systemui);
    fm5_systemui_set_user_source(&g_systemui, systemui_player2_user, NULL,
                                 com_addref);
    fm5_systemui_set_controller_observer(&g_systemui, systemui_claim_controller,
                                         NULL);
    if (resolve_hstring_api() == 0) {
        if (install_ro_factory_iat() == 0) {
            ok++;
            fm5_log("P2: hook RoGetActivationFactory (IAT 0x68e8c0) "
                    "instalado — bridge Windows.Xbox.UI.SystemUI ativa");
        } else {
            fm5_log("P2: FALHA ao instalar a bridge SystemUI (slot IAT "
                    "divergente do build 1.0.4?)");
        }
    } else {
        fm5_log("P2: WindowsGetStringRawBuffer indisponivel — bridge "
                "SystemUI desativada (fail-closed)");
    }

    if (fm5_hook_install(&g_hook_get_user) == 0) {
        g_orig_get_user = (get_user_fn)g_hook_get_user.trampoline;
        ok++;
        fm5_log("P2: hook Controller::get_User instalado");
    } else {
        fm5_log("P2: FALHA ao instalar get_User (assinatura divergente?)");
    }
    if (fm5_hook_install(&g_hook_get_users) == 0) {
        g_orig_get_users = (get_users_fn)g_hook_get_users.trampoline;
        ok++;
        fm5_log("P2: hook UserStatics::get_Users instalado");
    } else {
        fm5_log("P2: FALHA ao instalar get_Users (assinatura divergente?)");
    }
    if (fm5_hook_install(&g_hook_display_name) == 0) {
        g_orig_display_name = (get_name_fn)g_hook_display_name.trampoline;
        ok++;
        fm5_log("P2: hook get_DisplayName instalado");
    } else {
        fm5_log("P2: FALHA ao instalar get_DisplayName (assinatura divergente?)");
    }
    if (fm5_hook_install(&g_hook_get_user_by_id) == 0) {
        ok++;
        fm5_log("P2: hook UserStatics::GetUserById instalado");
    } else {
        fm5_log("P2: FALHA ao instalar GetUserById (assinatura divergente?)");
    }
    if (fm5_hook_install(&g_hook_user_count) == 0) {
        ok++;
        fm5_log("P2: hook UserStatics vtable[6] (contagem) instalado");
    } else {
        fm5_log("P2: FALHA ao instalar vtable[6] (assinatura divergente?)");
    }
    if (fm5_hook_install(&g_hook_user_get_id) == 0) {
        ok++;
        fm5_log("P2: hook User::get_Id instalado");
    } else {
        fm5_log("P2: FALHA ao instalar User::get_Id (assinatura divergente?)");
    }
    if (fm5_hook_install(&g_hook_user_added_add) == 0) {
        g_orig_user_added_add = (event_add_fn)g_hook_user_added_add.trampoline;
        ok++;
        fm5_log("P2: hook UserAdded add (vtable[7]) instalado");
    } else {
        fm5_log("P2: FALHA ao instalar UserAdded add (assinatura divergente?)");
    }
    if (fm5_hook_install(&g_hook_user_added_remove) == 0) {
        g_orig_user_added_remove =
            (event_remove_fn)g_hook_user_added_remove.trampoline;
        ok++;
        fm5_log("P2: hook UserAdded remove (vtable[8]) instalado");
    } else {
        fm5_log("P2: FALHA ao instalar UserAdded remove (assinatura divergente?)");
    }
    if (fm5_hook_install(&g_hook_get_reading) == 0) {
        g_orig_get_reading = (get_reading_fn)g_hook_get_reading.trampoline;
        ok++;
        fm5_log("P2: hook GamepadReading (botoes Menu/View) instalado");
    } else {
        fm5_log("P2: FALHA ao instalar GamepadReading (assinatura divergente?)");
    }
    /* Blindagem do carregamento: o executável do título normalmente ainda NÃO
     * está mapeado no DllMain (o Azimuth o carrega depois). Nesse caso fica
     * pendente e o rearme por frame (rearm_loading_hooks) resolve/instala. */
    {
        int hook_rc = ensure_window_hook();
        if (hook_rc == 0) {
            ok++;
        } else if (hook_rc == -2) {
            fm5_log("P2: FALHA ao instalar o handler WindowActivated "
                    "(0x%05x) — assinatura do titulo divergente?",
                    (unsigned)RVA_WINDOW_ACTIVATED);
        } else {
            fm5_log("P2: blindagem do carregamento pendente — executavel do "
                    "titulo ainda nao mapeado (rearme por frame)");
        }
        if (g_game_base) {
            int src = fm5_event_shield_install(g_game_base);
            if (src == 0 || src == 1) {
                InterlockedExchange(&g_loading_shield_logged, 2);
                ok++;
            }
            /* Blindagem da Visibility Thread (crash 0x1408595e0). */
            src = fm5_visibility_shield_install(g_game_base);
            if (src == 0 || src == 1) {
                InterlockedExchange(&g_visibility_shield_logged, 2);
                ok++;
                fm5_log("P2: blindagem de visibilidade instalada (JGE em "
                        "0x%05x + trava where/_Mylast em 0x%05x)",
                        (unsigned)RVA_VISIBILITY_BRANCH,
                        (unsigned)RVA_VISIBILITY_INSERT);
            }
        }
    }

    /* TICKET-HARNESS-168 — identidade Guest: os três getters da vtable de User
     * são patcheados em conjunto (rollback se algum slot divergir). */
    if (install_user_guest_vtable() == 0) {
        ok++;
        fm5_log("P2: vtable de User patcheada (slots %d/%d/%d: IsGuest, "
                "XboxUserHash, XboxUserId)",
                USER_VT_IS_GUEST, USER_VT_XBOX_USER_HASH, USER_VT_XBOX_USER_ID);
    } else {
        fm5_log("P2: FALHA ao patchear a vtable de User (build divergente?) — "
                "Player 2 nao se apresentara como Convidado");
    }

    /* TICKET-HARNESS-168 — captura os eventos de ControllerStatics para poder
     * sinalizar ControllerPairingChanged aos handlers do proprio jogo. */
    if (install_controller_event_vtable() == 0) {
        ok++;
        fm5_log("P2: vtable de ControllerStatics patcheada (slots 7..12: "
                "Added/Removed/PairingChanged)");
    } else {
        fm5_log("P2: FALHA ao patchear ControllerStatics (build divergente?) — "
                "o evento de pareamento nao sera disparado");
    }

    /* TICKET-HARNESS-168 — MakeAccountPickerUser -> User virtual do P2. */
    if (fm5_hook_install(&g_hook_account_picker) == 0) {
        g_orig_account_picker =
            (make_picker_user_fn)g_hook_account_picker.trampoline;
        ok++;
        fm5_log("P2: hook UserStatics::MakeAccountPickerUser instalado");
    } else {
        fm5_log("P2: FALHA ao instalar MakeAccountPickerUser (assinatura "
                "divergente?)");
    }
    /* O disparo de UserAdded so e seguro se conseguirmos capturar E remover
     * handlers; caso contrario nenhum delegate e guardado. */
    g_evt_hooks_ok = (g_orig_user_added_add != NULL &&
                      g_orig_user_added_remove != NULL);
    if (!g_evt_hooks_ok) {
        fm5_log("P2: UserAdded desativado (add/remove incompletos) — fail-closed");
    }

    g_ready = 1;
    fm5_log("P2: inicializacao concluida — %d/15 hooks ativos, max_users=%d "
            "tag=\"%s\" user_added=%s pairing_event=%s swap_start_back=%d",
            ok, max_users, tag,
            (g_user_added_disabled || !g_evt_hooks_ok) ? "desligado"
                                                       : "ligado",
            g_pairing_event_disabled ? "desligado" : "ligado",
            g_swap_start_back);
}

void fm5_hooks_shutdown(void)
{
    int i;
    if (!g_ready) {
        return;
    }
    fm5_hook_uninstall(&g_hook_get_user);
    fm5_hook_uninstall(&g_hook_get_users);
    fm5_hook_uninstall(&g_hook_display_name);
    fm5_hook_uninstall(&g_hook_get_user_by_id);
    fm5_hook_uninstall(&g_hook_user_count);
    fm5_hook_uninstall(&g_hook_user_get_id);
    fm5_hook_uninstall(&g_hook_user_added_add);
    fm5_hook_uninstall(&g_hook_user_added_remove);
    fm5_hook_uninstall(&g_hook_get_reading);
    /* Blindagem do carregamento: devolve o handler e restaura a fila. */
    fm5_hook_uninstall(&g_hook_window_activated);
    fm5_event_shield_uninstall(g_game_base);
    fm5_visibility_shield_uninstall(g_game_base);
    g_game_base = NULL;
    InterlockedExchange(&g_loading_shield_logged, 0);
    InterlockedExchange(&g_visibility_shield_logged, 0);
    /* TICKET-HARNESS-168: restaura as vtables e solta os delegates capturados. */
    fm5_hook_uninstall(&g_hook_account_picker);
    uninstall_user_guest_vtable();
    uninstall_controller_event_vtable();
    /* TICKET-HARNESS-165: devolve o slot IAT original de RoGetActivationFactory. */
    uninstall_ro_factory_iat();
    g_get_string_raw = NULL;
    fm5_systemui_init(&g_systemui);
    g_orig_get_user = NULL;
    g_orig_get_users = NULL;
    g_orig_display_name = NULL;
    g_orig_user_added_add = NULL;
    g_orig_user_added_remove = NULL;
    g_orig_get_reading = NULL;
    g_orig_account_picker = NULL;
    g_orig_user_is_guest = NULL;
    g_orig_user_xbox_user_hash = NULL;
    g_orig_user_xbox_user_id = NULL;

    AcquireSRWLockExclusive(&g_btn_lock);
    for (i = 0; i < FM5_BTN_TRACK; i++) {
        g_btn_state[i].device = NULL;
        g_btn_state[i].last = 0;
    }
    ReleaseSRWLockExclusive(&g_btn_lock);

    /* TICKET-HARNESS-166: o pareamento por rank foi substituído pela chave
     * canônica de device id; resta apenas limpar o espelho de diagnóstico. */
    AcquireSRWLockExclusive(&g_join_lock);
    g_p1_device = NULL;
    g_p2_device = NULL;
    ReleaseSRWLockExclusive(&g_join_lock);

    AcquireSRWLockExclusive(&g_evt_lock);
    for (i = 0; i < g_evt_count; i++) {
        com_release(g_evt_handler[i]);
        g_evt_handler[i] = NULL;
        g_evt_token[i] = 0;
    }
    g_evt_count = 0;
    ReleaseSRWLockExclusive(&g_evt_lock);

    /* TICKET-HARNESS-168: delegates de ControllerStatics capturados. */
    AcquireSRWLockExclusive(&g_ctrl_evt_lock);
    {
        int k;
        for (k = 0; k < FM5_CTRL_EV_COUNT; k++) {
            for (i = 0; i < g_ctrl_evt_count[k]; i++) {
                com_release(g_ctrl_evt_handler[k][i]);
                g_ctrl_evt_handler[k][i] = NULL;
                g_ctrl_evt_token[k][i] = 0;
            }
            g_ctrl_evt_count[k] = 0;
        }
    }
    ReleaseSRWLockExclusive(&g_ctrl_evt_lock);

    /* TICKET-HARNESS-170: solta as referências fortes da tabela
     * device -> Controller* usada pelo get_Controller do args de pareamento.
     * Os ponteiros são retirados sob o lock e os Release acontecem fora dele
     * (o destructor do objeto do jogo não deve rodar com lock nosso na mão). */
    {
        void *dropped[FM5_CTRL_BINDINGS];
        int dropped_count = 0;

        AcquireSRWLockExclusive(&g_ctrl_binding_lock);
        for (i = 0; i < g_ctrl_binding_count; i++) {
            dropped[dropped_count++] = g_ctrl_binding[i].controller;
            g_ctrl_binding[i].controller = NULL;
            g_ctrl_binding[i].dev_key = NULL;
        }
        g_ctrl_binding_count = 0;
        ReleaseSRWLockExclusive(&g_ctrl_binding_lock);
        for (i = 0; i < dropped_count; i++) {
            com_release(dropped[i]);
        }
    }

    fm5_identity_destroy(&g_identity);
    g_ready = 0;
}

int fm5_hooks_ready(void)
{
    return g_ready;
}
