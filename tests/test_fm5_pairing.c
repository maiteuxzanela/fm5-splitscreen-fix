/*
 * test_fm5_pairing.c — testes nativos (Linux/gcc, SEM mocks) do objeto COM
 * sintetizado para Windows.Xbox.Input.ControllerPairingChangedEventArgs
 * (TICKET-HARNESS-169).
 *
 * O que é provado aqui, contra o código REAL de fm5_pairing.c:
 *   1. layout ABI: o vfptr é o primeiro campo do objeto e os getters ocupam
 *      exatamente os slots 6 (Controller), 7 (User novo) e 8 (PreviousUser)
 *      da vtable publicada — os mesmos que o handler do Forza consulta
 *      (confirmado por desmontagem: 0x140675e81 lê vt[6] como Controller* e
 *      0x140675e36/e66 leem vt[7] como User*);
 *   2. cada slot é chamado PELO ENDEREÇO PUBLICADO na vtable, como o delegate
 *      do jogo faz (não por um atalho interno do teste);
 *   3. QueryInterface aceita IUnknown/IInspectable (S_OK + AddRef + mesmo
 *      objeto) e recusa qualquer outro IID com E_NOINTERFACE + *out = NULL;
 *   4. get_User/get_PreviousUser/get_Controller devolvem S_OK + NULL para
 *      controle rebaixado e S_OK + objeto COM AddRef'ado quando existe;
 *   5. out NULL devolve E_POINTER em TODAS as propriedades (nunca escreve em
 *      0x0 nem devolve lixo);
 *   6. GetIids/GetRuntimeClassName/GetTrustLevel e os stubs 9..12 respondem
 *      sem estourar a vtable (E_NOTIMPL/valores benignos);
 *   7. ciclo de vida: AddRef/Release contam corretamente e o destroy do
 *      objeto alocado no heap é chamado exatamente uma vez no zero;
 *   8. fm5_identity_controllers_for_index() devolve exatamente os controles do
 *      índice 1 (Player 2 virtual — o alvo do evento com User VÁLIDO) e
 *      fm5_identity_demoted_controllers() os de índice >= 2 (User = NULL);
 *   9. resolução por BYTES a partir do vfptr publicado (0x30 -> Controller*,
 *      0x38 -> User*, 0x40 -> PreviousUser*) e nunca cruzada entre slots, nas
 *      duas formas que o evento assume (P2 eleito e controle sem canal);
 *  10. ownership: cada consulta faz 1 AddRef, destruir o args NÃO solta os
 *      objetos (o chamador é o dono da referência forte) — sem double-free
 *      do Controller* guardado por device.
 *
 * Os "objetos do jogo" (User/Controller) são sentinelas com vtables REAIS de
 * AddRef/Release: o callback injetado chama a vtable[1] do próprio objeto,
 * exatamente como com_addref faz na DLL.
 */
#include "fm5_identity.h"
#include "fm5_pairing.h"

#include <stddef.h>
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
/* Sentinelas COM reais (sem mock: AddRef/Release têm estado observável)     */
/* ------------------------------------------------------------------------- */
typedef struct sentinel {
    void  **vt;      /* slot 0 QI, slot 1 AddRef, slot 2 Release */
    int     addrefs;
    int     releases;
} sentinel_t;

static uint32_t sentinel_add_ref(void *self)
{
    sentinel_t *s = (sentinel_t *)self;
    s->addrefs++;
    return (uint32_t)s->addrefs;
}

static uint32_t sentinel_release(void *self)
{
    sentinel_t *s = (sentinel_t *)self;
    s->releases++;
    return (uint32_t)(s->addrefs - s->releases);
}

static int32_t sentinel_qi(void *self, const void *riid, void **out)
{
    (void)riid;
    if (!out) {
        return FM5_PAIRING_E_POINTER;
    }
    *out = self;
    return FM5_PAIRING_S_OK;
}

static void *const g_sentinel_vt[3] = {
    (void *)sentinel_qi, (void *)sentinel_add_ref, (void *)sentinel_release
};

static void sentinel_init(sentinel_t *s)
{
    memset(s, 0, sizeof(*s));
    s->vt = (void **)g_sentinel_vt;
}

/* Mesmo contrato do com_addref da DLL: AddRef pela vtable[1] do objeto. */
static void test_addref(void *obj)
{
    typedef uint32_t (*addref_fn)(void *);
    void **vt;

    if (!obj) {
        return;
    }
    vt = *(void ***)obj;
    if (vt && vt[1]) {
        ((addref_fn)vt[1])(obj);
    }
}

/* Chamadas PELO ENDEREÇO PUBLICADO na vtable (como o jogo faz). */
static int32_t vt_get_user(const fm5_pairing_args_vt_t *vt, void *args,
                           void **out)
{
    return vt->get_user(args, out);
}

static int32_t vt_get_previous_user(const fm5_pairing_args_vt_t *vt, void *args,
                                    void **out)
{
    return vt->get_previous_user(args, out);
}

static int32_t vt_get_controller(const fm5_pairing_args_vt_t *vt, void *args,
                                 void **out)
{
    return vt->get_controller(args, out);
}

/*
 * Resolve o slot por DESLOCAMENTO DE BYTES a partir do vfptr publicado —
 * exatamente o que o exe faz (`mov 0x30(%rax),%rax` em 0x140675e81 para o
 * Controller*, `mov 0x38(%rax),%rax` em 0x140675e36/e66 para o User). Nenhum
 * nome de campo participa: só os bytes da vtable que o jogo enxerga.
 */
static int32_t call_at_offset(const fm5_pairing_args_vt_t *vt, size_t offset,
                              void *self, void **out)
{
    void *fn = *(void **)((const char *)vt + offset);

    return ((fm5_pairing_prop_fn)fn)(self, out);
}

static void test_layout(void)
{
    const fm5_pairing_args_vt_t *vt = fm5_pairing_args_vtbl();
    fm5_pairing_args_t args;

    CHECK(vt != NULL);
    /* Um slot = um ponteiro: a ordem dos campos É a ordem da ABI. */
    CHECK(offsetof(fm5_pairing_args_vt_t, query_interface) == 0 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, add_ref) == 1 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, release) == 2 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, get_iids) == 3 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, get_runtime_class) ==
          4 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, get_trust_level) ==
          5 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, get_controller) ==
          6 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, get_user) == 7 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, get_previous_user) ==
          8 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, slot9) == 9 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, slot10) == 10 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, slot11) == 11 * sizeof(void *));
    CHECK(offsetof(fm5_pairing_args_vt_t, slot12) == 12 * sizeof(void *));
    CHECK(sizeof(fm5_pairing_args_vt_t) ==
          FM5_PAIRING_VT_SLOTS * sizeof(void *));

    /* Todos os slots publicados são não nulos (vtable completa). */
    CHECK(vt->query_interface != NULL && vt->add_ref != NULL &&
          vt->release != NULL && vt->get_iids != NULL &&
          vt->get_runtime_class != NULL && vt->get_trust_level != NULL &&
          vt->get_user != NULL && vt->get_previous_user != NULL &&
          vt->get_controller != NULL && vt->slot9 != NULL &&
          vt->slot10 != NULL && vt->slot11 != NULL && vt->slot12 != NULL);

    /* O vfptr é o PRIMEIRO campo do objeto (o jogo lê *(void ***)args). */
    CHECK(offsetof(fm5_pairing_args_t, vt) == 0);
    fm5_pairing_args_init(&args, NULL, NULL, NULL, test_addref);
    CHECK(*(void ***)&args == (void **)fm5_pairing_args_vtbl());

    /* Prova POSICIONAL (independente dos nomes dos campos): ao chamar o slot
     * bruto 6 o jogo recebe o Controller*, o slot 7 entrega o User novo e o
     * slot 8 o PreviousUser — exatamente a ordem do handler do exe. */
    {
        sentinel_t u;
        sentinel_t p;
        sentinel_t c;
        fm5_pairing_args_t a;
        void **raw = (void **)fm5_pairing_args_vtbl();
        void *out = NULL;

        sentinel_init(&u);
        sentinel_init(&p);
        sentinel_init(&c);
        fm5_pairing_args_init(&a, &u, &p, &c, test_addref);

        CHECK(((fm5_pairing_prop_fn)raw[6])(&a, &out) == FM5_PAIRING_S_OK);
        CHECK(out == (void *)&c); /* slot 6 (+0x30) = Controller* */
        CHECK(c.addrefs == 1);

        out = NULL;
        CHECK(((fm5_pairing_prop_fn)raw[7])(&a, &out) == FM5_PAIRING_S_OK);
        CHECK(out == (void *)&u); /* slot 7 (+0x38) = User* novo */
        CHECK(u.addrefs == 1);

        out = NULL;
        CHECK(((fm5_pairing_prop_fn)raw[8])(&a, &out) == FM5_PAIRING_S_OK);
        CHECK(out == (void *)&p); /* slot 8 (+0x40) = PreviousUser */
        CHECK(p.addrefs == 1);
    }
}

/*
 * ABI por BYTES — o contrato que o handler do Forza consome.
 *
 * O desmontador mostra três acessos a partir do vfptr do args:
 *   0x30 (+6 slots) -> Controller*    (0x140675e81 -> [event+0x18])
 *   0x38 (+7 slots) -> User*         (0x140675e36/e66 -> [event+0x20])
 *   0x40 (+8 slots) -> PreviousUser* (par do User* antes da troca de dono)
 * Cada acesso é resolvido aqui por aritmética de bytes sobre a vtable
 * PUBLICADA, sem passar por campo nomeado nem por atalho interno.
 */
static void test_abi_byte_offsets(void)
{
    const fm5_pairing_args_vt_t *vt = fm5_pairing_args_vtbl();
    sentinel_t user_new;
    sentinel_t previous;
    sentinel_t controller;

    CHECK(FM5_PAIRING_VT_GET_CONTROLLER == 6u);
    CHECK(FM5_PAIRING_VT_GET_USER == 7u);
    CHECK(FM5_PAIRING_VT_GET_PREV_USER == 8u);
    CHECK((size_t)FM5_PAIRING_VT_GET_CONTROLLER * sizeof(void *) ==
          (size_t)0x30);
    CHECK((size_t)FM5_PAIRING_VT_GET_USER * sizeof(void *) == (size_t)0x38);
    CHECK((size_t)FM5_PAIRING_VT_GET_PREV_USER * sizeof(void *) ==
          (size_t)0x40);
    /* O deslocamento do campo na struct é o MESMO que o jogo usa. */
    CHECK(offsetof(fm5_pairing_args_vt_t, get_controller) == (size_t)0x30);
    CHECK(offsetof(fm5_pairing_args_vt_t, get_user) == (size_t)0x38);
    CHECK(offsetof(fm5_pairing_args_vt_t, get_previous_user) == (size_t)0x40);
    CHECK(*(void **)((const char *)vt + 0x30) == (void *)vt->get_controller);
    CHECK(*(void **)((const char *)vt + 0x38) == (void *)vt->get_user);
    CHECK(*(void **)((const char *)vt + 0x40) ==
          (void *)vt->get_previous_user);
    /* Slots distintos: 0x30, 0x38 e 0x40 nunca podem apontar para o mesmo
     * handler (era exatamente a confusão de tipos do crash original). */
    CHECK(vt->get_controller != vt->get_user);
    CHECK(vt->get_user != vt->get_previous_user);
    CHECK(vt->get_controller != vt->get_previous_user);

    /*
     * FASE 3 (P2 eleito): User virtual novo + PreviousUser = P1 + Controller
     * real do device. É a forma que notify_pairing_changed monta.
     */
    sentinel_init(&user_new);
    sentinel_init(&previous);
    sentinel_init(&controller);
    {
        fm5_pairing_args_t args;
        void *out = (void *)0x1;

        fm5_pairing_args_init(&args, &user_new, &previous, &controller,
                              test_addref);

        CHECK(call_at_offset(vt, 0x30, &args, &out) == FM5_PAIRING_S_OK);
        CHECK(out == (void *)&controller);
        CHECK(controller.addrefs == 1);
        CHECK(user_new.addrefs == 0 && previous.addrefs == 0);

        out = (void *)0x1;
        CHECK(call_at_offset(vt, 0x38, &args, &out) == FM5_PAIRING_S_OK);
        CHECK(out == (void *)&user_new);
        CHECK(user_new.addrefs == 1);
        CHECK(controller.addrefs == 1 && previous.addrefs == 0);

        out = (void *)0x1;
        CHECK(call_at_offset(vt, 0x40, &args, &out) == FM5_PAIRING_S_OK);
        CHECK(out == (void *)&previous);
        CHECK(previous.addrefs == 1);
        CHECK(controller.addrefs == 1 && user_new.addrefs == 1);

        /* Nenhum slot entrega o objeto de outro: Controller* nunca sai como
         * User/PreviousUser e vice-versa. */
        out = NULL;
        CHECK(call_at_offset(vt, 0x30, &args, &out) == FM5_PAIRING_S_OK);
        CHECK(out == (void *)&controller && out != (void *)&user_new &&
              out != (void *)&previous);
        out = NULL;
        CHECK(call_at_offset(vt, 0x38, &args, &out) == FM5_PAIRING_S_OK);
        CHECK(out == (void *)&user_new && out != (void *)&controller);
        out = NULL;
        CHECK(call_at_offset(vt, 0x40, &args, &out) == FM5_PAIRING_S_OK);
        CHECK(out == (void *)&previous && out != (void *)&controller);

        /* Cada consulta toma a SUA referência: 2 chamadas = 2 AddRef. */
        CHECK(controller.addrefs == 2);
        CHECK(user_new.addrefs == 2);
        CHECK(previous.addrefs == 2);
    }

    /*
     * FASE 2 (rebaixamento): User = NULL, PreviousUser = P1, Controller* real.
     * 0x30 tem de devolver o Controller do dispositivo e 0x38 tem de devolver
     * NULL (S_OK) — o par que 0x1406763a0 consome para gravar o User* NULL.
     */
    sentinel_init(&user_new);
    sentinel_init(&previous);
    sentinel_init(&controller);
    {
        fm5_pairing_args_t args;
        void *out = (void *)0x1;

        fm5_pairing_args_init(&args, NULL, &previous, &controller, test_addref);

        CHECK(call_at_offset(vt, 0x30, &args, &out) == FM5_PAIRING_S_OK);
        CHECK(out == (void *)&controller);
        CHECK(controller.addrefs == 1);

        out = (void *)0x1;
        CHECK(call_at_offset(vt, 0x38, &args, &out) == FM5_PAIRING_S_OK);
        CHECK(out == NULL);
        CHECK(user_new.addrefs == 0 && previous.addrefs == 0);

        out = (void *)0x1;
        CHECK(call_at_offset(vt, 0x40, &args, &out) == FM5_PAIRING_S_OK);
        CHECK(out == (void *)&previous);
        CHECK(previous.addrefs == 1);

        /* E_POINTER pelo deslocamento bruto: nunca escreve em 0x0. */
        CHECK(call_at_offset(vt, 0x30, &args, NULL) == FM5_PAIRING_E_POINTER);
        CHECK(call_at_offset(vt, 0x38, &args, NULL) == FM5_PAIRING_E_POINTER);
        CHECK(call_at_offset(vt, 0x40, &args, NULL) == FM5_PAIRING_E_POINTER);
    }
}

/*
 * Ownership do Controller* (e do User*) entregue pelos slots 6/7/8.
 *
 * O args NÃO é dono dos ponteiros: quem monta o evento (dispatch_pairing_changed)
 * mantém a referência forte e a solta depois do dispatch; o slot apenas faz
 * AddRef por consulta, entregando ao jogo uma referência que ele deve soltar.
 * Se o args também soltasse, o Release do chamador viraria double-free. Este
 * teste prova, com sentinelas de contagem real, as duas metades do contrato:
 *   - toda consulta = 1 AddRef;
 *   - destruir o args = 0 Release (nada de double-free no Controller* do
 *     device que o chamador ainda referencia).
 */
static void test_controller_ownership(void)
{
    const fm5_pairing_args_vt_t *vt = fm5_pairing_args_vtbl();
    sentinel_t user;
    sentinel_t previous;
    sentinel_t controller;
    fm5_pairing_args_t *heap;
    void *out = NULL;

    sentinel_init(&user);
    sentinel_init(&previous);
    sentinel_init(&controller);

    heap = fm5_pairing_args_create(&user, &previous, &controller, test_addref);
    CHECK(heap != NULL);
    if (!heap) {
        return;
    }

    /* Consumo no formato do handler: 0x30 (Controller) por último. */
    CHECK(call_at_offset(vt, 0x30, heap, &out) == FM5_PAIRING_S_OK);
    CHECK(out == (void *)&controller);
    out = NULL;
    CHECK(call_at_offset(vt, 0x38, heap, &out) == FM5_PAIRING_S_OK);
    CHECK(out == (void *)&user);
    out = NULL;
    CHECK(call_at_offset(vt, 0x40, heap, &out) == FM5_PAIRING_S_OK);
    CHECK(out == (void *)&previous);

    CHECK(controller.addrefs == 1);
    CHECK(user.addrefs == 1);
    CHECK(previous.addrefs == 1);

    /* Destruir o args (Release final do heap) NÃO pode soltar os objetos: o
     * chamador ainda é dono das referências fortes da tabela por device. */
    CHECK(fm5_pairing_args_release(heap) == 0);
    CHECK(controller.releases == 0);
    CHECK(user.releases == 0);
    CHECK(previous.releases == 0);

    /* E o chamador solta exatamente as referências que os slots entregaram. */
    sentinel_release(&controller);
    sentinel_release(&user);
    sentinel_release(&previous);
    CHECK(controller.releases == 1 && controller.addrefs == 1);
    CHECK(user.releases == 1 && user.addrefs == 1);
    CHECK(previous.releases == 1 && previous.addrefs == 1);
}

static void test_properties(void)
{
    const fm5_pairing_args_vt_t *vt = fm5_pairing_args_vtbl();
    sentinel_t new_user;
    sentinel_t previous_user;
    sentinel_t controller;
    fm5_pairing_args_t args;
    void *out = (void *)0x1;

    sentinel_init(&new_user);
    sentinel_init(&previous_user);
    sentinel_init(&controller);

    /* Controle REBAIXADO: User = NULL, PreviousUser = P1 nativo. */
    fm5_pairing_args_init(&args, NULL, &previous_user, NULL, test_addref);

    out = (void *)0x1;
    CHECK(vt_get_user(vt, &args, &out) == FM5_PAIRING_S_OK);
    CHECK(out == NULL); /* S_OK + NULL = "sem perfil", nunca erro */

    out = (void *)0x1;
    CHECK(vt_get_previous_user(vt, &args, &out) == FM5_PAIRING_S_OK);
    CHECK(out == (void *)&previous_user);
    CHECK(previous_user.addrefs == 1); /* ownership entregue ao jogo */

    out = (void *)0x1;
    CHECK(vt_get_controller(vt, &args, &out) == FM5_PAIRING_S_OK);
    CHECK(out == NULL);
    CHECK(controller.addrefs == 0);

    /* E_POINTER em todas as propriedades (nunca AV em 0x0). */
    CHECK(vt_get_user(vt, &args, NULL) == FM5_PAIRING_E_POINTER);
    CHECK(vt_get_previous_user(vt, &args, NULL) == FM5_PAIRING_E_POINTER);
    CHECK(vt_get_controller(vt, &args, NULL) == FM5_PAIRING_E_POINTER);
    CHECK(fm5_pairing_args_get_user(NULL, &out) == FM5_PAIRING_E_FAIL);
    CHECK(fm5_pairing_args_get_previous_user(NULL, &out) ==
          FM5_PAIRING_E_FAIL);
    CHECK(fm5_pairing_args_get_controller(NULL, &out) == FM5_PAIRING_E_FAIL);

    /* Eleição do P2: User virtual novo + Controller disponível. */
    fm5_pairing_args_init(&args, &new_user, &previous_user, &controller,
                          test_addref);
    out = NULL;
    CHECK(vt_get_user(vt, &args, &out) == FM5_PAIRING_S_OK);
    CHECK(out == (void *)&new_user);
    CHECK(new_user.addrefs == 1);
    out = NULL;
    CHECK(vt_get_controller(vt, &args, &out) == FM5_PAIRING_S_OK);
    CHECK(out == (void *)&controller);
    CHECK(controller.addrefs == 1);
    out = NULL;
    CHECK(vt_get_previous_user(vt, &args, &out) == FM5_PAIRING_S_OK);
    CHECK(out == (void *)&previous_user);
    CHECK(previous_user.addrefs == 2); /* 1 da fase anterior + 1 agora */

    /* Objeto presente sem callback de AddRef (init direto) não explode. */
    fm5_pairing_args_init(&args, &new_user, &previous_user, &controller, NULL);
    out = NULL;
    CHECK(vt_get_user(vt, &args, &out) == FM5_PAIRING_S_OK);
    CHECK(out == (void *)&new_user);

    /* PreviousUser indisponível (UserStatics+0x18 vazio): S_OK + NULL — o
     * contrato do console para "sem usuário anterior", nunca erro nem
     * ponteiro inventado. */
    fm5_pairing_args_init(&args, &new_user, NULL, &controller, test_addref);
    out = (void *)0x1;
    CHECK(vt_get_previous_user(vt, &args, &out) == FM5_PAIRING_S_OK);
    CHECK(out == NULL);
    /* E o User novo continua sendo o do P2, não o PreviousUser ausente. */
    out = NULL;
    CHECK(vt_get_user(vt, &args, &out) == FM5_PAIRING_S_OK);
    CHECK(out == (void *)&new_user);
    CHECK(new_user.addrefs == 2); /* 1 da fase P2 + 1 desta consulta */
}

static void test_inspectable(void)
{
    const fm5_pairing_args_vt_t *vt = fm5_pairing_args_vtbl();
    fm5_pairing_args_t args;
    uint8_t bogus_iid[16] = { 0x11, 0x22, 0x33 };
    uint32_t count = 7;
    void *iids = (void *)0x1;
    void *name = (void *)0x1;
    int32_t trust = -1;
    void *out = NULL;

    fm5_pairing_args_init(&args, NULL, NULL, NULL, test_addref);

    /* QI IUnknown */
    CHECK(vt->query_interface(&args, fm5_pairing_iid_iunknown, &out) ==
          FM5_PAIRING_S_OK);
    CHECK(out == (void *)&args);
    CHECK(args.refcount == 2); /* AddRef no QI */
    CHECK(vt->release(&args) == 1);

    /* QI IInspectable */
    out = NULL;
    CHECK(vt->query_interface(&args, fm5_pairing_iid_iinspectable, &out) ==
          FM5_PAIRING_S_OK);
    CHECK(out == (void *)&args);
    CHECK(args.refcount == 2);
    CHECK(vt->release(&args) == 1);

    /* QI de IID desconhecido: E_NOINTERFACE + *out = NULL. */
    out = (void *)0x1;
    CHECK(vt->query_interface(&args, bogus_iid, &out) ==
          FM5_PAIRING_E_NOINTERFACE);
    CHECK(out == NULL);
    CHECK(args.refcount == 1); /* nenhum AddRef no caminho de falha */

    /* QI compara 16 bytes EXATOS: um IID que difere em UM único byte não
     * pode passar. Sem isso, um prefixo/sufixo coincidente reintroduziria a
     * confusão de tipos que causou o STATUS_ACCESS_VIOLATION original. */
    {
        uint8_t near_miss[16];

        memcpy(near_miss, fm5_pairing_iid_iinspectable, 16);
        near_miss[15] ^= 0xFFu;
        out = (void *)0x1;
        CHECK(vt->query_interface(&args, near_miss, &out) ==
              FM5_PAIRING_E_NOINTERFACE);
        CHECK(out == NULL);
        CHECK(args.refcount == 1); /* nenhum AddRef no caminho de falha */

        memcpy(near_miss, fm5_pairing_iid_iunknown, 16);
        near_miss[0] ^= 0x01u;
        out = (void *)0x1;
        CHECK(vt->query_interface(&args, near_miss, &out) ==
              FM5_PAIRING_E_NOINTERFACE);
        CHECK(out == NULL);
        CHECK(args.refcount == 1);
    }

    /* Argumentos inválidos do QI. */
    CHECK(vt->query_interface(&args, fm5_pairing_iid_iunknown, NULL) ==
          FM5_PAIRING_E_POINTER);
    out = (void *)0x1;
    CHECK(vt->query_interface(&args, NULL, &out) == FM5_PAIRING_E_POINTER);
    CHECK(out == NULL);
    out = (void *)0x1;
    CHECK(vt->query_interface(NULL, fm5_pairing_iid_iunknown, &out) ==
          FM5_PAIRING_E_FAIL);
    CHECK(out == NULL);

    /* IInspectable: GetIids / GetRuntimeClassName / GetTrustLevel. */
    CHECK(vt->get_iids(&args, &count, &iids) == FM5_PAIRING_S_OK);
    CHECK(count == 0);
    CHECK(iids == NULL);
    CHECK(vt->get_iids(&args, NULL, &iids) == FM5_PAIRING_E_POINTER);
    CHECK(vt->get_iids(&args, &count, NULL) == FM5_PAIRING_E_POINTER);

    CHECK(vt->get_runtime_class(&args, &name) == FM5_PAIRING_S_OK);
    CHECK(name == NULL);
    CHECK(vt->get_runtime_class(&args, NULL) == FM5_PAIRING_E_POINTER);

    CHECK(vt->get_trust_level(&args, &trust) == FM5_PAIRING_S_OK);
    CHECK(trust == FM5_PAIRING_TRUST_LEVEL_BASE);
    CHECK(vt->get_trust_level(&args, NULL) == FM5_PAIRING_E_POINTER);
}

static void test_stubs(void)
{
    const fm5_pairing_args_vt_t *vt = fm5_pairing_args_vtbl();
    fm5_pairing_args_t args;

    fm5_pairing_args_init(&args, NULL, NULL, NULL, test_addref);

    /* Slots 9..12: nunca estouram a vtable; devolvem E_NOTIMPL. */
    CHECK(vt->slot9(&args, NULL, NULL) == FM5_PAIRING_E_NOTIMPL);
    CHECK(vt->slot10(&args, NULL, NULL) == FM5_PAIRING_E_NOTIMPL);
    CHECK(vt->slot11(&args, NULL, NULL) == FM5_PAIRING_E_NOTIMPL);
    CHECK(vt->slot12(&args, NULL, NULL) == FM5_PAIRING_E_NOTIMPL);
    CHECK(fm5_pairing_args_stub(&args, NULL, NULL) == FM5_PAIRING_E_NOTIMPL);
    /* O stub não escreve nos parâmetros: um escalar passado por engano
     * permanece intacto. */
    {
        uint64_t canary = 0xA5A5A5A5A5A5A5A5ULL;
        CHECK(vt->slot9(&args, &canary, NULL) == FM5_PAIRING_E_NOTIMPL);
        CHECK(canary == 0xA5A5A5A5A5A5A5A5ULL);
    }
}

static int g_destroy_calls;

static void test_destroy(fm5_pairing_args_t *self)
{
    (void)self;
    g_destroy_calls++;
}

static void test_lifecycle(void)
{
    const fm5_pairing_args_vt_t *vt = fm5_pairing_args_vtbl();
    fm5_pairing_args_t *heap;
    fm5_pairing_args_t stack;
    sentinel_t user;

    sentinel_init(&user);

    /* Sem callback de AddRef a fábrica falha fechada (não publica objeto que
     * devolveria ponteiros sem ownership). */
    CHECK(fm5_pairing_args_create(&user, NULL, NULL, NULL) == NULL);

    heap = fm5_pairing_args_create(&user, &user, NULL, test_addref);
    CHECK(heap != NULL);
    CHECK(heap->refcount == 1);
    CHECK(*(void ***)heap == (void **)fm5_pairing_args_vtbl());
    CHECK(fm5_pairing_args_addref(heap) == 2);
    CHECK(fm5_pairing_args_release(heap) == 1);
    CHECK(fm5_pairing_args_release(heap) == 0); /* libera o heap */

    /* AddRef/Release de NULL são no-op (0). */
    CHECK(fm5_pairing_args_addref(NULL) == 0);
    CHECK(fm5_pairing_args_release(NULL) == 0);

    /* Objeto de pilha: Release NÃO tenta liberar memória do chamador, mas o
     * destroy configurado é chamado exatamente uma vez no zero. */
    g_destroy_calls = 0;
    fm5_pairing_args_init(&stack, &user, NULL, NULL, test_addref);
    stack.destroy = test_destroy;
    CHECK(fm5_pairing_args_addref(&stack) == 2);
    CHECK(fm5_pairing_args_release(&stack) == 1);
    CHECK(g_destroy_calls == 0);
    CHECK(fm5_pairing_args_release(&stack) == 0);
    CHECK(g_destroy_calls == 1);

    /* O MESMO par AddRef/Release, mas pelo slot PUBLICADO na vtable (é o
     * caminho que o runtime do jogo usa ao soltar o args, não o atalho
     * exportado do teste). destroy continua acontecendo exatamente 1x. */
    g_destroy_calls = 0;
    fm5_pairing_args_init(&stack, &user, NULL, NULL, test_addref);
    stack.destroy = test_destroy;
    CHECK(vt->add_ref(&stack) == 2);
    CHECK(vt->release(&stack) == 1);
    CHECK(g_destroy_calls == 0);
    CHECK(vt->release(&stack) == 0);
    CHECK(g_destroy_calls == 1);
    /* Release extra não deve chamar destroy de novo (refcount já em 0). */
    CHECK(vt->release(NULL) == 0);
}

/* ------------------------------------------------------------------------- */
/* Snapshots por índice — alvo do evento de pareamento (TICKET-HARNESS-171)   */
/* ------------------------------------------------------------------------- */
/*
 * O evento ControllerPairingChanged do controle secundário precisa de um User
 * VÁLIDO: 0x140675e10 aborta em 140675e3e quando args->get_User() == NULL.
 * Portanto o alvo do evento é o conjunto de controles do índice 1 (Player 2
 * virtual), não mais um conjunto "neutro".
 */
static void test_controller_snapshots(void)
{
    fm5_identity_t id;
    int dev_a = 0x11;
    int dev_b = 0x22;
    int dev_c = 0x33;
    void *keys[FM5_P2_MAX_CONTROLLERS];
    int n;
    int index = -1;

    fm5_identity_init(&id, 2, "Player 2");

    /* Registra os três controles ainda na FASE 1 (todos índice 0). */
    CHECK(fm5_identity_index_for_controller(&id, &dev_a) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &dev_b) == 0);
    CHECK(fm5_identity_index_for_controller(&id, &dev_c) == 0);
    /* Antes do A não existe secundário nem rebaixado. */
    memset(keys, 0, sizeof(keys));
    CHECK(fm5_identity_controllers_for_index(&id, 1, keys,
                                             FM5_P2_MAX_CONTROLLERS) == 0);
    CHECK(fm5_identity_demoted_controllers(&id, keys,
                                           FM5_P2_MAX_CONTROLLERS) == 0);

    /* Primeiro A no dev_a: dev_b vira Player 2 virtual (índice 1) e dev_c cai
     * para o índice 2 (sem canal de usuário). */
    CHECK(fm5_identity_cascade_claim(&id, &dev_a, FM5_IDENTITY_BUTTON_A,
                                     &index) == FM5_CASCADE_P1_ELECTED);
    CHECK(index == 0);
    memset(keys, 0, sizeof(keys));
    n = fm5_identity_controllers_for_index(&id, 1, keys,
                                           FM5_P2_MAX_CONTROLLERS);
    CHECK(n == 1);
    CHECK(keys[0] == &dev_b);
    memset(keys, 0, sizeof(keys));
    n = fm5_identity_demoted_controllers(&id, keys, FM5_P2_MAX_CONTROLLERS);
    CHECK(n == 1);
    CHECK(keys[0] == &dev_c);
    CHECK(fm5_identity_is_assigned_controller(&id, &dev_a) == 1);
    CHECK(fm5_identity_is_assigned_controller(&id, &dev_b) == 1);
    /* O Player 1 nunca aparece em nenhum dos dois snapshots. */
    memset(keys, 0, sizeof(keys));
    CHECK(fm5_identity_controllers_for_index(&id, 0, keys,
                                             FM5_P2_MAX_CONTROLLERS) == 1);
    CHECK(keys[0] == &dev_a);
    /* Total > cap: só as primeiras chaves são copiadas. */
    CHECK(fm5_identity_demoted_controllers(&id, keys, 0) == 0);

    /* Start do dev_b: confirma o P2 no índice 1; snapshots não mudam. */
    CHECK(fm5_identity_cascade_claim(&id, &dev_b, FM5_IDENTITY_BUTTON_MENU,
                                     &index) == FM5_CASCADE_P2_ELECTED);
    CHECK(index == 1);
    CHECK(fm5_identity_p2_locked(&id) == 1);
    memset(keys, 0, sizeof(keys));
    CHECK(fm5_identity_controllers_for_index(&id, 1, keys,
                                             FM5_P2_MAX_CONTROLLERS) == 1);
    CHECK(keys[0] == &dev_b);
    CHECK(fm5_identity_demoted_controllers(&id, keys,
                                           FM5_P2_MAX_CONTROLLERS) == 1);

    /* Argumentos inválidos: zero, sem efeito colateral. */
    CHECK(fm5_identity_controllers_for_index(NULL, 1, keys, 3) == 0);
    CHECK(fm5_identity_controllers_for_index(&id, 1, NULL, 3) == 0);
    CHECK(fm5_identity_controllers_for_index(&id, 1, keys, 0) == 0);
    CHECK(fm5_identity_controllers_for_index(&id, -1, keys, 3) == 0);
    CHECK(fm5_identity_demoted_controllers(NULL, keys, 3) == 0);
    CHECK(fm5_identity_demoted_controllers(&id, NULL, 3) == 0);
    CHECK(fm5_identity_demoted_controllers(&id, keys, 0) == 0);

    fm5_identity_destroy(&id);
}

int main(void)
{
    test_layout();
    test_abi_byte_offsets();
    test_controller_ownership();
    test_properties();
    test_inspectable();
    test_stubs();
    test_lifecycle();
    test_controller_snapshots();

    if (g_failures) {
        fprintf(stderr, "FALHA: %d/%d verificacoes de pairing falharam\n",
                g_failures, g_checks);
        return 1;
    }
    printf("OK: %d verificacoes do args de ControllerPairingChanged "
           "passaram\n", g_checks);
    return 0;
}
