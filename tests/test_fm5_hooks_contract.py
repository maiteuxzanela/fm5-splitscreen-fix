#!/usr/bin/env python3
"""
test_fm5_hooks_contract.py — contrato de FIAÇÃO da camada Windows-only
(fm5_hooks.c) do TICKET-HARNESS-168.

Por que este teste existe
-------------------------
A camada de hooks não compila no host Linux (windows.h, SRWLOCK, patch de
vtable sobre o módulo carregado). A lógica *portátil* que ela consome é
exercitada de verdade (e sem mocks) por test_fm5_identity.c,
test_fm5_contract.c e test_fm5_systemui.c; o que resta é a FIAÇÃO: qual slot
de vtable recebe qual handler, em que ordem o guard `p1_locked` precede a
materialização, quantos AddRef o caminho do AccountPicker faz, e como o evento
de pareamento falha fechado.

Este teste é DETERMINÍSTICO e não simula comportamento: ele lê o fonte real e
verifica invariantes literais de semântica. A sensibilidade dessas verificações
é provada por test_mutation_sensitivity.py, que aplica cada regressão numa
cópia isolada e exige que ESTE arquivo reprove.

Não usa rede, não usa mock, não executa Win32.
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "fm5-p2", "src", "fm5_hooks.c")

failures = []
checks = 0


def must(cond, msg):
    global checks
    checks += 1
    if not cond:
        failures.append(msg)


def function_body(src, signature):
    """Corpo entre chaves da primeira ocorrência de `signature` (por chaves)."""
    start = src.find(signature)
    if start < 0:
        return None
    brace = src.find("{", start)
    if brace < 0:
        return None
    depth = 0
    for i in range(brace, len(src)):
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[brace:i + 1]
    return None


def definition_body(text, signature):
    """Corpo da DEFINIÇÃO: ignora a declaração forward (que termina em ';')."""
    pos = 0
    while True:
        i = text.find(signature, pos)
        if i < 0:
            return None
        j = i + len(signature)
        while j < len(text) and text[j] in " \t\r\n":
            j += 1
        if j < len(text) and text[j] == "{":
            return function_body(text[i:], signature)
        pos = i + 1


def ordered(body, *tokens):
    """True se todos os tokens aparecem, em ordem crescente de posição."""
    pos = -1
    for tok in tokens:
        nxt = body.find(tok, pos + 1)
        if nxt < 0:
            return False
        pos = nxt
    return True


def count(body, token):
    return body.count(token)


def define_int(src, name):
    m = re.search(r"#define\s+%s\s+(0x[0-9A-Fa-f]+|\d+)u?" % re.escape(name),
                  src)
    if not m:
        return None
    return int(m.group(1), 0)


def main():
    if not os.path.isfile(SRC):
        print("FALHA: fm5_hooks.c ausente em %s" % SRC)
        return 1
    with open(SRC, "r", encoding="utf-8") as f:
        src = f.read()

    # ------------------------------------------------------------------ #
    # 1) Mapa de slots/RVAs da identidade Guest (vtable de User)          #
    # ------------------------------------------------------------------ #
    must(define_int(src, "RVA_VT_USER") == 0x6C0B48,
         "RVA_VT_USER != 0x6c0b48 (vtable de User do build 1.0.4)")
    must(define_int(src, "RVA_USER_IS_GUEST") == 0x042080,
         "RVA_USER_IS_GUEST != 0x042080 (User::get_IsGuest)")
    must(define_int(src, "RVA_USER_XBOX_USER_HASH") == 0x042100,
         "RVA_USER_XBOX_USER_HASH != 0x042100")
    must(define_int(src, "RVA_USER_XBOX_USER_ID") == 0x042150,
         "RVA_USER_XBOX_USER_ID != 0x042150")
    must(define_int(src, "USER_VT_IS_GUEST") == 10,
         "get_IsGuest deve estar no slot 10 da vtable de User")
    must(define_int(src, "USER_VT_XBOX_USER_HASH") == 14,
         "get_XboxUserHash deve estar no slot 14 da vtable de User")
    must(define_int(src, "USER_VT_XBOX_USER_ID") == 15,
         "get_XboxUserId deve estar no slot 15 da vtable de User")

    install = function_body(src, "install_user_guest_vtable(void)")
    must(install is not None, "install_user_guest_vtable ausente")
    if install:
        # Ordem canônica dos três slots (o mesmo índice usado em want[]).
        must(ordered(install, "USER_VT_IS_GUEST", "USER_VT_XBOX_USER_HASH",
                     "USER_VT_XBOX_USER_ID"),
             "install_user_guest_vtable: ordem dos slots divergente")
        must(ordered(install, "RVA_USER_IS_GUEST", "RVA_USER_XBOX_USER_HASH",
                     "RVA_USER_XBOX_USER_ID"),
             "install_user_guest_vtable: ordem dos RVAs esperados divergente")
        # Fail-closed: cada slot é CONFERIDO antes de ser escrito.
        must(count(install, "check_vtable_range(") == 1,
             "install_user_guest_vtable: validacao previa unica ausente")
        must(ordered(install, "check_vtable_range(", "write_vtable_range("),
             "install_user_guest_vtable: escreve slot antes de validar")
        must(count(install, "write_vtable_range(") == 2,
             "install_user_guest_vtable: esperado 1 escrita + 1 rollback")
        # Rollback dos slots ja trocados.
        must("while (done > 0)" in install and "&orig[done]" in install,
             "install_user_guest_vtable: rollback dos slots ausente")
        # Handlers por slot, na ordem [guest, hash, id].
        must(ordered(install, "hook_user_is_guest", "hook_user_xbox_user_hash",
                     "hook_user_xbox_user_id"),
             "install_user_guest_vtable: handlers fora da ordem dos slots")
        # Os getters nativos originais sao preservados para delegacao do P1.
        must("g_orig_user_is_guest = (bool_getter_fn)orig[0];" in install,
             "getter nativo de IsGuest nao preservado para delegacao")
        must("g_orig_user_xbox_user_hash = (hstring_getter_fn)orig[1];"
             in install, "getter nativo de XboxUserHash nao preservado")
        must("g_orig_user_xbox_user_id = (hstring_getter_fn)orig[2];"
             in install, "getter nativo de XboxUserId nao preservado")

    # ------------------------------------------------------------------ #
    # 2) get_IsGuest: P2 virtual == 1, P1/desconhecido delegam ao nativo  #
    # ------------------------------------------------------------------ #
    is_guest = function_body(src, "hook_user_is_guest(void *self, uint8_t *out)")
    must(is_guest is not None, "hook_user_is_guest ausente")
    if is_guest:
        must("int index = index_for_user_object(self);" in is_guest,
             "get_IsGuest: indice nao resolvido por index_for_user_object")
        must("if (index >= 1 && fm5_identity_is_guest(&g_identity, index)) {"
             in is_guest,
             "get_IsGuest: guarda 'index >= 1 && is_guest' ausente (P1 seria "
             "classificado como Convidado ou o virtual perderia o slot)")
        must("*out = 1;" in is_guest,
             "get_IsGuest: nao escreve 1 para o Player 2 virtual")
        must("return S_OK;" in is_guest,
             "get_IsGuest: nao devolve S_OK no caminho virtual")
        must("(HRESULT)0x80004003" in is_guest and "*out" in is_guest,
             "get_IsGuest: E_POINTER para out NULL ausente")
        must("return g_orig_user_is_guest(self, out);" in is_guest,
             "get_IsGuest: P1/desconhecido nao delegam ao corpo nativo")
        must("if (!g_orig_user_is_guest)" in is_guest,
             "get_IsGuest: fail-closed sem getter nativo ausente")

    # ------------------------------------------------------------------ #
    # 3) XboxUserHash / XboxUserId: valores distintos para P2 vs P1       #
    # ------------------------------------------------------------------ #
    for fn, sig, core in (
        ("XboxUserHash", "hook_user_xbox_user_hash(void *self, void **out)",
         "fm5_identity_xbox_user_hash"),
        ("XboxUserId", "hook_user_xbox_user_id(void *self, void **out)",
         "fm5_identity_xbox_user_id"),
    ):
        body = function_body(src, sig)
        must(body is not None, "hook_user_%s ausente" % fn)
        if body:
            must("int index = index_for_user_object(self);" in body,
                 "%s: indice nao resolvido por index_for_user_object" % fn)
            must("if (index >= 1 &&" in body,
                 "%s: guarda 'index >= 1' ausente — P1 receberia hash/XUID "
                 "virtual" % fn)
            must("%s(&g_identity, index, text, sizeof(text))" % core in body,
                 "%s: nao consulta o nucleo portatil %s" % (fn, core))
            must("return serve_virtual_hstring(text, out);" in body,
                 "%s: nao materializa a HSTRING do valor virtual" % fn)
            must("return g_orig_user_%s(self, out);"
                 % ("xbox_user_hash" if fn == "XboxUserHash"
                    else "xbox_user_id") in body,
                 "%s: P1/desconhecido nao delegam ao corpo nativo" % fn)

    resolver = function_body(src, "index_for_user_object(void *self)")
    must(resolver is not None, "index_for_user_object ausente")
    if resolver:
        must("fm5_identity_index_for_native_user(&g_identity, self)"
             in resolver,
             "index_for_user_object: nao reconhece o User virtual do nucleo")
        must("statics_singleton()" in resolver,
             "index_for_user_object: nao consulta o singleton de UserStatics")
        must("STATICS_USER_OFFSET" in resolver,
             "index_for_user_object: nao compara com UserStatics+0x18 (P1)")
        must("return 0;" in resolver,
             "index_for_user_object: P1 nativo nao mapeado ao indice 0")
        must("return -1;" in resolver,
             "index_for_user_object: objeto desconhecido nao mapeado a -1")

    # ------------------------------------------------------------------ #
    # 4) Hook de MakeAccountPickerUser (0x4c8030): P2 virtual + 1 AddRef  #
    # ------------------------------------------------------------------ #
    must(define_int(src, "RVA_MAKE_ACCOUNT_PICKER_USER") == 0x4C8030,
         "RVA_MAKE_ACCOUNT_PICKER_USER != 0x4c8030")
    m = re.search(r"EXPECT_MAKE_ACCOUNT_PICKER\[16\]\s*=\s*\{(.*?)\};",
                  src, re.S)
    must(m is not None, "EXPECT_MAKE_ACCOUNT_PICKER[16] ausente")
    if m:
        raw = re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1))
        expect = "40534883ec20e845a9b7ff90488b5818"
        must("".join(x.lower() for x in raw) == expect,
             "prologue do detour 0x4c8030 divergente: %s != %s"
             % ("".join(raw), expect))
        must(len(raw) == 16,
             "detour de 0x4c8030 deve cobrir exatamente 16 bytes (obtido %d)"
             % len(raw))
        # O rel32 fica em +6; retomada em +16 = `test rbx,rbx`.
        must(raw[6].lower() == "e8",
             "0x4c8030: byte +6 nao e o CALL rel32 do patch")

    picker = function_body(src, "hook_make_account_picker_user(void)")
    must(picker is not None, "hook_make_account_picker_user ausente")
    if picker:
        # Guard: so depois do P1 eleito o P2 virtual e servido.
        must("if (g_orig_account_picker && "
             "fm5_identity_p1_locked(&g_identity)) {" in picker,
             "AccountPicker: guarda 'trampolim && p1_locked' ausente")
        # Materializa exatamente o indice 1 (Player 2).
        must("materialize_virtual_user(NULL, &g_identity, 1)" in picker,
             "AccountPicker: nao materializa o User virtual do indice 1")
        # AddRef exatamente uma vez, ANTES de devolver, e so no caminho virtual.
        must(count(picker, "com_addref(user);") == 1,
             "AccountPicker: com_addref deve ocorrer exatamente 1x no corpo "
             "(obtido %d)" % count(picker, "com_addref(user);"))
        must(ordered(picker, "materialize_virtual_user(NULL, &g_identity, 1)",
                     "com_addref(user);", "return user;"),
             "AccountPicker: AddRef nao ocorre entre materializar e devolver")
        must("if (user)" in picker,
             "AccountPicker: AddRef nao esta condicionado a materializacao")
        # Sem virtual / sem p1_locked: trampolim nativo (nunca NULL silencioso
        # quando o original existe).
        must("return g_orig_account_picker ? g_orig_account_picker() : NULL;"
             in picker,
             "AccountPicker: fallback para o trampolim nativo ausente")
        must(count(picker, "com_addref(") == 1,
             "AccountPicker: AddRef tambem no caminho do trampolim (refcount "
             "do nativo seria corrompido)")

    # ------------------------------------------------------------------ #
    # 5) ControllerStatics: slots 7..12 e evento de pareamento fail-closed #
    # ------------------------------------------------------------------ #
    must(define_int(src, "RVA_VT_CONTROLLER_STATICS") == 0x6ED8B8,
         "vtable de ControllerStatics != 0x6ed8b8")
    for name, rva in (
        ("RVA_CTRL_ADDED_ADD", 0x19B9C0),
        ("RVA_CTRL_ADDED_REMOVE", 0x19B9E0),
        ("RVA_CTRL_REMOVED_ADD", 0x19BA00),
        ("RVA_CTRL_REMOVED_REMOVE", 0x19BA20),
        ("RVA_CTRL_PAIRING_ADD", 0x19BA40),
        ("RVA_CTRL_PAIRING_REMOVE", 0x19BA60),
    ):
        must(define_int(src, name) == rva,
             "%s divergente do thunk do build 1.0.4" % name)
    must(define_int(src, "RVA_CTRL_STATICS_SINGLETON") == 0x19BE70,
         "singleton de ControllerStatics != 0x19be70")

    ctrl_install = function_body(src, "install_controller_event_vtable(void)")
    must(ctrl_install is not None, "install_controller_event_vtable ausente")
    if ctrl_install:
        must("check_vtable_range(RVA_VT_CONTROLLER_STATICS, 7, want, 6)"
             in ctrl_install,
             "ControllerStatics: slots 7..12 nao validados antes do patch")
        must("write_vtable_range(RVA_VT_CONTROLLER_STATICS, 7, handlers, 6)"
             in ctrl_install,
             "ControllerStatics: patch dos 6 slots ausente")
        must(ordered(ctrl_install, "hook_ctrl_added_add",
                     "hook_ctrl_added_remove", "hook_ctrl_removed_add",
                     "hook_ctrl_removed_remove", "hook_ctrl_pairing_add",
                     "hook_ctrl_pairing_remove"),
             "ControllerStatics: handlers fora da ordem add/remove dos slots")

    # ------------------------------------------------------------------ #
    # 5b) TICKET-HARNESS-169 — args COM legítimo do evento de pareamento  #
    # ------------------------------------------------------------------ #
    dispatch = function_body(src, "dispatch_pairing_changed(void *new_user, "
                                   "void *controller)")
    must(dispatch is not None, "dispatch_pairing_changed ausente")
    if dispatch:
        # Sem handlers, nada e invocado (fail-closed) e o fato e logado.
        must("if (n <= 0)" in dispatch and "fail-closed" in dispatch,
             "ControllerPairingChanged: caminho sem handlers nao e fail-closed")
        # Referencia propria antes de invocar; Release depois.
        must(ordered(dispatch, "com_addref(handlers[i]);",
                     "sender = statics_controller_singleton();",
                     "com_release(handlers[i]);"),
             "ControllerPairingChanged: ordem AddRef -> invoke -> Release "
             "divergente")
        must("if (!sender)" in dispatch,
             "ControllerPairingChanged: sender nulo nao e tratado")
        # O args e um objeto sintetizado de verdade (IControllerPairingChanged-
        # EventArgs), com PreviousUser = User nativo do P1.
        must("p1_native_user_ref()" in dispatch,
             "ControllerPairingChanged: PreviousUser (P1 nativo) nao resolvido")
        must("fm5_pairing_args_create(new_user, previous_user, controller,"
             in dispatch,
             "ControllerPairingChanged: args nao fabricado por "
             "fm5_pairing_args_create(user, previous_user, controller, ...)")
        must("com_addref)" in dispatch,
             "ControllerPairingChanged: args nao recebe com_addref como "
             "callback de AddRef")
        # O delegate recebe o ARGS (nunca o sender, que era o crash).
        must("((invoke_fn)vt[3])(handlers[i], sender, args)" in dispatch,
             "ControllerPairingChanged: invoke nao entrega o args sintetizado")
        must("sender, sender" not in dispatch,
             "ControllerPairingChanged: args ainda e o sender (crash "
             "STATUS_ACCESS_VIOLATION no handler do jogo)")
        must(ordered(dispatch, "((invoke_fn)vt[3])(handlers[i], sender, args)",
                     "fm5_pairing_args_release(args);"),
             "ControllerPairingChanged: args nao e liberado apos o dispatch")
        must("hr=0x%08lx" in dispatch,
             "ControllerPairingChanged: HRESULT do handler nao e logado")
        must("vt && vt[3]" in dispatch,
             "ControllerPairingChanged: invoke sem checar slot 3 do delegate")
        must("com_release(previous_user);" in dispatch,
             "ControllerPairingChanged: referencia do PreviousUser vazando")

    pair = function_body(src, "notify_pairing_changed(void)")
    must(pair is not None, "notify_pairing_changed ausente")
    if pair:
        # Kill-switch antes de qualquer efeito.
        idx_switch = pair.find("if (g_pairing_event_disabled)")
        idx_effect = pair.find("fm5_identity_p2_locked(&g_identity)")
        must(idx_switch >= 0 and idx_effect >= 0 and idx_switch < idx_effect,
             "ControllerPairingChanged: kill-switch nao e o primeiro efeito")
        # TICKET-HARNESS-171: FASE 2 (pos-A) entrega o User VIRTUAL do indice 1
        # ao controle secundario. Um User NULL faria o Forza abortar o evento
        # em 140675e3e (je 0x140675f67) e o segundo controle continuaria P1.
        must("fm5_identity_controllers_for_index(&g_identity, 1, keys,"
             in pair,
             "ControllerPairingChanged: controles do indice 1 (Player 2 "
             "virtual) nao enumerados")
        must(ordered(pair,
                     "fm5_identity_controllers_for_index(&g_identity, 1, keys,",
                     "materialize_virtual_user(NULL, &g_identity, 1)",
                     "dispatch_pairing_for_keys(keys, total, new_user)"),
             "ControllerPairingChanged: o secundario nao recebe o User virtual "
             "materializado (User NULL aborta o evento no jogo)")
        must("if (!new_user)" in pair,
             "ControllerPairingChanged: falha ao materializar o User virtual "
             "do secundario nao e fail-closed")
        # Indices >= 2 (Player 3+): sem canal de usuario, evento com User NULL.
        must("fm5_identity_demoted_controllers(&g_identity, keys," in pair,
             "ControllerPairingChanged: controles sem canal (indice >= 2) nao "
             "enumerados")
        must("dispatch_pairing_for_keys(keys, total, NULL)" in pair,
             "ControllerPairingChanged: controles sem canal nao recebem evento "
             "com User = NULL")
        # Eleicao do P2 (FASE 3): User virtual do indice 1 e PreviousUser = P1.
        must("materialize_virtual_user(NULL, &g_identity, 1)" in pair,
             "ControllerPairingChanged: P2 eleito sem User virtual do indice 1")
        must("controller_for_device_ref(p2_device)" in pair,
             "ControllerPairingChanged: Controller* real do P2 nao capturado "
             "pelo device eleito")
        must("dispatch_pairing_changed(new_user, controller)" in pair,
             "ControllerPairingChanged: P2 eleito nao dispara evento com o "
             "User virtual (e o Controller real, quando conhecido)")
        must("com_release(controller);" in pair,
             "ControllerPairingChanged: referencia do Controller do P2 "
             "vazando")
        must("serve_native_user" not in pair,
             "ControllerPairingChanged: notify nao deve servir User nativo")

    # TICKET-HARNESS-171: helper que dispara o evento por chave de device,
    # sempre com o Controller* REAL (nunca NULL cego) e soltando a referencia.
    for_keys = function_body(src, "dispatch_pairing_for_keys(void *const *keys, "
                                  "int total, void *user)")
    must(for_keys is not None, "dispatch_pairing_for_keys ausente")
    if for_keys:
        must("void *controller = controller_for_device_ref(keys[i]);"
             in for_keys,
             "dispatch_pairing_for_keys: Controller* real do device nao "
             "recuperado pela tabela")
        must(ordered(for_keys,
                     "void *controller = controller_for_device_ref(keys[i]);",
                     "invoked += dispatch_pairing_changed(user, controller);",
                     "com_release(controller);"),
             "dispatch_pairing_for_keys: Controller* nao e recuperado antes do "
             "dispatch e liberado depois (vazamento ou ponteiro nulo)")
        must("if (!controller)" in for_keys and "fm5_log" in for_keys,
             "dispatch_pairing_for_keys: device sem Controller* nao e logado")

    # TICKET-HARNESS-170: tabela device -> Controller* (referencia forte).
    remember = definition_body(src, "remember_controller_for_device(void *dev_key, "
                                    "void *controller)")
    if remember is None:
        remember = function_body(src, "remember_controller_for_device(void *dev_key, "
                                      "void *controller)")
    must(remember is not None, "remember_controller_for_device ausente")
    if remember:
        must(ordered(remember, "com_addref(controller);",
                     "g_ctrl_binding[i].controller = controller;"),
             "remember_controller_for_device: guarda ponteiro sem AddRef")
        must("if (!dev_key || !controller)" in remember,
             "remember_controller_for_device: aceita chave/ponteiro nulo")

    ref_body = function_body(src, "controller_for_device_ref(void *dev_key)")
    must(ref_body is not None, "controller_for_device_ref ausente")
    if ref_body:
        must("com_addref(controller);" in ref_body,
             "controller_for_device_ref: devolve ponteiro sem AddRef")
        must("g_ctrl_binding[i].dev_key == dev_key" in ref_body,
             "controller_for_device_ref: nao busca pela chave do device")

    # hook_get_user: `self` E o Controller* do Forza e precisa ser associado
    # ao device antes de qualquer evento de pareamento.
    get_user = function_body(src, "hook_get_user(void *self, void **out)")
    must(get_user is not None, "hook_get_user ausente")
    if get_user:
        must("remember_controller_for_device(dev_key, self);" in get_user,
             "hook_get_user: Controller* real (self) nao associado ao device")

    observer = function_body(src, "systemui_claim_controller(void *ctx, "
                                  "void *controller)")
    must(observer is not None, "observador do AccountPicker ausente")
    if observer:
        must(ordered(observer,
                     "remember_controller_for_device(dev_key, controller);",
                     "announce_player2(index);", "notify_pairing_changed();"),
             "observador do AccountPicker: Controller do P2 nao e guardado "
             "antes do evento de pareamento")

    # ------------------------------------------------------------------ #
    # 5d) TICKET-HARNESS-170 — tabela device -> Controller* (ref. forte)  #
    # ------------------------------------------------------------------ #
    # O get_Controller do args (slot 6) só entrega o Controller* REAL se a
    # camada de hooks mantiver a associação por device com referência própria.
    must(define_int(src, "FM5_CTRL_BINDINGS") == 32,
         "FM5_CTRL_BINDINGS deve ser 32 (tabela device -> Controller*)")
    must("static fm5_ctrl_binding_t g_ctrl_binding[FM5_CTRL_BINDINGS];" in src,
         "tabela g_ctrl_binding ausente/fora do tamanho declarado")
    must("static SRWLOCK            g_ctrl_binding_lock = SRWLOCK_INIT;" in src,
         "g_ctrl_binding_lock dedicado ausente (tabela sem lock proprio)")
    must("void *dev_key;" in src and "void *controller;" in src,
         "fm5_ctrl_binding_t sem os campos dev_key/controller")

    remember = definition_body(src, "remember_controller_for_device(void *dev_key, "
                                    "void *controller)")
    must(remember is not None, "remember_controller_for_device ausente")
    if remember:
        # AddRef ANTES de publicar: o objeto COM do jogo pode ser solto a
        # qualquer momento, então a referência tem de existir antes de o
        # ponteiro ficar visível para outra thread.
        must(ordered(remember, "if (!dev_key || !controller)",
                     "com_addref(controller);",
                     "AcquireSRWLockExclusive(&g_ctrl_binding_lock);",
                     "g_ctrl_binding[i].controller = controller;"),
             "remember_controller_for_device: AddRef nao precede a publicacao "
             "sob lock")
        # Substituicao do mesmo device: guarda a referencia antiga e libera.
        must("old = g_ctrl_binding[i].controller;" in remember,
             "remember_controller_for_device: nao recupera a referencia "
             "anterior do mesmo device")
        # Capacidade: nunca escreve fora do array; no overflow devolve a
        # referencia recem-tomada em vez de vazar.
        must("if (g_ctrl_binding_count < FM5_CTRL_BINDINGS)" in remember,
             "remember_controller_for_device: sem guarda de capacidade")
        must(ordered(remember, "old = controller;", "overflow = 1;",
                     "ReleaseSRWLockExclusive(&g_ctrl_binding_lock);"),
             "remember_controller_for_device: overflow nao devolve a "
             "referencia tomada (vazamento no caminho de tabela cheia)")
        # Release da referencia antiga FORA do lock (destrutor do objeto do
        # jogo nunca roda com lock nosso na mao).
        must(ordered(remember, "ReleaseSRWLockExclusive(&g_ctrl_binding_lock);",
                     "com_release(old);"),
             "remember_controller_for_device: Release da referencia anterior "
             "dentro do lock (risco de deadlock no destructor do jogo)")
        must(count(remember, "AcquireSRWLockExclusive(&g_ctrl_binding_lock);")
             == 1,
             "remember_controller_for_device: lock adquirido mais de uma vez")
        must(count(remember, "ReleaseSRWLockExclusive(&g_ctrl_binding_lock);")
             == 1,
             "remember_controller_for_device: lock liberado mais de uma vez")
        must(count(remember, "com_addref(controller);") == 1,
             "remember_controller_for_device: AddRef duplicado/ausente")
        must(count(remember, "com_release(old);") == 1,
             "remember_controller_for_device: Release da referencia anterior "
             "duplicado/ausente")

    ref_body = function_body(src, "controller_for_device_ref(void *dev_key)")
    must(ref_body is not None, "controller_for_device_ref ausente")
    if ref_body:
        must("void *controller = NULL;" in ref_body,
             "controller_for_device_ref: ponteiro nao inicializado em NULL "
             "(device desconhecido devolveria lixo)")
        # AddRef AINDA sob o lock: entre achar e referenciar o objeto nao pode
        # ser liberado por outra thread.
        must(ordered(ref_body,
                     "AcquireSRWLockExclusive(&g_ctrl_binding_lock);",
                     "g_ctrl_binding[i].dev_key == dev_key",
                     "com_addref(controller);",
                     "break;",
                     "ReleaseSRWLockExclusive(&g_ctrl_binding_lock);",
                     "return controller;"),
             "controller_for_device_ref: AddRef fora do lock ou sem busca por "
             "device")
        must("if (!dev_key)" in ref_body,
             "controller_for_device_ref: chave nula nao e fail-closed")

    # Shutdown: as referencias fortes saem da tabela SOB o lock e os Release
    # acontecem DEPOIS de soltar o lock.
    must(ordered(src, "solta as referências fortes da tabela",
                 "AcquireSRWLockExclusive(&g_ctrl_binding_lock);",
                 "dropped[dropped_count++] = g_ctrl_binding[i].controller;",
                 "g_ctrl_binding[i].controller = NULL;",
                 "g_ctrl_binding[i].dev_key = NULL;",
                 "g_ctrl_binding_count = 0;",
                 "ReleaseSRWLockExclusive(&g_ctrl_binding_lock);",
                 "com_release(dropped[i]);"),
         "shutdown: referencias da tabela device -> Controller* nao sao "
         "retiradas sob lock e liberadas fora dele (leak ou Release com lock)")
    must("void *dropped[FM5_CTRL_BINDINGS];" in src,
         "shutdown: buffer de drenagem fora do tamanho da tabela")

    if pair:
        # FASE 3: Controller* do P2 recuperado PELO DEVICE e solto depois do
        # dispatch (a referencia do evento e do chamador, nao do args).
        # A adjacencia literal e exigida: um `com_release(controller);` do
        # outro ramo (FASE 2) nao pode satisfazer esta verificacao.
        must(ordered(pair, "controller_for_device_ref(p2_device)",
                     "invoked = dispatch_pairing_changed(new_user, controller);"),
             "notify_pairing_changed: Controller* do P2 nao e recuperado pelo "
             "device antes do dispatch")
        must("invoked = dispatch_pairing_changed(new_user, controller);\n"
             "        com_release(controller);" in pair,
             "notify_pairing_changed: referencia do Controller* do P2 nao e "
             "liberada imediatamente apos o dispatch (vazamento)")
        # FASE 2: o secundario (indice 1) recebe o User VIRTUAL; o helper
        # recupera o Controller* do SEU device e libera depois do dispatch.
        must(count(pair, "dispatch_pairing_for_keys(") == 2,
             "notify_pairing_changed: esperado 1 dispatch para o indice 1 "
             "(User virtual) + 1 para os indices >= 2 (User NULL), obtido %d"
             % count(pair, "dispatch_pairing_for_keys("))
        must(ordered(pair,
                     "invoked = dispatch_pairing_for_keys(keys, total, new_user);",
                     "invoked += dispatch_pairing_for_keys(keys, total, NULL);"),
             "notify_pairing_changed: ordem secundario (User virtual) -> sem "
             "canal (User NULL) divergente")

    if get_user:
        # A associacao acontece ANTES da resolucao do User: mesmo que a
        # resolucao falhe, o Controller* do device ja esta na tabela para o
        # proximo evento de pareamento.
        must(ordered(get_user,
                     "remember_controller_for_device(dev_key, self);",
                     "fm5_resolve_get_user("),
             "hook_get_user: Controller* associado depois da resolucao do "
             "User (evento poderia sair sem o ponteiro real)")

    if observer:
        # g_p2_device tem de estar publicado antes de announce/notify, senao a
        # FASE 3 de notify_pairing_changed recuperaria controller de device
        # errado (ou NULL).
        must(ordered(observer,
                     "remember_controller_for_device(dev_key, controller);",
                     "g_p2_device = dev_key;",
                     "announce_player2(index);",
                     "notify_pairing_changed();"),
             "observador do AccountPicker: g_p2_device nao e publicado antes "
             "do evento de pareamento")

    # ------------------------------------------------------------------ #
    # 5c) TICKET-HARNESS-169 — layout do args em fm5_pairing.h/.c        #
    # ------------------------------------------------------------------ #
    must('#include "fm5_pairing.h"' in src,
         "fm5_hooks.c nao inclui fm5_pairing.h (args sintetizado ausente)")
    hdr_path = os.path.join(REPO, "fm5-p2", "include", "fm5_pairing.h")
    impl_path = os.path.join(REPO, "fm5-p2", "src", "fm5_pairing.c")
    must(os.path.isfile(hdr_path), "fm5_pairing.h ausente")
    must(os.path.isfile(impl_path), "fm5_pairing.c ausente")
    hdr = open(hdr_path, encoding="utf-8").read() if os.path.isfile(hdr_path) else ""
    impl = open(impl_path, encoding="utf-8").read() if os.path.isfile(impl_path) else ""

    # O vtable do args precisa ter 13 slots com getters em 6/7/8 na ordem
    # confirmada por desmontagem (0x140675e81 le vt[6] como Controller* e
    # 0x140675e36/e66 leem vt[7] como User*): qualquer reordenacao faz o jogo
    # tratar um User* como Controller* e abortar a atualizacao do slot.
    for name, slot in (("FM5_PAIRING_VT_QI", 0),
                       ("FM5_PAIRING_VT_ADDREF", 1),
                       ("FM5_PAIRING_VT_RELEASE", 2),
                       ("FM5_PAIRING_VT_GET_IIDS", 3),
                       ("FM5_PAIRING_VT_RUNTIME_NAME", 4),
                       ("FM5_PAIRING_VT_TRUST_LEVEL", 5),
                       ("FM5_PAIRING_VT_GET_CONTROLLER", 6),
                       ("FM5_PAIRING_VT_GET_USER", 7),
                       ("FM5_PAIRING_VT_GET_PREV_USER", 8),
                       ("FM5_PAIRING_VT_FIRST_STUB", 9),
                       ("FM5_PAIRING_VT_SLOTS", 13)):
        must(define_int(hdr, name) == slot,
             "%s deve valer %d (ABI do args de ControllerPairingChanged)"
             % (name, slot))

    # O vfptr tem de ser o PRIMEIRO campo do objeto (o jogo le *(void***)args).
    must(ordered(hdr, "typedef struct fm5_pairing_args {",
                 "const fm5_pairing_args_vt_t *vt;"),
         "fm5_pairing_args: vt nao e o primeiro campo")

    # A vtable publicada precisa listar os getters na ORDEM dos slots 6/7/8.
    must(ordered(impl, "static const fm5_pairing_args_vt_t g_args_vt",
                 ".get_controller = args_get_controller",
                 ".get_user = args_get_user",
                 ".get_previous_user = args_get_previous_user",
                 ".slot9 = args_stub",
                 ".slot12 = args_stub"),
         "fm5_pairing.c: vtable com getters fora da ordem 6/7/8 ou stubs "
         "9..12 ausentes")

    # get_User/get_PreviousUser/get_Controller passam pelo MESMO caminho que
    # faz AddRef antes de entregar o objeto (ownership correto ao jogo).
    must("static int32_t serve_object(fm5_pairing_args_t *args, void *object,"
         " void **out)" in impl,
         "fm5_pairing.c: helper serve_object ausente")
    serve = definition_body(impl, "serve_object(fm5_pairing_args_t *args, "
                                  "void *object, void **out)")
    must(serve is not None, "fm5_pairing.c: serve_object sem corpo")
    if serve:
        must("if (!out)" in serve and "FM5_PAIRING_E_POINTER" in serve,
             "serve_object: out NULL nao devolve E_POINTER")
        must("*out = NULL;" in serve and "FM5_PAIRING_S_OK" in serve,
             "serve_object: objeto ausente nao devolve S_OK + NULL")
        must("args->addref(object);" in serve,
             "serve_object: nao faz AddRef do objeto entregue")
    for fn, field in (("args_get_user", "args->user"),
                      ("args_get_previous_user", "args->previous_user"),
                      ("args_get_controller", "args->controller")):
        body = definition_body(impl, "%s(void *self, void **out)" % fn)
        must(body is not None, "fm5_pairing.c: %s ausente" % fn)
        if body:
            must("serve_object(args, %s, out)" % field in body,
                 "%s: nao entrega %s por serve_object" % (fn, field))

    # QueryInterface: IUnknown/IInspectable com S_OK + AddRef; resto
    # E_NOINTERFACE com *out = NULL (nunca ponteiro invalido).
    qi = definition_body(impl, "args_query_interface(void *self, "
                               "const void *riid, void **out)")
    must(qi is not None, "fm5_pairing.c: args_query_interface ausente")
    if qi:
        must("fm5_pairing_iid_iunknown" in qi and
             "fm5_pairing_iid_iinspectable" in qi,
             "QueryInterface: IIDs IUnknown/IInspectable nao reconhecidos")
        must("*out = NULL;" in qi and "FM5_PAIRING_E_NOINTERFACE" in qi,
             "QueryInterface: IID desconhecido nao devolve E_NOINTERFACE+NULL")
        must("args_add_ref(self);" in qi,
             "QueryInterface: S_OK sem AddRef")

    # Stubs 9..12 devolvem E_NOTIMPL e nao escrevem nos parametros.
    stub = definition_body(impl, "args_stub(void *self, void *a, void *b)")
    must(stub is not None, "fm5_pairing.c: args_stub ausente")
    if stub:
        must("FM5_PAIRING_E_NOTIMPL" in stub, "args_stub: nao devolve E_NOTIMPL")
        must("*(void **)a" not in stub and "*(void **)b" not in stub,
             "args_stub: escreve em parametro de assinatura desconhecida")

    # ------------------------------------------------------------------ #
    # 6) AddRef/Release COM = slots 1 e 2 (ABI IUnknown)                  #
    # ------------------------------------------------------------------ #
    addref = function_body(src, "com_addref(void *obj)")
    release = function_body(src, "com_release(void *obj)")
    must(addref is not None and "vt[1]" in addref and "!obj" in addref,
         "com_addref: nao usa vtable[1] nem tolera NULL")
    must(release is not None and "vt[2]" in release and "!obj" in release,
         "com_release: nao usa vtable[2] nem tolera NULL")

    # ------------------------------------------------------------------ #
    # 7) Blindagem do carregamento de corrida (crash 0x140687f4c)        #
    # ------------------------------------------------------------------ #
    # Forense (logs/steam-0.log): WM_ACTIVATE -> WindowActivated (RVA
    # 0x5d7500 do EXECUTÁVEL DO TÍTULO) -> EventQueue::PostEvent(25, 6) ->
    # escrita em NULL em 0x140687f4c. O alvo NÃO vive no azimuth.exe: é um
    # mapa manual do título em 0x140000000. O handler é neutralizado (S_OK,
    # sem evento) e a fila ganha uma guarda anti-NULL.
    must(define_int(src, "RVA_WINDOW_ACTIVATED") == 0x5D7500,
         "RVA_WINDOW_ACTIVATED != 0x5d7500 (handler WindowActivated)")
    must(define_int(src, "RVA_EVENT_QUEUE_LINK") == 0x687F48,
         "RVA_EVENT_QUEUE_LINK != 0x687f48 (escrita em [rax] com rax NULL)")
    must(define_int(src, "FM5_GAME_PREFERRED_BASE") == 0x140000000,
         "base preferida do titulo deve ser 0x140000000")
    must('FM5_GAME_MODULE_NAME    "forza_durango_release_final.exe"' in src,
         "nome do modulo do titulo ausente")

    # Prologue REAL do handler no título 1.0.0.20 (RVA 0x5d7500):
    # push rdi; sub rsp,0x50; mov [rsp+0x30],-2 (15 bytes, fronteira exata).
    m = re.search(r"EXPECT_WINDOW_ACTIVATED\[15\]\s*=\s*\{(.*?)\};",
                  src, re.S)
    must(m is not None, "EXPECT_WINDOW_ACTIVATED[15] ausente")
    if m:
        raw = "".join(x.lower()
                      for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))
        must(raw == "40574883ec5048c7442430feffffff",
             "prologue de 0x5d7500 divergente do titulo 1.0.0.20: %s" % raw)
        must(len(raw) == 30,
             "hook de 0x5d7500 deve cobrir 15 bytes (obtido %d)" % (len(raw) // 2))

    wa = function_body(src, "hook_window_activated(void *self, void *args)")
    must(wa is not None, "hook_window_activated ausente")
    if wa:
        must("return 0;" in wa, "WindowActivated: nao devolve S_OK (0)")
        must("PostEvent" not in wa,
             "WindowActivated: ainda posta o evento 25/6 na fila")
        must("trampoline" not in wa and "g_orig_window" not in wa,
             "WindowActivated: chama o handler original (o evento voltaria a "
             "ser postado e a fila desestabilizaria no carregamento)")
        must("fm5_event_shield_install(g_game_base)" in wa,
             "WindowActivated: nao arma a guarda anti-NULL da fila")

    # O alvo tem de ser o executavel do JOGO, nunca o wrapper (g_base).
    must("g_hook_window_activated.target = g_game_base + RVA_WINDOW_ACTIVATED;"
         in src,
         "WindowActivated: alvo nao e o executavel do titulo (g_game_base)")
    must("g_hook_window_activated.target = g_base + RVA_WINDOW_ACTIVATED;" not in
         src,
         "WindowActivated: alvo aponta para o azimuth.exe (g_base) — o hook "
         "patchearia o modulo errado")
    must("g_hook_window_activated.patch_len = 15;" in src,
         "WindowActivated: patch_len != 15 (fronteira de instrucao)")
    must("g_hook_window_activated.expect = EXPECT_WINDOW_ACTIVATED;" in src,
         "WindowActivated: assinatura do titulo nao e verificada (fail-closed)")

    # Resolucao da base do titulo (mapa manual invisivel ao GetModuleHandle).
    resolver = function_body(src, "resolve_game_base(void)")
    must(resolver is not None, "resolve_game_base ausente")
    if resolver:
        must(ordered(resolver, "FM5_P2_GAME_BASE",
                     "GetModuleHandleA(FM5_GAME_MODULE_NAME)",
                     "FM5_GAME_PREFERRED_BASE"),
             "resolve_game_base: ordem override -> modulo -> base preferida "
             "divergente")
        must("game_signature_ok(cand)" in resolver,
             "resolve_game_base: base preferida usada sem validar assinatura")

    sig = function_body(src, "game_signature_ok(uint8_t *base)")
    must(sig is not None, "game_signature_ok ausente")
    if sig:
        must("fm5_shield_is_original(base + RVA_EVENT_QUEUE_LINK)" in sig,
             "game_signature_ok: sequencia do crash da fila nao validada")
        must("memcmp(base + RVA_WINDOW_ACTIVATED, EXPECT_WINDOW_ACTIVATED,"
             in sig,
             "game_signature_ok: prologue do handler nao validado")
        must(count(sig, "page_is_readable(") == 2,
             "game_signature_ok: leitura da base manual sem checar pagina")

    # Sonda de integridade do salto: fm5_hook_install instala FF 25 00 00 00 00
    # + endereco absoluto (fm5_encode_abs_jmp), NUNCA um E9. A sonda precisa
    # comparar o salto COMPLETO com o MESMO encoder e conferir o destino —
    # uma sonda de 0xE9 daria "sobrescrito" sempre e queimaria o rearme.
    probe = function_body(src, "window_hook_state(void)")
    must(probe is not None, "window_hook_state ausente")
    if probe:
        must("fm5_encode_abs_jmp(expected," in probe,
             "sonda do rearme: nao usa o MESMO encoder do salto instalado")
        must("g_hook_window_activated.hook_fn" in probe,
             "sonda do rearme: nao confere o destino do salto")
        must("memcmp(p, expected, FM5_ABS_JMP_LEN) == 0" in probe,
             "sonda do rearme: nao exige o salto de 14 bytes completo")
        must("page_is_readable" in probe,
             "sonda do rearme: le a base do titulo sem checar a pagina")
        must("0xE9" not in probe,
             "sonda do rearme: sentinela E9 nao corresponde ao salto "
             "instalado (FF 25 00 00 00 00) — rearme inoperante")

    ensure = function_body(src, "ensure_window_hook(void)")
    must(ensure is not None, "ensure_window_hook ausente")
    if ensure:
        must("if (fm5_hook_install(&g_hook_window_activated) != 0) {"
             in ensure,
             "ensure_window_hook: hook nunca e instalado (ou sem fail-closed)")
        must(ordered(ensure, "resolve_game_base()",
                     "fm5_hook_install(&g_hook_window_activated)"),
             "ensure_window_hook: instalacao antes de resolver a base")
        must(ordered(ensure, "window_hook_state()",
                     "fm5_hook_install(&g_hook_window_activated)"),
             "ensure_window_hook: rearme nao consulta window_hook_state")

    must("fm5_hook_uninstall(&g_hook_window_activated);" in src,
         "WindowActivated: hook nao e removido no shutdown")
    must("fm5_event_shield_uninstall(g_game_base);" in src,
         "guarda anti-NULL: nao e restaurada no shutdown")

    rearm = function_body(src, "rearm_loading_hooks(void)")
    must(rearm is not None, "rearm_loading_hooks ausente")
    if rearm:
        must(ordered(rearm, "ensure_window_hook();",
                     "fm5_event_shield_install(g_game_base)"),
             "rearme: ordem handler -> guarda anti-NULL divergente")
        must("!fm5_event_shield_active() || !fm5_event_shield_intact()" in
             rearm,
             "rearme: guarda ativa nao e revalidada (sobrescrita do E9 pelo "
             "mapeador passaria batida)")

    reading = function_body(src, "hook_get_reading(void *retbuf, void *device)")
    must(reading is not None, "hook_get_reading ausente")
    if reading:
        must(ordered(reading, "rearm_loading_hooks();",
                     "if (!g_orig_get_reading)"),
             "hook_get_reading: rearme deve ocorrer ANTES do caminho sem "
             "trampolim (a guarda precisa instalar mesmo se a leitura falhar)")

    enc_path = os.path.join(REPO, "fm5-p2", "src",
                            "fm5_event_shield_encode.h")
    must(os.path.isfile(enc_path), "fm5_event_shield_encode.h ausente")
    if os.path.isfile(enc_path):
        with open(enc_path, "r", encoding="utf-8") as f:
            enc = f.read()

        def macro_bytes(text, name):
            mm = re.search(r"#define\s+%s\s+([^\n]*)"
                           % re.escape(name), text)
            if not mm:
                return None
            return "".join(x.lower()
                           for x in re.findall(r"0x([0-9A-Fa-f]{2})",
                                               mm.group(1)))

        must(define_int(enc, "FM5_SHIELD_RVA") == 0x687F48,
             "encoder: FM5_SHIELD_RVA != 0x687f48 (rip do crash)")
        must(define_int(enc, "FM5_SHIELD_RESUME_RVA") == 0x687F4F,
             "encoder: retomada != 0x687f4f (fronteira apos mov [rax],rcx)")
        must(macro_bytes(enc, "FM5_SHIELD_ORIG_BYTES") == "488b4108488908",
             "encoder: constante forense != 48 8b 41 08 48 89 08 "
             "(mov rax,[rcx+8]; mov [rax],rcx)")
        cave = macro_bytes(enc, "FM5_SHIELD_CAVE_OPCODES") or ""
        must(cave == "488b41089c4885c074034889089d",
             "encoder: opcodes da caverna divergem da guarda esperada "
             "(48 8b 41 08 9c 48 85 c0 74 03 48 89 08 9d), obtido %r"
             % cave)
        must("0x9C" in enc and "0x9D" in enc,
             "encoder: pushfq/popfq ausentes (EFLAGS do chamador seriam "
             "perdidas)")
        must("0xE9" in enc,
             "encoder: salto de entrada nao e E9 rel32")

    shield_src = os.path.join(REPO, "fm5-p2", "src", "fm5_event_shield.c")
    must(os.path.isfile(shield_src), "fm5_event_shield.c ausente")
    if os.path.isfile(shield_src):
        with open(shield_src, "r", encoding="utf-8") as f:
            shsrc = f.read()
        intact = function_body(shsrc, "fm5_event_shield_intact(void)")
        must(intact is not None, "fm5_event_shield_intact ausente")
        if intact:
            must("p[0] != 0xE9" in intact,
                 "intact: nao verifica o E9 publicado na fila")
            must("+ (int64_t)disp" in intact and "g_shield_cave" in intact,
                 "intact: nao confere que o E9 resolve para a NOSSA cave")
            must("shield_page_readable" in intact,
                 "intact: le a base do titulo sem checar a pagina")
        sh_inst = function_body(shsrc,
                                "fm5_event_shield_install(uint8_t *base)")
        must(sh_inst is not None, "fm5_event_shield_install sem corpo")
        if sh_inst:
            must("if (g_shield_state == 1 && fm5_event_shield_intact()) {"
                 in sh_inst,
                 "install: caminho rapido nao revalida a integridade")
            must("if (!shield_page_readable(target) || "
                 "!fm5_shield_is_original(target))" in sh_inst,
                 "install: nao valida pagina + assinatura antes de patchear")
            must(sh_inst.count("publish_jump(target, g_shield_cave)") == 1,
                 "install: rearme nao reusa a cave existente")
    sh_hdr = os.path.join(REPO, "fm5-p2", "src", "fm5_event_shield.h")
    must(os.path.isfile(sh_hdr), "fm5_event_shield.h ausente")
    if os.path.isfile(sh_hdr):
        with open(sh_hdr, "r", encoding="utf-8") as f:
            shh = f.read()
        must("int fm5_event_shield_intact(void);" in shh,
             "fm5_event_shield.h nao expoe fm5_event_shield_intact")

    shield_test = os.path.join(REPO, "tests", "test_fm5_event_shield.c")
    must(os.path.isfile(shield_test),
         "tests/test_fm5_event_shield.c ausente (guarda sem prova de execucao)")

    # ------------------------------------------------------------------ #
    # Blindagem da Visibility Thread (crash 0x1408595e0, Thread 0344)     #
    # ------------------------------------------------------------------ #
    must(define_int(src, "RVA_VISIBILITY_INSERT") == 0x859500,
         "RVA_VISIBILITY_INSERT != 0x859500 (fronteira de vector::insert)")
    must(define_int(src, "RVA_VISIBILITY_BRANCH") == 0x859516,
         "RVA_VISIBILITY_BRANCH != 0x859516 (jae unsigned do crash)")
    must('#include "fm5_visibility_shield.h"' in src,
         "fm5_hooks.c nao inclui fm5_visibility_shield.h")
    must("fm5_visibility_shield_uninstall(g_game_base);" in src,
         "blindagem de visibilidade nao e restaurada no shutdown")
    rearm_vis = function_body(src, "rearm_loading_hooks(void)")
    must(rearm_vis is not None, "rearm_loading_hooks ausente (visibilidade)")
    if rearm_vis:
        must(ordered(rearm_vis, "fm5_event_shield_install(g_game_base)",
                     "fm5_visibility_shield_install(g_game_base)"),
             "rearme: blindagem de visibilidade deve vir apos a guarda NULL")
        must("!fm5_visibility_shield_active() || "
             "!fm5_visibility_shield_intact()" in rearm_vis,
             "rearme: blindagem de visibilidade nao e revalidada")

    vis_enc = os.path.join(REPO, "fm5-p2", "src",
                           "fm5_visibility_shield_encode.h")
    must(os.path.isfile(vis_enc), "fm5_visibility_shield_encode.h ausente")
    if os.path.isfile(vis_enc):
        with open(vis_enc, "r", encoding="utf-8") as f:
            venc = f.read()

        def vis_macro_bytes(text, name):
            mm = re.search(r"#define\s+%s\s+((?:[^\n]*\\\n)*[^\n]*)"
                           % re.escape(name), text)
            if not mm:
                return None
            return "".join(x.lower() for x in
                           re.findall(r"0x([0-9A-Fa-f]{2})", mm.group(1)))

        must(define_int(venc, "FM5_VIS_BRANCH_RVA") == 0x859516,
             "encoder: FM5_VIS_BRANCH_RVA != 0x859516")
        must(define_int(venc, "FM5_VIS_GUARD_RVA") == 0x859500,
             "encoder: FM5_VIS_GUARD_RVA != 0x859500")
        must(define_int(venc, "FM5_VIS_GUARD_RESUME_RVA") == 0x85950D,
             "encoder: retomada != 0x85950d")
        must(vis_macro_bytes(venc, "FM5_VIS_BRANCH_ORIG_BYTES") ==
             "0f838d000000",
             "encoder: assinatura do crash != 0f 83 8d 00 00 00 (JAE +0x8d)")
        must(vis_macro_bytes(venc, "FM5_VIS_BRANCH_FIXED_BYTES") ==
             "0f8d8d000000",
             "encoder: patch != 0f 8d 8d 00 00 00 (JGE +0x8d)")
        must(vis_macro_bytes(venc, "FM5_VIS_GUARD_SEQ_BYTES") ==
             "c5f829742440492bc048c1f804",
             "encoder: sequencia de 0x859500 divergente (vmovaps/sub/sar)")
        vcave = vis_macro_bytes(venc, "FM5_VIS_GUARD_CAVE_OPCODES") or ""
        must(vcave ==
             "c5f829742440492bc048c1f8044c39c27d114989d04889d5"
             "48899424900000004831c0",
             "encoder: opcodes da caverna divergem das TRES travas de "
             "where (cmp rdx,r8; jge +0x11; mov r8,rdx; mov rbp,rdx; "
             "mov [rsp+0x90],rdx; xor eax,eax), obtido %r" % vcave)
        must(define_int(venc, "FM5_VIS_GUARD_CAVE_OPCODES_LEN") == 35,
             "encoder: FM5_VIS_GUARD_CAVE_OPCODES_LEN != 35")
        # Camada [3]: helper 0x85b770 (crash rip=0x14085b77a).
        must(define_int(venc, "FM5_VIS_HELPER_RVA") == 0x85B770,
             "encoder: FM5_VIS_HELPER_RVA != 0x85b770")
        must(define_int(venc, "FM5_VIS_HELPER_JCC_RVA") == 0x85B773,
             "encoder: FM5_VIS_HELPER_JCC_RVA != 0x85b773")
        must(define_int(venc, "FM5_VIS_HELPER_STORE_RVA") == 0x85B772,
             "encoder: FM5_VIS_HELPER_STORE_RVA != 0x85b772 (word par)")
        must(vis_macro_bytes(venc, "FM5_VIS_HELPER_ORIG_BYTES") ==
             "483bca7426",
             "encoder: helper original != 48 3b ca 74 26 (cmp; je)")
        must(vis_macro_bytes(venc, "FM5_VIS_HELPER_FIXED_BYTES") ==
             "483bca7326",
             "encoder: helper corrigido != 48 3b ca 73 26 (cmp; jae)")
        # Camada [4]: fonte 0x8580e0 (clamp antes do call 0x8580e8).
        must(define_int(venc, "FM5_VIS_SRC_RVA") == 0x8580E0,
             "encoder: FM5_VIS_SRC_RVA != 0x8580e0")
        must(define_int(venc, "FM5_VIS_SRC_RESUME_RVA") == 0x8580E8,
             "encoder: FM5_VIS_SRC_RESUME_RVA != 0x8580e8")
        must(define_int(venc, "FM5_VIS_MYLAST_RVA") == 0x24717D8,
             "encoder: FM5_VIS_MYLAST_RVA != 0x24717d8 (global _Mylast)")
        must(vis_macro_bytes(venc, "FM5_VIS_SRC_SEQ_BYTES") ==
             "4d8bc34889442420",
             "encoder: sequencia da fonte != 4d 8b c3 48 89 44 24 20")
        vsrc_cave = vis_macro_bytes(venc, "FM5_VIS_SRC_CAVE_OPCODES") or ""
        must(vsrc_cave ==
             "4d8bc34889442420488b0d000000004939c876034989c8",
             "encoder: opcodes da caverna da fonte divergem (reemissao + "
             "clamp r8=rcx), obtido %r" % vsrc_cave)

    vis_src = os.path.join(REPO, "fm5-p2", "src",
                           "fm5_visibility_shield.c")
    must(os.path.isfile(vis_src), "fm5_visibility_shield.c ausente")
    if os.path.isfile(vis_src):
        with open(vis_src, "r", encoding="utf-8") as f:
            vsrc = f.read()
        vinst = function_body(vsrc,
                              "fm5_visibility_shield_install(uint8_t *base)")
        must(vinst is not None, "fm5_visibility_shield_install sem corpo")
        if vinst:
            must("if (g_vis_state == 1 && fm5_visibility_shield_intact()) {"
                 in vinst,
                 "install: caminho rapido nao revalida a integridade")
            must("(fm5_vis_is_branch_original(branch) ||" in vinst,
                 "install: nao valida a assinatura viva antes de patchear")
            must("install_helper(base)" in vinst and
                 "install_src(base)" in vinst,
                 "install: camadas [3] (helper) e [4] (fonte) nao chamadas")
        guard_body = function_body(vsrc, "install_guard(uint8_t *base)")
        must(guard_body is not None, "install_guard ausente")
        if guard_body:
            must("if (!fm5_vis_is_guard_sequence(target)) {" in guard_body,
                 "trava: nao valida a sequencia forense de 0x859500 "
                 "(fail-closed ausente)")
        helper_body = function_body(vsrc, "install_helper(uint8_t *base)")
        must(helper_body is not None, "install_helper ausente (camada [3])")
        if helper_body:
            must("if (!fm5_vis_is_helper_original(target)) {" in helper_body,
                 "helper: nao valida a sequencia forense de 0x85b770 "
                 "(fail-closed ausente)")
            must("FM5_VIS_HELPER_FIXED_WORD" in helper_body,
                 "helper: nao publica o word 0x73ca (JAE) atomico")
        src_body = function_body(vsrc, "install_src(uint8_t *base)")
        must(src_body is not None, "install_src ausente (camada [4])")
        if src_body:
            must("if (!fm5_vis_is_src_sequence(target)) {" in src_body,
                 "fonte: nao valida a sequencia forense de 0x8580e0 "
                 "(fail-closed ausente)")
        jump_is_ours = function_body(vsrc,
                                     "guard_jump_is_ours(const uint8_t *target)")
        must(jump_is_ours is not None, "guard_jump_is_ours ausente")
        if jump_is_ours:
            must("target[0] != 0xE9" in jump_is_ours,
                 "guard_jump_is_ours: sentinela do E9 publicado ausente")
        src_jump_is_ours = function_body(
            vsrc, "src_jump_is_ours(const uint8_t *target)")
        must(src_jump_is_ours is not None, "src_jump_is_ours ausente")
        if src_jump_is_ours:
            must("target[0] != 0xE9" in src_jump_is_ours,
                 "src_jump_is_ours: sentinela do E9 publicado ausente")
        intact_vis = function_body(vsrc, "fm5_visibility_shield_intact(void)")
        must(intact_vis is not None,
             "fm5_visibility_shield_intact ausente")
        if intact_vis:
            must("fm5_vis_is_branch_fixed(branch)" in intact_vis,
                 "intact: nao confere o JGE publicado em 0x859516")
            must("guard_jump_is_ours(gtarget)" in intact_vis,
                 "intact: nao confere que o E9 resolve para a NOSSA caverna")
            must("fm5_vis_is_helper_fixed(htarget)" in intact_vis,
                 "intact: nao confere o `73` (JAE) publicado no helper")
            must("src_jump_is_ours(starget)" in intact_vis,
                 "intact: nao confere o E9 da fonte (camada [4])")
        unint = function_body(
            vsrc, "fm5_visibility_shield_uninstall(uint8_t *base)")
        must(unint is not None, "fm5_visibility_shield_uninstall ausente")
        if unint:
            must("src_jump_is_ours(starget)" in unint,
                 "uninstall: E9 da fonte nao restaurado antes do free")
            must("fm5_vis_is_helper_fixed(htarget)" in unint,
                 "uninstall: word do helper nao restaurado")

    vis_test = os.path.join(REPO, "tests", "test_fm5_visibility_shield.c")
    must(os.path.isfile(vis_test),
         "tests/test_fm5_visibility_shield.c ausente (blindagem sem prova)")

    # ------------------------------------------------------------------ #
    if failures:
        print("FALHA: %d/%d verificacoes de fiacao dos hooks falharam"
              % (len(failures), checks))
        for f in failures:
            print("  - " + f)
        return 1
    print("OK: %d verificacoes do contrato de fiacao dos hooks passaram"
          % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
