#!/usr/bin/env python3
"""
test_mutation_sensitivity.py — prova de SENSIBILIDADE da suíte do
TICKET-HARNESS-168 (identidade Guest + rebaixamento + hook do AccountPicker).

Regra do SDET: um teste novo só vale depois de provar que REPROVA quando o
comportamento de produção é desfeito. Este script aplica mutações cirúrgicas
(exatamente 1 substituição por mutação) numa CÓPIA ISOLADA da árvore em
diretório temporário, compila/roda a suíte real sobre o mutante e exige
VERMELHO. O checkout compartilhado nunca é tocado: os sha256 dos fontes são
conferidos antes e depois.

Mutante que sobrevive (suíte continua verde) => o teste correspondente não
protege a entrega e este script reprova.

Determinístico: sem rede, sem mocks, sem sleeps.
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

WATCHED = [
    "fm5-p2/src/fm5_identity.c",
    "fm5-p2/src/fm5_hooks.c",
    "fm5-p2/src/fm5_pairing.c",
    "fm5-p2/include/fm5_pairing.h",
    "fm5-p2/src/fm5_buttons.h",
    "fm5-p2/include/fm5_identity.h",
    "fm5-p2/include/fm5_systemui.h",
    "fm5-p2/src/fm5_event_shield.c",
    "fm5-p2/src/fm5_event_shield.h",
    "fm5-p2/src/fm5_event_shield_encode.h",
    "tests/test_fm5_event_shield.c",
    "fm5-p2/src/fm5_visibility_shield.c",
    "fm5-p2/src/fm5_visibility_shield.h",
    "fm5-p2/src/fm5_visibility_shield_encode.h",
    "tests/test_fm5_visibility_shield.c",
    "tests/test_fm5_identity.c",
    "tests/test_fm5_contract.c",
    "tests/test_fm5_hooks_contract.py",
    "tests/test_fm5_pairing.c",
]

MUTATIONS = [
    # --- núcleo portátil: identidade Guest ------------------------------- #
    dict(id="is_guest_sempre_zero", file="fm5-p2/src/fm5_identity.c",
         old="return (index >= 1 && index < max_users) ? 1 : 0;",
         new="return 0;",
         why="get_IsGuest do P2 virtual voltaria 0 (jogo trataria como "
             "jogador assinado)",
         runners=["identity", "contract"]),
    dict(id="xuid_base_sem_indice", file="fm5-p2/src/fm5_identity.c",
         old="xuid = FM5_XBOX_USER_ID_BASE + (uint64_t)index;",
         new="xuid = FM5_XBOX_USER_ID_BASE;",
         why="P1 e P2 colidiriam no mesmo XUID (ConnectedStorageSpace "
             "compartilhado)",
         runners=["identity", "contract"]),
    dict(id="hash_constante", file="fm5-p2/src/fm5_identity.c",
         old="if (u64_to_dec((uint64_t)index + 1ULL, buf, cap) < 0) {",
         new="if (u64_to_dec(1ULL, buf, cap) < 0) {",
         why="XboxUserHash do P2 viraria \"1\" (igual ao P1)",
         runners=["identity", "contract"]),
    # --- núcleo portátil: promoção do secundário após P1 eleito ---------- #
    dict(id="secundario_nao_promovido", file="fm5-p2/src/fm5_identity.c",
         old="id->controller_user[i] = (i == slot) ? 0 : next++;",
         new="id->controller_user[i] = 0;",
         why="o secundário herdaria o User do Player 1 (índice 0) em vez de "
             "ser promovido ao Player 2 virtual (índice 1) no primeiro A",
         runners=["identity", "contract", "pairing"]),
    # --- camada de hooks (fiação Windows-only) --------------------------- #
    dict(id="picker_sem_addref", file="fm5-p2/src/fm5_hooks.c",
         func="hook_make_account_picker_user(void)",
         old="com_addref(user);", new="",
         why="User virtual devolvido sem AddRef (use-after-free / refcount "
             "errado no WinRT)",
         runners=["hooks"]),
    dict(id="picker_sem_p1_lock", file="fm5-p2/src/fm5_hooks.c",
         func="hook_make_account_picker_user(void)",
         old="if (g_orig_account_picker && "
             "fm5_identity_p1_locked(&g_identity)) {",
         new="if (g_orig_account_picker) {",
         why="AccountPicker serviria o P2 virtual antes do P1 eleito",
         runners=["hooks"]),
    dict(id="picker_indice_errado", file="fm5-p2/src/fm5_hooks.c",
         func="hook_make_account_picker_user(void)",
         old="materialize_virtual_user(NULL, &g_identity, 1)",
         new="materialize_virtual_user(NULL, &g_identity, 2)",
         why="AccountPicker entregaria o User do índice 2, não o Player 2",
         runners=["hooks"]),
    dict(id="is_guest_p1_vira_convidado", file="fm5-p2/src/fm5_hooks.c",
         func="hook_user_is_guest(void *self, uint8_t *out)",
         old="if (index >= 1 && fm5_identity_is_guest",
         new="if (index >= 0 && fm5_identity_is_guest",
         why="Player 1 passaria a se apresentar como Convidado",
         runners=["hooks"]),
    # --- TICKET-HARNESS-169: args COM do ControllerPairingChanged -------- #
    dict(id="pairing_args_e_sender_de_novo", file="fm5-p2/src/fm5_hooks.c",
         func="dispatch_pairing_changed(void *new_user, void *controller)",
         old="((invoke_fn)vt[3])(handlers[i], sender, args)",
         new="((invoke_fn)vt[3])(handlers[i], sender, sender)",
         why="regressao exata do crash: o handler resolve a vtable de "
             "ControllerStatics como se fosse o args (STATUS_ACCESS_VIOLATION)",
         runners=["hooks"]),
    dict(id="pairing_args_null_de_novo", file="fm5-p2/src/fm5_hooks.c",
         func="dispatch_pairing_changed(void *new_user, void *controller)",
         old="((invoke_fn)vt[3])(handlers[i], sender, args)",
         new="((invoke_fn)vt[3])(handlers[i], sender, NULL)",
         why="args NULL faz handler que consulte args sofrer access violation "
             "em 0x0 em vez de receber S_OK+NULL",
         runners=["hooks"]),
    dict(id="pairing_sem_addref", file="fm5-p2/src/fm5_pairing.c",
         func="serve_object(fm5_pairing_args_t *args, void *object, void **out)",
         old="args->addref(object);", new="",
         why="get_User/get_PreviousUser/get_Controller entregariam o objeto "
             "sem AddRef (use-after-free / refcount errado no WinRT)",
         runners=["pairing"]),
    dict(id="pairing_slot_controller_errado",
         file="fm5-p2/include/fm5_pairing.h",
         old="#define FM5_PAIRING_VT_GET_CONTROLLER   6u",
         new="#define FM5_PAIRING_VT_GET_CONTROLLER   8u",
         why="a ABI do args deixaria de expor get_Controller no slot 6 (o "
             "handler do Forza receberia get_PreviousUser como Controller* e "
             "0x1406763a0 abortaria sem gravar o User)",
         runners=["hooks"]),
    dict(id="pairing_rebaixados_sem_evento", file="fm5-p2/src/fm5_hooks.c",
         func="notify_pairing_changed(void)",
         old="invoked += dispatch_pairing_for_keys(keys, total, NULL);",
         new="(void)0;",
         why="controles em índice >= 2 nao receberiam o evento com User = NULL "
             "e o jogo manteria o User cacheado do Player 1",
         runners=["hooks"]),
    dict(id="controller_p2_sem_addref", file="fm5-p2/src/fm5_hooks.c",
         func="remember_controller_for_device(void *dev_key, void *controller)",
         old="com_addref(controller);", new="",
         why="get_Controller entregaria um Controller* sem referencia (o jogo "
             "pode soltar o objeto antes do handler terminar)",
         runners=["hooks"]),
    dict(id="rebaixado_sem_controller_real", file="fm5-p2/src/fm5_hooks.c",
         func="dispatch_pairing_for_keys(void *const *keys, int total, void *user)",
         old="void *controller = controller_for_device_ref(keys[i]);",
         new="void *controller = NULL;",
         why="o evento voltaria a entregar Controller* NULL e 0x1406763a0 "
             "abortaria sem gravar o User no slot interno do controle",
         runners=["hooks"]),
    dict(id="neutros_nao_filtrados", file="fm5-p2/src/fm5_identity.c",
         func="fm5_identity_controllers_for_index(fm5_identity_t *id, int index,",
         old="if (id->controller_user[i] != index) {",
         new="if (0) {",
         why="o snapshot do índice 1 incluiria o Player 1 e os controles sem "
             "canal, disparando o evento de pareamento para quem não é P2",
         runners=["pairing"]),
    dict(id="sem_canal_nao_filtrado", file="fm5-p2/src/fm5_identity.c",
         func="fm5_identity_demoted_controllers(fm5_identity_t *id, void **out, int cap)",
         old="if (id->controller_user[i] < 2) {",
         new="if (0) {",
         why="o snapshot dos índices >= 2 incluiria P1/P2 e o evento com "
             "User = NULL seria disparado para o próprio Player 1",
         runners=["pairing"]),
    # TICKET-HARNESS-171: o evento do secundário precisa de User VÁLIDO.
    dict(id="secundario_com_user_null", file="fm5-p2/src/fm5_hooks.c",
         func="notify_pairing_changed(void)",
         old="invoked = dispatch_pairing_for_keys(keys, total, new_user);",
         new="invoked = dispatch_pairing_for_keys(keys, total, NULL);",
         why="regressao exata do requisito: User NULL faz 0x140675e10 abortar "
             "em 140675e3e e o segundo controle nunca vira Player 2",
         runners=["hooks"]),
    # --- TICKET-HARNESS-170: tabela device -> Controller* + ABI 0x30/0x38/0x40 #
    dict(id="pairing_vtable_getters_trocados", file="fm5-p2/src/fm5_pairing.c",
         old=".get_controller = args_get_controller,",
         new=".get_controller = args_get_user,",
         why="slot 6 (+0x30) passaria a devolver o User* e 0x1406763a0 "
             "abortaria a atualizacao do slot de controle",
         runners=["pairing", "hooks"]),
    dict(id="pairing_previous_user_trocado", file="fm5-p2/src/fm5_pairing.c",
         old=".get_previous_user = args_get_previous_user,",
         new=".get_previous_user = args_get_user,",
         why="slot 8 (+0x40) deixaria de entregar o PreviousUser (P1 nativo) e "
             "devolveria o User novo",
         runners=["pairing"]),
    dict(id="pairing_slot_prev_user_errado",
         file="fm5-p2/include/fm5_pairing.h",
         old="#define FM5_PAIRING_VT_GET_PREV_USER    8u",
         new="#define FM5_PAIRING_VT_GET_PREV_USER    7u",
         why="get_PreviousUser sairia no slot do User novo (0x38) e o "
             "despachante leria o User errado como PreviousUser",
         runners=["hooks"]),
    dict(id="bindings_sem_release_do_antigo", file="fm5-p2/src/fm5_hooks.c",
         func="remember_controller_for_device(void *dev_key, void *controller)",
         old="ReleaseSRWLockExclusive(&g_ctrl_binding_lock);\n"
             "    com_release(old);",
         new="ReleaseSRWLockExclusive(&g_ctrl_binding_lock);",
         why="a referencia antiga do mesmo device vazaria a cada get_User "
             "repetido (o jogo recria wrappers Controller* a cada enumeracao)",
         runners=["hooks"]),
    dict(id="bindings_release_dentro_do_lock", file="fm5-p2/src/fm5_hooks.c",
         func="remember_controller_for_device(void *dev_key, void *controller)",
         old="ReleaseSRWLockExclusive(&g_ctrl_binding_lock);\n"
             "    com_release(old);",
         new="com_release(old);\n"
             "    ReleaseSRWLockExclusive(&g_ctrl_binding_lock);",
         why="Release do Controller* (destructor do objeto do jogo) rodaria "
             "com o lock da tabela na mao — deadlock/reentrancia",
         runners=["hooks"]),
    dict(id="bindings_overflow_vaza", file="fm5-p2/src/fm5_hooks.c",
         func="remember_controller_for_device(void *dev_key, void *controller)",
         old="old = controller;\n            overflow = 1;",
         new="overflow = 1;",
         why="com a tabela cheia a referencia recem-tomada nao seria devolvida "
             "(vazamento de Controller* no 33o device)",
         runners=["hooks"]),
    dict(id="bindings_lookup_sem_addref", file="fm5-p2/src/fm5_hooks.c",
         func="controller_for_device_ref(void *dev_key)",
         old="com_addref(controller);", new="",
         why="get_Controller entregaria um Controller* cuja referencia forte "
             "nao existe (o chamador soltaria algo que nao possui)",
         runners=["hooks"]),
    dict(id="hook_get_user_nao_associa", file="fm5-p2/src/fm5_hooks.c",
         func="hook_get_user(void *self, void **out)",
         old="remember_controller_for_device(dev_key, self);", new="",
         why="a tabela ficaria vazia e get_Controller (slot 6) devolveria "
             "NULL — 0x1406763a0 abortaria sem gravar o User",
         runners=["hooks"]),
    dict(id="p2_device_nao_guardado", file="fm5-p2/src/fm5_hooks.c",
         func="systemui_claim_controller(void *ctx, void *controller)",
         old="g_p2_device = dev_key;", new="(void)0;",
         why="a FASE 3 do evento recuperaria o Controller* do device errado "
             "(ou NULL) para o Player 2 eleito",
         runners=["hooks"]),
    dict(id="controller_p2_sem_release", file="fm5-p2/src/fm5_hooks.c",
         func="notify_pairing_changed(void)",
         old="invoked = dispatch_pairing_changed(new_user, controller);\n"
             "        com_release(controller);",
         new="invoked = dispatch_pairing_changed(new_user, controller);",
         why="a referencia forte do Controller* do P2 vazaria a cada eleicao",
         runners=["hooks"]),
    dict(id="shutdown_sem_release_dos_controllers",
         file="fm5-p2/src/fm5_hooks.c",
         old="            com_release(dropped[i]);", new="            (void)0;",
         why="as referencias fortes da tabela device -> Controller* vazariam "
             "no shutdown do hook",
         runners=["hooks"]),
    dict(id="shutdown_release_dentro_do_lock", file="fm5-p2/src/fm5_hooks.c",
         old="ReleaseSRWLockExclusive(&g_ctrl_binding_lock);\n"
             "        for (i = 0; i < dropped_count; i++) {\n"
             "            com_release(dropped[i]);\n"
             "        }",
         new="for (i = 0; i < dropped_count; i++) {\n"
             "            com_release(dropped[i]);\n"
             "        }\n"
             "        ReleaseSRWLockExclusive(&g_ctrl_binding_lock);",
         why="o shutdown soltaria os Controller* com o lock da tabela na mao",
         runners=["hooks"]),
    # --- Blindagem do carregamento de corrida (crash 0x140687f4c) -------- #
    dict(id="window_handler_nao_sok", file="fm5-p2/src/fm5_hooks.c",
         func="hook_window_activated(void *self, void *args)",
         old="return 0; /* S_OK */", new="return 1;",
         why="o handler WindowActivated deixaria de devolver S_OK e o wrapper "
             "poderia tratar a ativacao como erro em pleno carregamento",
         runners=["hooks"]),
    dict(id="window_handler_volta_ao_original", file="fm5-p2/src/fm5_hooks.c",
         func="hook_window_activated(void *self, void *args)",
         old="return 0; /* S_OK */",
         new="return ((int32_t (*)(void *, void *))g_orig_window_activated)"
             "(self, args);",
         why="regressao exata do crash: o handler original voltaria a postar o "
             "evento 25/6 e a fila seria desestabilizada no carregamento",
         runners=["hooks"]),
    dict(id="window_hook_nao_instalado", file="fm5-p2/src/fm5_hooks.c",
         old="if (fm5_hook_install(&g_hook_window_activated) != 0) {\n"
             "            return -2;",
         new="if (0) {\n            return -2;",
         why="o handler WindowActivated nunca seria instalado e o evento 25/6 "
             "continuaria sendo postado durante a transicao de tela",
         runners=["hooks"]),
    dict(id="window_hook_no_modulo_errado", file="fm5-p2/src/fm5_hooks.c",
         func="ensure_window_hook(void)",
         old="g_hook_window_activated.target = g_game_base + RVA_WINDOW_ACTIVATED;",
         new="g_hook_window_activated.target = g_base + RVA_WINDOW_ACTIVATED;",
         why="regressao mais perigosa deste card: o hook patchearia o "
             "azimuth.exe (wrapper) em vez do executavel do titulo mapeado em "
             "0x140000000 — o crash continuaria e o wrapper seria corrompido",
         runners=["hooks"]),
    dict(id="game_base_sem_assinatura", file="fm5-p2/src/fm5_hooks.c",
         func="game_signature_ok(uint8_t *base)",
         old="if (!fm5_shield_is_original(base + RVA_EVENT_QUEUE_LINK)) {\n"
             "        return 0;\n    }",
         new="",
         why="a base candidata seria aceita sem provar a sequencia do crash "
             "(patch em memoria arbitraria se o mapa mudar de base)",
         runners=["hooks"]),
    dict(id="shield_sem_teste_de_null",
         file="fm5-p2/src/fm5_event_shield_encode.h",
         old="0x48, 0x85, 0xC0, 0x74, 0x03", new="0x90, 0x90, 0x90, 0x90, 0x90",
         why="sem test/jz a caverna executaria mov [rax],rcx com rax==NULL e o "
             "processo morreria (a guarda deixaria de existir)",
         runners=["shield"]),
    dict(id="shield_salta_a_escrita",
         file="fm5-p2/src/fm5_event_shield_encode.h",
         old="0x74, 0x03", new="0xEB, 0x03",
         why="o salto incondicional pularia a escrita mesmo com next valido "
             "(o encadeamento da fila deixaria de acontecer)",
         runners=["shield"]),
    dict(id="shield_sem_popfq",
         file="fm5-p2/src/fm5_event_shield_encode.h",
         old="0x48, 0x89, 0x08, 0x9D", new="0x48, 0x89, 0x08, 0x90",
         why="sem popfq as EFLAGS do chamador seriam corrompidas pelo test "
             "rax,rax e o codigo em 0x687f4f poderia divergir",
         runners=["shield"]),
    dict(id="shield_original_trocado",
         file="fm5-p2/src/fm5_event_shield_encode.h",
         old="#define FM5_SHIELD_ORIG_BYTES "
             "0x48, 0x8B, 0x41, 0x08, 0x48, 0x89, 0x08",
         new="#define FM5_SHIELD_ORIG_BYTES "
             "0x48, 0x8B, 0x41, 0x08, 0x48, 0x89, 0x01",
         why="a assinatura forense passaria a ser mov [rcx],rax: a guarda nao "
             "reconheceria o crash (nem mapearia a escrita em NULL)",
         runners=["shield"]),
    dict(id="window_probe_sentinela_e9", file="fm5-p2/src/fm5_hooks.c",
         func="window_hook_state(void)",
         old="return memcmp(p, expected, FM5_ABS_JMP_LEN) == 0;",
         new="return p[0] == 0xE9;",
         why="regressao exata do achado da Clara: fm5_encode_abs_jmp instala "
             "FF 25 00 00 00 00, entao a sonda de 0xE9 daria 'sobrescrito' "
             "sempre e o rearme jamais funcionaria",
         runners=["hooks"]),
    dict(id="window_probe_sem_destino", file="fm5-p2/src/fm5_hooks.c",
         func="window_hook_state(void)",
         old="(uint64_t)(uintptr_t)g_hook_window_activated.hook_fn",
         new="(uint64_t)(uintptr_t)g_hook_window_activated.trampoline",
         why="a sonda compararia com um salto para o trampolim e nao para o "
             "handler instalado (rearme falso-positivo)",
         runners=["hooks"]),
    dict(id="rearm_sem_redeteccao_da_guarda", file="fm5-p2/src/fm5_hooks.c",
         func="rearm_loading_hooks(void)",
         old="if (!fm5_event_shield_active() || !fm5_event_shield_intact()) {",
         new="if (!fm5_event_shield_active()) {",
         why="depois de ativa, uma sobrescrita dos 7 bytes pelo mapeador nunca "
             "seria detectada (a guarda ficaria perdida ate o exit)",
         runners=["hooks"]),
    dict(id="shield_sem_redeteccao", file="fm5-p2/src/fm5_event_shield.c",
         func="fm5_event_shield_install(uint8_t *base)",
         old="if (g_shield_state == 1 && fm5_event_shield_intact()) {",
         new="if (g_shield_state == 1) {",
         why="install devolveria 1 sem checar o E9 publicado: rearme da guarda "
             "viraria no-op apos a primeira instalacao",
         runners=["hooks"]),
    dict(id="shield_intact_sentinela_errado",
         file="fm5-p2/src/fm5_event_shield.c",
         func="fm5_event_shield_intact(void)",
         old="if (p[0] != 0xE9) {", new="if (p[0] != 0xFF) {",
         why="sentinela errada no intact(): a guarda nunca seria considerada "
             "integra e o rearme patchearia a cada poll",
         runners=["hooks"]),
    dict(id="shield_rearme_removido", file="fm5-p2/src/fm5_hooks.c",
         old="rearm_loading_hooks();\n\n    if (!g_orig_get_reading)",
         new="if (!g_orig_get_reading)",
         why="sem rearme a guarda nunca seria instalada se a regiao ainda "
             "estivesse cifrada no DllMain",
         runners=["hooks"]),
    # --- blindagem da Visibility Thread (crash 0x1408595e0, Thread 0344) ---
    dict(id="vis_branch_continua_jae", file="fm5-p2/src/fm5_visibility_shield_encode.h",
         old="#define FM5_VIS_BRANCH_FIXED_BYTES 0x0F, 0x8D, 0x8D, 0x00, 0x00, 0x00",
         new="#define FM5_VIS_BRANCH_FIXED_BYTES 0x0F, 0x83, 0x8D, 0x00, 0x00, 0x00",
         why="o 'patch' seria identico ao JAE original: count negativo continuaria "
             "saltando para o laco de copia para tras (runaway 0x1408595e0)",
         runners=["visibility", "hooks"]),
    dict(id="vis_cave_sem_trava", file="fm5-p2/src/fm5_visibility_shield_encode.h",
         old="    0x7D, 0x11, \\",
         new="    0x90, 0x90, \\",
         why="o jge da caverna viraria NOP: where > _Mylast nunca seria travado "
             "em _Mylast (a defesa em profundidade sumiria)",
         runners=["visibility"]),
    dict(id="vis_cave_jge_invertido", file="fm5-p2/src/fm5_visibility_shield_encode.h",
         old="    0x7D, 0x11, \\",
         new="    0x7C, 0x11, \\",
         why="jl inverte a condicao: a trava seria pulada EXATAMENTE quando "
             "where > _Mylast, o caso do crash",
         runners=["visibility"]),
    dict(id="vis_helper_sem_jae", file="fm5-p2/src/fm5_visibility_shield_encode.h",
         old="#define FM5_VIS_HELPER_FIXED_BYTES 0x48, 0x3B, 0xCA, 0x73, 0x26",
         new="#define FM5_VIS_HELPER_FIXED_BYTES 0x48, 0x3B, 0xCA, 0x74, 0x26",
         why="sem o JAE o helper 0x85b770 continua com JE desgovernado: "
             "cmp rdx,rcx com rcx > rdx toma o laco de copia para tras e "
             "morre em rip=0x14085b77a (o crash reportado)",
         runners=["visibility", "hooks"]),
    dict(id="vis_src_cave_sem_trava", file="fm5-p2/src/fm5_visibility_shield_encode.h",
         old="    0x49, 0x89, 0xC8",
         new="    0x90, 0x90, 0x90",
         why="sem `mov r8,rcx` a trava da fonte nao corrige where antes do "
             "call 0x8580e8: o forward-copy do helper continua livre para "
             "estourar em rip=0x14085b77a",
         runners=["visibility", "hooks"]),
    dict(id="vis_rva_divergente", file="fm5-p2/src/fm5_visibility_shield_encode.h",
         old="#define FM5_VIS_BRANCH_RVA             0x859516u",
         new="#define FM5_VIS_BRANCH_RVA             0x859518u",
         why="a ancora forense do executavel do titulo reprovaria (o jae vive "
             "em 0x859516) e o patch cairia em bytes errados",
         runners=["visibility", "hooks"]),
    dict(id="vis_install_sem_redeteccao", file="fm5-p2/src/fm5_visibility_shield.c",
         func="fm5_visibility_shield_install(uint8_t *base)",
         old="if (g_vis_state == 1 && fm5_visibility_shield_intact()) {",
         new="if (g_vis_state == 1) {",
         why="install devolveria 1 sem checar os bytes publicados: o rearme "
             "nunca reaplicaria o JGE se o mapeador o sobrescrever",
         runners=["hooks"]),
    dict(id="rearm_sem_visibilidade", file="fm5-p2/src/fm5_hooks.c",
         func="rearm_loading_hooks(void)",
         old="if (!fm5_visibility_shield_active() || "
             "!fm5_visibility_shield_intact()) {",
         new="if (!fm5_visibility_shield_active()) {",
         why="depois de ativa, uma sobrescrita dos bytes em 0x859516 pelo "
             "mapeador nunca seria detectada (a blindagem se perderia)",
         runners=["hooks"]),
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot():
    return {rel: sha256(os.path.join(REPO, rel)) for rel in WATCHED
            if os.path.isfile(os.path.join(REPO, rel))}


def function_span(text, signature):
    start = text.find(signature)
    if start < 0:
        return None
    brace = text.find("{", start)
    if brace < 0:
        return None
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return start, brace, i + 1
    return None


def apply_mutation(root, mut):
    path = os.path.join(root, mut["file"])
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if mut.get("func"):
        span = function_span(text, mut["func"])
        if span is None:
            return "funcao %r ausente" % mut["func"]
        _, b, e = span
        body = text[b:e]
        if body.count(mut["old"]) != 1:
            return ("padrao ocorre %d vezes no corpo de %s (esperado 1)"
                    % (body.count(mut["old"]), mut["func"]))
        text = text[:b] + body.replace(mut["old"], mut["new"], 1) + text[e:]
    else:
        if text.count(mut["old"]) != 1:
            return ("padrao ocorre %d vezes em %s (esperado 1)"
                    % (text.count(mut["old"]), mut["file"]))
        text = text.replace(mut["old"], mut["new"], 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return None


def run_native(root, test_name):
    """Compila e roda um teste C nativo real dentro da cópia temporária."""
    build = os.path.join(root, "build")
    os.makedirs(build, exist_ok=True)
    exe = os.path.join(build, test_name)
    cmd = [
        "gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
        "-I", os.path.join(root, "fm5-p2", "include"),
        "-o", exe,
        os.path.join(root, "tests", test_name + ".c"),
        os.path.join(root, "fm5-p2", "src", "fm5_identity.c"),
    ]
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        return False, "compilacao falhou: " + (proc.stderr or "")[-300:]
    run = subprocess.run([exe], cwd=root, capture_output=True, text=True)
    return run.returncode == 0, ((run.stdout or "") + (run.stderr or ""))[-300:]


def run_hooks_contract(root):
    proc = subprocess.run([sys.executable,
                           os.path.join(root, "tests",
                                        "test_fm5_hooks_contract.py")],
                          cwd=root, capture_output=True, text=True)
    return proc.returncode == 0, ((proc.stdout or "")
                                 + (proc.stderr or ""))[-300:]


def run_shield(root):
    """Compila e roda o teste nativo da guarda anti-NULL (execucao real)."""
    build = os.path.join(root, "build")
    os.makedirs(build, exist_ok=True)
    exe = os.path.join(build, "test_fm5_event_shield")
    cmd = [
        "gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-I", os.path.join(root, "fm5-p2", "include"),
        "-I", os.path.join(root, "fm5-p2", "src"),
        "-o", exe,
        os.path.join(root, "tests", "test_fm5_event_shield.c"),
    ]
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        return False, "compilacao falhou: " + (proc.stderr or "")[-300:]
    run = subprocess.run([exe], cwd=root, capture_output=True, text=True)
    return run.returncode == 0, ((run.stdout or "") + (run.stderr or ""))[-300:]


def run_visibility(root):
    """Compila e roda o teste nativo da blindagem da Visibility Thread."""
    build = os.path.join(root, "build")
    os.makedirs(build, exist_ok=True)
    exe = os.path.join(build, "test_fm5_visibility_shield")
    cmd = [
        "gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-I", os.path.join(root, "fm5-p2", "include"),
        "-I", os.path.join(root, "fm5-p2", "src"),
        "-o", exe,
        os.path.join(root, "tests", "test_fm5_visibility_shield.c"),
    ]
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        return False, "compilacao falhou: " + (proc.stderr or "")[-300:]
    env = dict(os.environ)
    # A ancora forense aponta para o executavel do checkout REAL: a copia
    # temporaria nao leva Game/Mount (o teste aceita FM5_TITLE_EXE).
    candidate_title = os.path.join(REPO, "Game", "Mount", "forza_durango_release_final.exe")
    if not os.path.isfile(candidate_title):
        candidate_title = os.path.join(REPO, "..", "Games", "ForzaMotorsport5", "Game", "Mount", "forza_durango_release_final.exe")
    env["FM5_TITLE_EXE"] = candidate_title
    run = subprocess.run([exe], cwd=root, capture_output=True, text=True,
                         env=env)
    return run.returncode == 0, ((run.stdout or "") + (run.stderr or ""))[-300:]


def run_pairing(root):
    """Compila e roda o teste nativo do args de pareamento (fm5_pairing.c)."""
    build = os.path.join(root, "build")
    os.makedirs(build, exist_ok=True)
    exe = os.path.join(build, "test_fm5_pairing")
    cmd = [
        "gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
        "-I", os.path.join(root, "fm5-p2", "include"),
        "-o", exe,
        os.path.join(root, "tests", "test_fm5_pairing.c"),
        os.path.join(root, "fm5-p2", "src", "fm5_pairing.c"),
        os.path.join(root, "fm5-p2", "src", "fm5_identity.c"),
    ]
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        return False, "compilacao falhou: " + (proc.stderr or "")[-300:]
    run = subprocess.run([exe], cwd=root, capture_output=True, text=True)
    return run.returncode == 0, ((run.stdout or "") + (run.stderr or ""))[-300:]


RUNNERS = {
    "identity": lambda root: run_native(root, "test_fm5_identity"),
    "contract": lambda root: run_native(root, "test_fm5_contract"),
    "hooks": run_hooks_contract,
    "pairing": run_pairing,
    "shield": run_shield,
    "visibility": run_visibility,
}


def make_tree(dest):
    """Copia só o necessário para compilar/rodar a suíte real."""
    shutil.copytree(os.path.join(REPO, "fm5-p2", "src"),
                    os.path.join(dest, "fm5-p2", "src"))
    shutil.copytree(os.path.join(REPO, "fm5-p2", "include"),
                    os.path.join(dest, "fm5-p2", "include"))
    os.makedirs(os.path.join(dest, "tests"), exist_ok=True)
    for name in os.listdir(os.path.join(REPO, "tests")):
        if name.endswith(".c") or name.endswith(".py"):
            shutil.copy2(os.path.join(REPO, "tests", name),
                         os.path.join(dest, "tests", name))


def main():
    before = snapshot()
    if len(before) != len(WATCHED):
        missing = [r for r in WATCHED if r not in before]
        print("FALHA: fontes ausentes: %r" % missing)
        return 1

    failures = []
    checks = 0
    work = tempfile.mkdtemp(prefix="fm5-168-mut-")
    try:
        pristine = os.path.join(work, "pristine")
        make_tree(pristine)

        # Controle: a árvore limpa tem de ficar VERDE nos três runners.
        for name in ("identity", "contract", "hooks", "pairing", "shield",
                     "visibility"):
            checks += 1
            ok, detail = RUNNERS[name](pristine)
            if not ok:
                failures.append("controle %s deveria passar: %s"
                                % (name, detail))

        for mut in MUTATIONS:
            tree = os.path.join(work, mut["id"])
            shutil.copytree(pristine, tree)
            err = apply_mutation(tree, mut)
            checks += 1
            if err:
                failures.append("mutacao %s inaplicavel: %s" % (mut["id"], err))
                continue
            for runner in mut["runners"]:
                checks += 1
                ok, detail = RUNNERS[runner](tree)
                if ok:
                    failures.append(
                        "MUTANTE SOBREVIVEU: %s (%s) nao foi detectada por "
                        "%s — %s" % (mut["id"], mut["file"], runner, mut["why"]))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    after = snapshot()
    checks += 1
    if before != after:
        changed = [k for k in before if before[k] != after.get(k)]
        failures.append("checkout compartilhado foi contaminado: %r" % changed)

    checks += 1
    if len(after) != len(WATCHED):
        failures.append("fontes desapareceram do checkout durante o teste")

    if failures:
        print("FALHA: %d/%d verificacoes de mutacao falharam"
              % (len(failures), checks))
        for f in failures:
            print("  - " + f)
        return 1
    print("OK: %d verificacoes de sensibilidade (%d mutacoes x runners) "
          "passaram" % (checks, len(MUTATIONS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
