#!/usr/bin/env python3
"""
test_pe_targets.py — validação determinística do binário alvo do Player 2.

Prova, sem desassemblador e sem rede, que:
  1. azimuth.exe é PE32+ x86-64 com image base 0x140000000;
  2. os prologues dos 3 alvos de hook batem byte-a-byte;
  3. as vtables apontam para as funções esperadas nos slots esperados;
  4. as strings de classe usadas na construção do IVectorView são as reais;
  5. os helpers (factory/allocators/HSTRING) têm as assinaturas esperadas;
  6. os fontes da DLL referenciam exatamente os RVAs auditados.

Exit 0 = tudo confere; 1 = divergência (o build 1.0.4 não é o alvo).
"""
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANDIDATE_EXES = [
    os.path.join(REPO, "azimuth.exe"),
    os.path.join(REPO, "..", "Games", "ForzaMotorsport5", "azimuth.exe"),
    os.environ.get("FM5_AZIMUTH_EXE", ""),
]
EXE = next((p for p in CANDIDATE_EXES if p and os.path.isfile(p)), os.path.join(REPO, "azimuth.exe"))
SRC_DIR = os.path.join(REPO, "src") if os.path.isdir(os.path.join(REPO, "src")) else os.path.join(REPO, "fm5-p2", "src")

failures = []
checks = 0


def check(cond, msg):
    global checks
    checks += 1
    if not cond:
        failures.append(msg)


def read_u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def read_u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def read_u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def main():
    if not os.path.isfile(EXE):
        print("FALHA: azimuth.exe nao encontrado em %s" % EXE)
        return 1
    with open(EXE, "rb") as f:
        data = f.read()

    # ---- Cabecalho PE -----------------------------------------------------
    check(data[:2] == b"MZ", "assinatura MZ ausente")
    pe_off = read_u32(data, 0x3C)
    check(data[pe_off:pe_off + 4] == b"PE\0\0", "assinatura PE ausente")
    coff = pe_off + 4
    machine = read_u16(data, coff)
    num_sections = read_u16(data, coff + 2)
    opt_size = read_u16(data, coff + 16)
    opt = coff + 20
    magic = read_u16(data, opt)
    image_base = read_u64(data, opt + 24)
    check(machine == 0x8664, "machine esperado 0x8664, obtido 0x%04x" % machine)
    check(magic == 0x20B, "magic esperado PE32+ (0x20b), obtido 0x%03x" % magic)
    check(image_base == 0x140000000,
          "image base esperado 0x140000000, obtido 0x%x" % image_base)

    # ---- Tabela de secoes -> mapa RVA/fileregiao --------------------------
    sections = []
    sec = opt + opt_size
    for i in range(num_sections):
        base = sec + i * 40
        name = data[base:base + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize = read_u32(data, base + 8)
        vaddr = read_u32(data, base + 12)
        rawsize = read_u32(data, base + 16)
        rawptr = read_u32(data, base + 20)
        sections.append((name, vaddr, vsize, rawptr, rawsize))

    def rva_to_off(rva):
        for name, vaddr, vsize, rawptr, rawsize in sections:
            span = max(vsize, rawsize)
            if vaddr <= rva < vaddr + span:
                delta = rva - vaddr
                if delta >= rawsize:
                    return None
                return rawptr + delta
        return None

    def bytes_at(rva, n):
        off = rva_to_off(rva)
        if off is None or off + n > len(data):
            return None
        return data[off:off + n]

    def ptr_at(rva):
        b = bytes_at(rva, 8)
        return None if b is None else read_u64(b, 0)

    def wstring_at(rva):
        off = rva_to_off(rva)
        if off is None:
            return None
        end = off
        while end + 1 < len(data) and data[end:end + 2] != b"\0\0":
            end += 2
        return data[off:end].decode("utf-16-le", "replace")

    # ---- Prologues --------------------------------------------------------
    prologues = {
        0x19A4C0: (bytes.fromhex("40534883ec20488bdae8b284eaff"),
                   "Controller::get_User"),
        0x0424A0: (bytes.fromhex("48895c2408488974241848897c2420"),
                   "UserStatics::get_Users"),
        0x041D10: (bytes.fromhex("48895c241048897c241841564883ec20"),
                   "UserDisplayInfo::get_DisplayName"),
        # TICKET-HARNESS-159: hardcode `cmp $1,%edx; jne -> NULL`
        0x042580: (bytes.fromhex("4883ec2883fa017506488b4918eb02"),
                   "UserStatics::GetUserById"),
        # vtable[6]: `mov dword [rdx],1` (contagem hardcoded)
        0x042480: (bytes.fromhex("4885d27506b803400080c3c70201000000"),
                   "UserStatics vtable[6] count"),
        # vtable[7]/[8]: add/remove do evento UserAdded em +0x20
        0x0425C0: (bytes.fromhex("4883ec284883c1204d8bc84c8bc233d2"),
                   "UserStatics vtable[7] UserAdded add"),
        0x0425E0: (bytes.fromhex("4883ec284883c1204c8bc233d2e8ae110000"),
                   "UserStatics vtable[8] UserAdded remove"),
        # User::get_Id: `mov dword [rdx],1` (todo User se apresenta como 1)
        0x041F70: (bytes.fromhex("4885d27506b803400080c3c7020100000033c0c3"),
                   "User::get_Id"),
        # TICKET-HARNESS-160: prologue comum de leitura de Gamepad
        # (0x19a5c0/0x19a690 -> 0x4b18c0). 15 bytes terminam exatamente na
        # fronteira de instrucao antes de `sub rsp,0x70`.
        0x04B18C0: (bytes.fromhex("48895c241055565741564157488bec"),
                    "Gamepad::GetReading (shared)"),
        # TICKET-HARNESS-168: getter do User da "LiveTable"/AccountPicker,
        # usado como alvo do detour que serve o Player 2 virtual.
        0x04C8030: (bytes.fromhex("40534883ec20e845a9b7ff90488b5818"),
                    "UserStatics::MakeAccountPickerUser"),
    }
    for rva, (expect, name) in prologues.items():
        got = bytes_at(rva, len(expect))
        check(got == expect,
              "%s (RVA 0x%x): prologue divergente: %s != %s" %
              (name, rva, got.hex() if got else "None", expect.hex()))

    # TICKET-HARNESS-160: o patch de 15 bytes do get_reading tem de retomar
    # exatamente em 0x4b18cf (`sub rsp,0x70`), sem partir instrucao. Se este
    # byte mudar, o trampolim executaria lixo e derrubaria o jogo.
    check(bytes_at(0x04B18CF, 4) == bytes.fromhex("4883ec70"),
          "get_reading: ponto de retomada 0x4b18cf nao e sub rsp,0x70")

    # ---- get_User: elo call -> UserStatics e semantica de AddRef ----------
    # Ancora o RVA_USER_STATICS de PRODUCAO no binario real: o disp32 do CALL
    # em 0x19a4c9 (o mesmo copiado para o trampolim) tem de resolver para a
    # RVA declarada em fm5_hooks.c. Um RVA errado aqui derruba o jogo; sem
    # esta checagem o mutante sobreviveria a suite.
    try:
        with open(os.path.join(SRC_DIR, "fm5_hooks.c"), "r",
                  encoding="utf-8") as f:
            hooks_text = f.read()
        m = re.search(r"#define\s+RVA_USER_STATICS\s+(0x[0-9A-Fa-f]+)u?",
                      hooks_text)
        check(m is not None, "fm5_hooks.c: RVA_USER_STATICS nao declarado")
        if m:
            declared_rva = int(m.group(1), 16)
            call_site = bytes_at(0x19A4C9, 5)
            check(call_site is not None and call_site[0] == 0xE8,
                  "get_User: 0x19a4c9 nao e CALL (bytes=%s)" %
                  (call_site.hex() if call_site else "None"))
            if call_site is not None and call_site[0] == 0xE8:
                disp = struct.unpack("<i", call_site[1:5])[0]
                target = image_base + 0x19A4C9 + 5 + disp
                check(target == image_base + declared_rva,
                      "get_User: call 0x19a4c9 -> 0x%x, RVA_USER_STATICS "
                      "declarado aponta para 0x%x" %
                      (target, image_base + declared_rva))
            # O trampolim (patch de 14 bytes) retoma em 0x19a4ce; o byte
            # seguinte tem de ser NOP e 0x19a4cf le o User em +0x18.
            check(bytes_at(0x19A4CE, 1) == b"\x90",
                  "get_User: ponto de retomada 0x19a4ce nao e NOP")
            check(bytes_at(0x19A4CF, 4) == bytes.fromhex("488b4818"),
                  "get_User: 0x19a4cf nao le o User em +0x18")
            # Semantica WinRT exata: *out = user (0x19a4e3), AddRef via
            # vtable[1] (0x19a4eb) e S_OK (0x19a4f2), nesta ordem.
            check(bytes_at(0x19A4E3, 3) == bytes.fromhex("48890b"),
                  "get_User: 0x19a4e3 nao grava *out = user")
            check(bytes_at(0x19A4EB, 6) == bytes.fromhex("488b01ff5008"),
                  "get_User: 0x19a4eb nao chama AddRef via vtable[1]")
            check(bytes_at(0x19A4F2, 2) == bytes.fromhex("33c0"),
                  "get_User: 0x19a4f2 nao devolve S_OK")
    except OSError as exc:
        check(False, "fm5_hooks.c ilegivel: %s" % exc)

    # ---- Vtables ----------------------------------------------------------
    vt_checks = [
        (0x6EDAB8 + 8 * 8, 0x14019A4C0, "Controller iface slot 8 -> get_User"),
        (0x6C0898 + 9 * 8, 0x1400424A0, "UserStatics slot 9 -> get_Users"),
        (0x6C0898 + 6 * 8, 0x140042480, "UserStatics slot 6 -> count"),
        (0x6C0898 + 7 * 8, 0x1400425C0, "UserStatics slot 7 -> UserAdded add"),
        (0x6C0898 + 8 * 8, 0x1400425E0, "UserStatics slot 8 -> UserAdded remove"),
        (0x6C0898 + 14 * 8, 0x140042580, "UserStatics slot 14 -> GetUserById"),
        (0x6C0760 + 6 * 8, 0x140041D10, "UserDisplayInfo slot 6 -> get_DisplayName"),
        (0x6C0B48 + 6 * 8, 0x140041F70, "User slot 6 -> get_Id"),
        (0x6C0B48 + 9 * 8, 0x140042050, "User slot 9 -> inner (display info)"),
    ]
    for rva, expect, name in vt_checks:
        got = ptr_at(rva)
        check(got == expect,
              "%s: esperado 0x%x, obtido %s" %
              (name, expect, ("0x%x" % got) if got is not None else "None"))

    # ---- TICKET-HARNESS-168: vtable de User (identidade Guest) ------------
    # Slots 10/14/15 = get_IsGuest / get_XboxUserHash / get_XboxUserId. O
    # patch valida estes ponteiros antes de trocar: se o build mudar, o patch
    # e cancelado (fail-closed) e o P2 nao se apresenta como Convidado.
    vt168 = [
        (0x6C0B48, 10, 0x140042080, "User slot 10 -> get_IsGuest"),
        (0x6C0B48, 14, 0x140042100, "User slot 14 -> get_XboxUserHash"),
        (0x6C0B48, 15, 0x140042150, "User slot 15 -> get_XboxUserId"),
    ]
    # ControllerStatics: slots 7..12 = Added add/remove, Removed add/remove,
    # PairingChanged add/remove.
    ctrl_vt = [
        (7, 0x14019B9C0, "ControllerStatics slot 7 -> ControllerAdded add"),
        (8, 0x14019B9E0, "ControllerStatics slot 8 -> ControllerAdded remove"),
        (9, 0x14019BA00, "ControllerStatics slot 9 -> ControllerRemoved add"),
        (10, 0x14019BA20, "ControllerStatics slot 10 -> ControllerRemoved remove"),
        (11, 0x14019BA40, "ControllerStatics slot 11 -> PairingChanged add"),
        (12, 0x14019BA60, "ControllerStatics slot 12 -> PairingChanged remove"),
    ]
    for vt_rva, slot, expect, name in vt168 + [
            (0x6ED8B8, sl, ex, nm) for sl, ex, nm in ctrl_vt]:
        got = ptr_at(vt_rva + 8 * slot)
        check(got == expect,
              "%s: esperado 0x%x, obtido %s" %
              (name, expect, ("0x%x" % got) if got is not None else "None"))

    # Os 6 thunks de evento comecam com `sub rsp,0x28; add rcx,0x18` — prova
    # que o self e ajustado para o container de handlers em +0x18.
    for rva in (0x19B9C0, 0x19B9E0, 0x19BA00, 0x19BA20, 0x19BA40, 0x19BA60):
        check(bytes_at(rva, 8) == bytes.fromhex("4883ec284883c118"),
              "thunk de ControllerStatics 0x%x: prologue divergente" % rva)

    # Add vs remove: os ADD thunks movem `r8 -> r9` (token) e zeram/ajustam
    # edx (indice do container); os REMOVE nao. Ancora a ABI (self, handler,
    # token*) usada por ctrl_event_add.
    for rva in (0x19B9C0, 0x19BA00, 0x19BA40):
        check(bytes_at(rva + 8, 6) == bytes.fromhex("4d8bc84c8bc2"),
              "add thunk 0x%x: nao move r9=r8/r8=rdx (ABI add)" % rva)

    # Singleton de ControllerStatics: aloca 0xb0 bytes (`mov ecx,0xb0`), o que
    # confirma o tamanho do objeto e o getter usado como `sender` do evento.
    check(bytes_at(0x19BEB4, 5) == bytes.fromhex("b9b0000000"),
          "ControllerStatics singleton: alocacao de 0xb0 bytes ausente")

    # Ponto de retomada do patch de 16 bytes em MakeAccountPickerUser:
    # 0x4c8040 = `test rbx,rbx` (nao parte instrucao).
    check(bytes_at(0x04C8040, 3) == bytes.fromhex("4885db"),
          "MakeAccountPickerUser: retomada 0x4c8040 nao e test rbx,rbx")

    # ---- Strings de classe ------------------------------------------------
    strings = [
        (0x6C05B0, "Windows.Xbox.System.User", "User class name"),
        (0x6C05F0, "Windows.Xbox.System.UserDisplayInfo", "display info class"),
        (0x6C0638, "Azimuth.OfflineUserView", "view class name"),
        (0x6C0668, "Azimuth.OfflineUserIterator", "iterator class name"),
    ]
    for rva, expect, name in strings:
        got = wstring_at(rva)
        check(got == expect,
              "%s (RVA 0x%x): esperado %r, obtido %r" % (name, rva, expect, got))

    # ---- Helpers usados pela camada Windows -------------------------------
    helpers = [
        (0x6057E4, bytes.fromhex("e9dbe20000"), "operator new (jmp)"),
        (0x00DF90, None, "operator new[]"),
        (0x041F00, bytes.fromhex("40534883ec20488d"), "User factory"),
        (0x17F310, bytes.fromhex("48895c2408574883"), "HSTRING maker"),
    ]
    for rva, expect, name in helpers:
        got = bytes_at(rva, 8)
        check(got is not None, "%s (RVA 0x%x): fora do arquivo" % (name, rva))
        if expect is not None and got is not None:
            check(got[:len(expect)] == expect,
                  "%s (RVA 0x%x): prologue divergente %s != %s" %
                  (name, rva, got[:len(expect)].hex(), expect.hex()))

    # ---- Fontes referenciam os RVAs auditados -----------------------------
    hooks_src = os.path.join(SRC_DIR, "fm5_hooks.c")
    check(os.path.isfile(hooks_src), "fm5_hooks.c ausente")
    if os.path.isfile(hooks_src):
        with open(hooks_src, "r", encoding="utf-8") as f:
            src = f.read()
        required = [
            "0x19a4c0", "0x0424a0", "0x041d10",
            "0x6057e4", "0x00df90", "0x041f00", "0x17f310",
            "0x6c09d0", "0x6c0720", "0x6c0638", "0x6c0668",
            # TICKET-HARNESS-159
            "0x042580", "0x042480", "0x0425c0", "0x0425e0", "0x041f70",
            # TICKET-HARNESS-160
            "0x04b18c0", "0x19a5c0", "0x19a690",
            "FM5_P2_SWAP_START_BACK",
            # TICKET-HARNESS-168 — identidade Guest + evento de pareamento
            "0x6c0b48", "0x042080", "0x042100", "0x042150",
            "0x6ed8b8", "0x19b9c0", "0x19b9e0", "0x19ba00", "0x19ba20",
            "0x19ba40", "0x19ba60", "0x19be70", "0x4c8030",
            "FM5_P2_DISABLE_PAIRING_EVENT",
            "MakeAccountPickerUser", "ControllerPairingChanged",
        ]
        for token in required:
            check(token in src, "fm5_hooks.c nao referencia o RVA %s" % token)

    # ---- TICKET-HARNESS-165: IAT de RoGetActivationFactory ----------------
    # O slot RVA 0x68e8c0 tem de estar na IAT e apontar para o nome
    # RoGetActivationFactory (via api-ms-win-core-winrt-l1-1-0.dll). Sem essa
    # prova o patch da bridge SystemUI poderia acertar memoria errada.
    def cstr_at(rva):
        off = rva_to_off(rva)
        if off is None:
            return None
        end = data.find(b"\0", off)
        if end < 0:
            return None
        return data[off:end].decode("ascii", "replace")

    ro_slot_name = None
    import_rva = read_u32(data, opt + 112 + 8)
    import_off = rva_to_off(import_rva)
    if import_off is not None:
        entry = import_off
        for _ in range(64):
            oft, _ts, _fc, name_rva, ft = struct.unpack_from(
                "<IIIII", data, entry)
            if name_rva == 0:
                break
            if ft == 0x68E8C0:
                lookup = rva_to_off(oft) if oft else rva_to_off(ft)
                if lookup is not None:
                    hint = read_u32(data, lookup)
                    if hint & 0x80000000 == 0:
                        ro_slot_name = cstr_at((hint & 0x7FFFFFFF) + 2)
                break
            entry += 20
    check(ro_slot_name == "RoGetActivationFactory",
          "IAT RVA 0x68e8c0 nao e RoGetActivationFactory (obtido %r)" %
          ro_slot_name)
    check("0x68e8c0" in src if os.path.isfile(hooks_src) else False,
          "fm5_hooks.c nao referencia o slot IAT 0x68e8c0")

    # Bridge portatil: nome de classe, GUID e ShowAccountPickerAsync.
    systemui_src = os.path.join(SRC_DIR, "fm5_systemui.c")
    systemui_hdr = os.path.join(REPO, "include", "fm5_systemui.h") if os.path.isfile(os.path.join(REPO, "include", "fm5_systemui.h")) else os.path.join(REPO, "fm5-p2", "include", "fm5_systemui.h")
    check(os.path.isfile(systemui_src), "fm5_systemui.c ausente")
    check(os.path.isfile(systemui_hdr), "fm5_systemui.h ausente")
    if os.path.isfile(systemui_src) and os.path.isfile(systemui_hdr):
        with open(systemui_src, "r", encoding="utf-8") as f:
            sysrc = f.read()
        with open(systemui_hdr, "r", encoding="utf-8") as f:
            syshdr = f.read()
        check("Windows.Xbox.UI.SystemUI" in syshdr,
              "fm5_systemui.h nao declara a classe Windows.Xbox.UI.SystemUI")
        # GUID ISystemUIStatics {1a0dd80e-3f9d-4cfa-8e50-0e2ebd1aa72f}.
        check("0x0e, 0xd8, 0x0d, 0x1a" in sysrc and
              "0x8e, 0x50, 0x0e, 0x2e, 0xbd, 0x1a, 0xa7, 0x2f" in sysrc,
              "fm5_systemui.c nao contem os bytes do GUID ISystemUIStatics")
        check("show_account_picker_async" in sysrc,
              "fm5_systemui.c nao implementa ShowAccountPickerAsync")
        check("FM5_SYSTEMUI_VT_SHOW_ACCOUNT_PICKER == 8u" in syshdr or
              "FM5_SYSTEMUI_VT_SHOW_ACCOUNT_PICKER 8u" in syshdr,
              "fm5_systemui.h nao fixa ShowAccountPickerAsync no slot 8")

    # ---- ShowAccountPickerAsync: nao existe neste build -------------------
    # O wrapper offline 1.0.4 nao expoe nenhum seletor de conta (nem o simbolo
    # ASCII nem o nome de classe UTF-16). Portanto NAO ha stub a forcar: o
    # caminho de login nao pode bloquear o Player 2 por essa via. A ausencia e
    # verificada de forma deterministica para nao "inventar" um alvo.
    check(b"ShowAccountPicker" not in data,
          "azimuth.exe contem ShowAccountPicker (build diferente do 1.0.4?)")
    check("ShowAccountPicker".encode("utf-16-le") not in data,
          "azimuth.exe contem ShowAccountPicker em UTF-16")
    check(b"AccountPicker" not in data,
          "azimuth.exe contem AccountPicker (build diferente do 1.0.4?)")

    proxy_src = os.path.join(SRC_DIR, "dinput8_proxy.c")
    check(os.path.isfile(proxy_src), "dinput8_proxy.c ausente")
    if os.path.isfile(proxy_src):
        with open(proxy_src, "r", encoding="utf-8") as f:
            proxy = f.read()
        for export in ("DirectInput8Create", "DllCanUnloadNow",
                       "DllGetClassObject", "DllRegisterServer",
                       "DllUnregisterServer"):
            check(export in proxy, "proxy nao exporta/encaminha %s" % export)

    # ---- Blindagem do carregamento (crash 0xC0000005 @ 0x140687f4c) -------
    # O rip do crash NÃO pertence ao azimuth.exe: pertence ao executável do
    # TÍTULO (Game/Mount/forza_durango_release_final.exe), mapeado manualmente
    # pelo Azimuth na base preferida 0x140000000. A prova é byte-a-byte e o
    # unwind info observado no log (0x2024bf4 para 0x5d7500 e 0x204673c para
    # 0x687e20) casa com o .pdata do arquivo do título.
    CANDIDATE_GUESTS = [
        os.path.join(REPO, "Game", "Mount", "forza_durango_release_final.exe"),
        os.path.join(REPO, "..", "Games", "ForzaMotorsport5", "Game", "Mount", "forza_durango_release_final.exe"),
        os.environ.get("FM5_TITLE_EXE", ""),
    ]
    guest_path = next((p for p in CANDIDATE_GUESTS if p and os.path.isfile(p)), os.path.join(REPO, "Game", "Mount", "forza_durango_release_final.exe"))
    check(os.path.isfile(guest_path),
          "executavel do titulo ausente em %s" % guest_path)
    if os.path.isfile(guest_path):
        with open(guest_path, "rb") as f:
            guest = f.read()

        g_pe = read_u32(guest, 0x3C)
        check(guest[:2] == b"MZ" and guest[g_pe:g_pe + 4] == b"PE\0\0",
              "titulo: cabecalho PE ausente")
        g_coff = g_pe + 4
        g_nsec = read_u16(guest, g_coff + 2)
        g_optsz = read_u16(guest, g_coff + 16)
        g_opt = g_coff + 20
        check(read_u16(guest, g_coff) == 0x8664,
              "titulo: machine != x86-64")
        check(read_u16(guest, g_opt) == 0x20B,
              "titulo: magic != PE32+")
        check(read_u64(guest, g_opt + 24) == 0x140000000,
              "titulo: ImageBase != 0x140000000 (base do rip do crash)")
        check(read_u32(guest, g_opt + 56) > 0x204673C,
              "titulo: SizeOfImage nao cobre o unwind info do crash")

        g_secs = []
        g_sec = g_opt + g_optsz
        for i in range(g_nsec):
            b = g_sec + i * 40
            g_secs.append((read_u32(guest, b + 12), read_u32(guest, b + 8),
                           read_u32(guest, b + 20), read_u32(guest, b + 16)))

        def g_rva_off(rva):
            for vaddr, vsize, rawptr, rawsize in g_secs:
                if vaddr <= rva < vaddr + max(vsize, rawsize):
                    d = rva - vaddr
                    return rawptr + d if d < rawsize else None
            return None

        def g_bytes(rva, n):
            o = g_rva_off(rva)
            if o is None or o + n > len(guest):
                return None
            return guest[o:o + n]

        # Prologue do handler WindowActivated (RVA 0x5d7500) — o hook de 15
        # bytes termina na fronteira exata da instrucao seguinte.
        check(g_bytes(0x5D7500, 15) ==
              bytes.fromhex("40574883ec5048c7442430feffffff"),
              "titulo: prologue de 0x5d7500 divergente do crash")
        check(g_bytes(0x5D7500 + 15, 4) == bytes.fromhex("48895c24"),
              "titulo: retomada 0x5d750f nao e mov [rsp+0x60],rbx")
        # Sequencia do crash na fila (RVA 0x687f48): mov rax,[rcx+8];
        # mov [rax],rcx  => 48 8b 41 08 48 89 08 (NUNCA 48 89 01, que e
        # `mov [rcx],rax` e nao escreveria em 0x0).
        check(g_bytes(0x687F48, 7) == bytes.fromhex("488b4108488908"),
              "titulo: sequencia de 0x687f48 divergente do crash "
              "(mov rax,[rcx+8]; mov [rax],rcx)")
        check(g_bytes(0x687F4F, 4) == bytes.fromhex("488b4c24"),
              "titulo: retomada 0x687f4f nao e fronteira de instrucao")
        # .pdata: as duas funcoes do log existem nas RVAs exatas e apontam
        # para os unwind infos registrados (0x2024bf4 / 0x204673c).
        g_pd_off = g_rva_off(0x261E000)
        pd_found = {}
        if g_pd_off is not None:
            for o in range(g_pd_off, min(g_pd_off + 0xE2050, len(guest)), 12):
                b0, b1, u = struct.unpack_from("<III", guest, o)
                if b0 == 0x5D7500:
                    pd_found["window"] = (b0, b1, u)
                if b0 == 0x687E20:
                    pd_found["queue"] = (b0, b1, u)
        check(pd_found.get("window") == (0x5D7500, 0x5D75D8, 0x2024BF4),
              "titulo: RUNTIME_FUNCTION de WindowActivated divergente "
              "(obtido %r)" % (pd_found.get("window"),))
        check(pd_found.get("queue") == (0x687E20, 0x687F96, 0x204673C),
              "titulo: RUNTIME_FUNCTION de EventQueue::PostEvent divergente "
              "(obtido %r)" % (pd_found.get("queue"),))

    # Ancoras no fonte de producao (os RVAs acima, nao os do wrapper).
    if os.path.isfile(hooks_src):
        for token in ("0x5d7500", "0x687f48", "0x140000000",
                      "forza_durango_release_final.exe"):
            check(token in src,
                  "fm5_hooks.c nao ancora o alvo da blindagem %s" % token)
        check("g_hook_window_activated.target = g_game_base + "
              "RVA_WINDOW_ACTIVATED;" in src,
              "fm5_hooks.c nao aponta o hook para o executavel do titulo")
        check("g_hook_window_activated.expect = EXPECT_WINDOW_ACTIVATED;" in src,
              "fm5_hooks.c nao valida o prologue do titulo antes do hook")
    else:
        check(False, "fm5_hooks.c ausente para ancorar a blindagem")

    shield_hdr = os.path.join(SRC_DIR, "fm5_event_shield_encode.h")
    check(os.path.isfile(shield_hdr), "fm5_event_shield_encode.h ausente")
    if os.path.isfile(shield_hdr):
        with open(shield_hdr, "r", encoding="utf-8") as f:
            shield = f.read()

        def macro_hex(text, name):
            m = re.search(r"#define\s+%s\s+([^\n]*)" % re.escape(name), text)
            if not m:
                return None
            return "".join(x.lower()
                           for x in re.findall(r"0x([0-9A-Fa-f]{2})",
                                               m.group(1)))

        check(re.search(r"#define\s+FM5_SHIELD_RVA\s+0x687F48u?",
                        shield) is not None,
              "FM5_SHIELD_RVA deve ser 0x687f48 (rip do crash)")
        check(re.search(r"#define\s+FM5_SHIELD_RESUME_RVA\s+0x687F4Fu?",
                        shield) is not None,
              "FM5_SHIELD_RESUME_RVA deve ser 0x687f4f (fronteira apos a "
              "escrita)")
        check(macro_hex(shield, "FM5_SHIELD_ORIG_BYTES") == "488b4108488908",
              "constante forense deve ser 48 8b 41 08 48 89 08 "
              "(mov rax,[rcx+8]; mov [rax],rcx)")
        check(macro_hex(shield, "FM5_SHIELD_CAVE_OPCODES") ==
              "488b41089c4885c074034889089d",
              "caverna deve ser test rax,rax + jz + mov [rax],rcx com "
              "pushfq/popfq")
        if os.path.isfile(hooks_src):
            check(re.search(r"RVA_WINDOW_ACTIVATED\s+0x5d7500u?", src)
                  is not None,
                  "RVA_WINDOW_ACTIVATED deve ser 0x5d7500")
            check(re.search(r"#define\s+RVA_EVENT_QUEUE_LINK\s+0x687[Ff]48u?",
                            src) is not None,
                  "RVA_EVENT_QUEUE_LINK deve ser 0x687f48")

    # ---- Resultado --------------------------------------------------------
    if failures:
        print("FALHA: %d/%d verificacoes do binario falharam" %
              (len(failures), checks))
        for f in failures:
            print("  - " + f)
        return 1
    print("OK: %d verificacoes do binario alvo passaram" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
