#!/usr/bin/env python3
"""
test_dll_artifact.py — valida o artefato dist/dinput8.dll quando presente.

Se o mingw-w64 não estiver disponível e a DLL não tiver sido gerada, o teste
imprime SKIP e sai com 0 (a suíte nativa + a validação do exe continuam
obrigatórias). Se a DLL existir, ela PRECISA ser um PE32+ x86-64 com o flag de
DLL e exportar exatamente os 5 símbolos de dinput8, importando KERNEL32.
"""
import hashlib
import os
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DLL = os.path.join(REPO, "fm5-p2", "dist", "dinput8.dll")

EXPECTED_EXPORTS = {
    "DirectInput8Create",
    "DllCanUnloadNow",
    "DllGetClassObject",
    "DllRegisterServer",
    "DllUnregisterServer",
}

failures = []
checks = 0


def check(cond, msg):
    global checks
    checks += 1
    if not cond:
        failures.append(msg)


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def main():
    if not os.path.isfile(DLL):
        print("SKIP: dist/dinput8.dll ausente (mingw-w64 indisponivel nesta maquina)")
        return 0

    with open(DLL, "rb") as f:
        data = f.read()

    check(data[:2] == b"MZ", "DLL: assinatura MZ ausente")
    pe = u32(data, 0x3C)
    check(data[pe:pe + 4] == b"PE\0\0", "DLL: assinatura PE ausente")
    coff = pe + 4
    machine = u16(data, coff)
    num_sections = u16(data, coff + 2)
    opt_size = u16(data, coff + 16)
    characteristics = u16(data, coff + 18)
    opt = coff + 20
    magic = u16(data, opt)
    check(machine == 0x8664, "DLL: machine 0x%04x != 0x8664" % machine)
    check(magic == 0x20B, "DLL: magic 0x%03x != PE32+" % magic)
    check(characteristics & 0x2000, "DLL: flag IMAGE_FILE_DLL ausente")

    sections = []
    sec = opt + opt_size
    for i in range(num_sections):
        base = sec + i * 40
        vsize = u32(data, base + 8)
        vaddr = u32(data, base + 12)
        rawsize = u32(data, base + 16)
        rawptr = u32(data, base + 20)
        sections.append((vaddr, vsize, rawptr, rawsize))

    def rva_off(rva):
        for vaddr, vsize, rawptr, rawsize in sections:
            span = max(vsize, rawsize)
            if vaddr <= rva < vaddr + span:
                d = rva - vaddr
                if d < rawsize:
                    return rawptr + d
        return None

    def cstr(rva):
        o = rva_off(rva)
        if o is None:
            return None
        e = data.find(b"\0", o)
        if e < 0:
            return None
        return data[o:e].decode("ascii", "replace")

    # Data directories (PE32+: inicio em opt + 112)
    dd = opt + 112
    export_rva = u32(data, dd + 0)
    import_rva = u32(data, dd + 8)

    # ---- Exports ----------------------------------------------------------
    eo = rva_off(export_rva)
    check(eo is not None, "DLL: diretorio de exportacao invalido")
    if eo is not None:
        num_names = u32(data, eo + 24)
        addr_names = u32(data, eo + 32)
        names = set()
        for i in range(num_names):
            nrva = u32(data, rva_off(addr_names) + i * 4)
            name = cstr(nrva)
            if name:
                names.add(name)
        check(names == EXPECTED_EXPORTS,
              "DLL: exports %r != esperado %r" %
              (sorted(names), sorted(EXPECTED_EXPORTS)))

    # ---- Imports ----------------------------------------------------------
    io = rva_off(import_rva)
    check(io is not None, "DLL: diretorio de importacao invalido")
    if io is not None:
        dlls = set()
        p = io
        while True:
            name_rva = u32(data, p + 12)
            if name_rva == 0:
                break
            d = cstr(name_rva)
            if d:
                dlls.add(d.lower())
            p += 20
            if p - io > 20 * 64:
                break
        check(any(d.startswith("kernel32") for d in dlls),
              "DLL: nao importa KERNEL32 (imports=%r)" % sorted(dlls))

    # ---- TICKET-HARNESS-159: hooks de identidade compilados no artefato ---
    # Cada RVA e embutido como imediato de 32 bits no codigo do hook; se o
    # artefato foi gerado sem os novos alvos, o imediato nao existe.
    for rva, name in (
        (0x042580, "GetUserById"),
        (0x042480, "vtable[6] count"),
        (0x0425C0, "UserAdded add"),
        (0x0425E0, "UserAdded remove"),
        (0x041F70, "User::get_Id"),
    ):
        check(struct.pack("<I", rva) in data,
              "DLL: RVA 0x%05x (%s) ausente do artefato" % (rva, name))
    check(b"GetUserById" in data, "DLL: string de log GetUserById ausente")
    check(b"FM5_P2_DISABLE_USER_ADDED" in data,
          "DLL: kill-switch FM5_P2_DISABLE_USER_ADDED ausente")

    # ---- TICKET-HARNESS-160: hook de GamepadReading + recomposicao Buttons --
    check(struct.pack("<I", 0x04B18C0) in data,
          "DLL: RVA 0x04b18c0 (GamepadReading) ausente do artefato")
    check(b"P2: botoes device=" in data,
          "DLL: string de log de botoes ausente")
    check(b"FM5_P2_SWAP_START_BACK" in data,
          "DLL: override FM5_P2_SWAP_START_BACK ausente")

    # ---- TICKET-HARNESS-163: cascata P1 (A) -> demais P2 -> Start -> P2 -----
    # Marcadores literais introduzidos exclusivamente por este ticket: se o
    # artefato foi compilado sem a cascata, a string nao existe.
    check(b"Player 1 DEFINITIVO eleito por A no splash" in data,
          "DLL: marcador da eleicao de Player 1 por A ausente")
    check(b"Player 2 DEFINITIVO eleito por Start no lobby" in data,
          "DLL: marcador da eleicao de Player 2 por Start ausente")
    check(b"boot como Player 1" in data,
          "DLL: marcador de controle nascendo Player 1 ausente")
    # TICKET-HARNESS-171: o A promove o secundario a Player 2 VIRTUAL (indice 1)
    # e o evento de pareamento leva o User virtual, nunca NULL.
    check(b"secundario(s) promovido(s) a Player 2 virtual" in data,
          "DLL: marcador da promocao direta do secundario (TICKET-171) ausente")
    check(b"Player 2 virtual (user=%p" in data,
          "DLL: marcador do evento de pareamento com User virtual ausente")
    check(b"demais -> Player 3 (indice 2)" in data,
          "DLL: marcador de reatribuicao dos demais para indice 2 ausente")

    # ---- TICKET-HARNESS-165: bridge Windows.Xbox.UI.SystemUI ---------------
    # Marcadores literais e dados da bridge: se a DLL foi compilada sem o
    # modulo SystemUI ou sem o patch do IAT, algum destes nao existe.
    check(struct.pack("<I", 0x68E8C0) in data,
          "DLL: RVA 0x68e8c0 (IAT de RoGetActivationFactory) ausente")
    check("Windows.Xbox.UI.SystemUI".encode("utf-16-le") in data,
          "DLL: nome de classe Windows.Xbox.UI.SystemUI (UTF-16) ausente")
    check(bytes.fromhex("0ed80d1a9d3ffa4c8e500e2ebd1aa72f") in data,
          "DLL: GUID ISystemUIStatics ausente")
    check(b"SystemUI ativado" in data,
          "DLL: marcador de ativacao da SystemUI ausente")
    check(b"ShowAccountPickerAsync -> Player 2 virtual" in data,
          "DLL: marcador de ShowAccountPickerAsync ausente")
    check(b"WindowsGetStringRawBuffer" in data,
          "DLL: API WindowsGetStringRawBuffer ausente")
    check(b"RoGetActivationFactory (IAT" in data,
          "DLL: marcador do hook IAT de RoGetActivationFactory ausente")

    # ---- TICKET-HARNESS-166: enum Xbox One ERA + chave canonica de device --
    # O log do hook de leitura agora grava o baseline do 1o frame e identifica
    # o dispositivo pela chave canonica (device id), nunca por rank.
    check(b"P2: botoes device=" in data,
          "DLL: string de log de botoes ausente")
    check(b"[baseline]" in data,
          "DLL: marcador de baseline do 1o frame ausente")
    check(b"raw=0x%04x gamepad=0x%04x" in data,
          "DLL: formato do log de botoes (raw/gamepad) ausente")
    check(b"reivindicacao sem efeito (device=" in data,
          "DLL: marcador de reivindicacao por device id ausente")
    check(b"directinput=0x%04x" not in data,
          "DLL: log legado 'directinput=' ainda presente no artefato")
    check(b"ShowAccountPickerAsync controller=%p device=%p" in data,
          "DLL: observador de ShowAccountPickerAsync (device id) ausente")

    # ---- TICKET-HARNESS-168: identidade Guest + evento de pareamento ------
    # RVAs dos novos alvos: vtable de User (IsGuest/XboxUserHash/XboxUserId),
    # vtable de ControllerStatics (slots 7..12), singleton e o getter do
    # AccountPicker. Se a DLL foi gerada sem o ticket, o imediato de 32 bits
    # nao existe no codigo.
    for rva, name in (
        (0x042080, "User::get_IsGuest"),
        (0x042100, "User::get_XboxUserHash"),
        (0x042150, "User::get_XboxUserId"),
        (0x6C0B48, "User vtable"),
        (0x6ED8B8, "ControllerStatics vtable"),
        (0x19BE70, "ControllerStatics singleton"),
        (0x19BA40, "ControllerPairingChanged add"),
        (0x19BA60, "ControllerPairingChanged remove"),
        (0x4C8030, "MakeAccountPickerUser"),
    ):
        check(struct.pack("<I", rva) in data,
              "DLL: RVA 0x%05x (%s) ausente do artefato" % (rva, name))
    for marker in (
        b"MakeAccountPickerUser servindo o User virtual",
        b"ControllerPairingChanged disparado",
        b"vtable de User patcheada",
        b"vtable de ControllerStatics patcheada",
        b"FM5_P2_DISABLE_PAIRING_EVENT",
        b"secundario(s) promovido(s) a Player 2 virtual",
    ):
        check(marker in data,
              "DLL: marcador %r do TICKET-171 ausente" % marker)
    check(b"demais controles -> NAO-ASSIGNADOS" not in data,
          "DLL: marcador legado 'demais -> NAO-ASSIGNADOS' ainda presente")
    check(b"demais controles -> Player 2 (indice 1)" not in data,
          "DLL: marcador legado 'demais -> indice 1' ainda presente")
    # XUID base e um imediato de 64 bits (2533274790395904 <=> 0x9000000000000),
    # nao uma string decimal: o XUID e formatado em runtime por u64_to_dec.
    check(struct.pack("<Q", 2533274790395904) in data,
          "DLL: imediato do XUID base (0x9000000000000) ausente")

    # ---- TICKET-HARNESS-169: args COM do ControllerPairingChanged ---------
    # O evento deixa de reutilizar o `sender` como args: a DLL embute o objeto
    # sintetizado (vtable de 13 slots, IIDs de IUnknown/IInspectable e log do
    # args/hresult). Se o artefato foi gerado sem o ticket, os literais nao
    # existem.
    check(b"ControllerPairingChanged args=%p user=%p previous_user=%p "
          b"controller=%p" in data,
          "DLL: marcador de log do args de ControllerPairingChanged ausente")
    check(b"hr=0x%08lx (user=%p previous_user=%p)" in data,
          "DLL: log do HRESULT por handler com user/previous_user ausente")
    check(bytes.fromhex("e0e286af2db16a4c9c5ad7aa65101e90") in data,
          "DLL: IID IInspectable (AF86E2E0-...) ausente do artefato")
    check(bytes.fromhex("0000000000000000c000000000000046") in data,
          "DLL: IID IUnknown (00000000-0000-0000-C000-000000000046) ausente")
    check(b"sem canal de usuario, " in data,
          "DLL: marcador do disparo para controles sem canal ausente")
    check(b"disparado para o Player 2" in data,
          "DLL: marcador do disparo de pareamento do Player 2 ausente")

    # ---- TICKET-HARNESS-167: once-loader serializado (race do dinput8) -----
    # Literais introduzidos exclusivamente por este ticket: comprovam que o
    # artefato carrega a carga serializada (SRWLOCK) e os logs por tid,
    # nunca a implementação antiga que devolvia NULL transitório.
    check(b"[dinput8_proxy] resolve_real: loaded %s -> %p (tid=%lu)" in data,
          "DLL: marcador de log 'resolve_real: loaded' ausente")
    check(b"[dinput8_proxy] DirectInput8Create(tid=%lu) -> real=%p "
          b"hr=0x%08lx" in data,
          "DLL: marcador de log 'DirectInput8Create(tid=...)' ausente")

    # ---- Blindagem do carregamento de corrida (crash 0x140687f4c) --------
    # O artefato precisa carregar o hook do handler WindowActivated (RVA
    # 0x5d7500) e a guarda anti-NULL da fila de eventos (RVA 0x687f48), com os
    # marcadores de log que provam o caminho neutralizado e o rearme.
    for rva, name in (
        (0x5D7500, "WindowActivated handler"),
        (0x687F48, "EventQueue link write"),
    ):
        check(struct.pack("<I", rva) in data,
              "DLL: RVA 0x%05x (%s) ausente do artefato" % (rva, name))
    for marker in (
        b"handler WindowActivated neutralizado (S_OK sem EventQueue::PostEvent)",
        b"guarda NULL na fila de eventos",
        b"assinatura viva divergente do titulo",
        b"WindowActivated rearmado",
        b"executavel do titulo resolvido em",
        b"blindagem do carregamento pendente",
    ):
        check(marker in data,
              "DLL: marcador %r da blindagem do carregamento ausente" % marker)

    # ---- TICKET-HARNESS-170: frescor do artefato (build >= fontes) --------
    # A DLL e o artefato de RUNTIME: um binario gerado antes da ultima
    # alteracao de fonte não contém a correção de vtable/Controller* e o jogo
    # carregaria o comportamento antigo (crash ou P1 contra P1). A prova e
    # objetiva: mtime do artefato ESTRITAMENTE posterior ao fonte mais novo.
    newest = None
    for sub in ("src", "include"):
        d = os.path.join(REPO, "fm5-p2", sub)
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if not (name.endswith(".c") or name.endswith(".h")):
                continue
            path = os.path.join(d, name)
            mtime = os.path.getmtime(path)
            if newest is None or mtime > newest[0]:
                newest = (mtime, path)
    check(newest is not None, "DLL: nenhum fonte encontrado para o check de "
                              "frescor")
    if newest is not None:
        check(os.path.getmtime(DLL) > newest[0],
              "DLL DESATUALIZADA: fonte mais novo que o artefato (%s). "
              "Rode `make -C fm5-p2 dll install`."
              % os.path.relpath(newest[1], REPO))

    # A copia instalada ao lado do exe e a que o jogo carrega: precisa ser
    # BYTE-A-BYTE o mesmo artefato (senao dist e jogo divergem).
    installed = os.path.join(REPO, "dinput8.dll")
    if os.path.isfile(installed):
        def _sha256(path):
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()

        check(_sha256(installed) == _sha256(DLL),
              "dinput8.dll instalado ao lado do exe difere de "
              "dist/dinput8.dll (rode `make -C fm5-p2 install`)")

    if failures:
        print("FALHA: %d/%d verificacoes da DLL falharam" % (len(failures), checks))
        for f in failures:
            print("  - " + f)
        return 1
    print("OK: %d verificacoes do artefato dist/dinput8.dll passaram" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
