# Makefile — Player 2 / Split-Screen do Azimuth (Forza Motorsport 5)
#
# Alvos:
#   make test    -> compila e roda os testes nativos reais (gcc/pthread)
#   make pe      -> valida o binário alvo (azimuth.exe 1.0.4) em Python
#   make dll     -> compila dist/dinput8.dll (requer mingw-w64)
#   make all     -> test + pe + dll
#   make clean
#
# Sem mingw-w64 instalado, `make dll` explica e sai com código 0 (SKIP) para
# não mascarar os testes nativos, mas imprime um aviso destacado.

CC      ?= gcc
MINGW   ?= x86_64-w64-mingw32-gcc
PYTHON  ?= python3
# Fallback de cross-compile quando o mingw-w64 nao esta instalado: zig cc
# (bundle de headers/libs mingw-w64). Aceita tanto `zig` quanto `python-zig`.
ZIGCC   ?= $(shell command -v zig >/dev/null 2>&1 && echo 'zig cc -target x86_64-windows-gnu' || { command -v python-zig >/dev/null 2>&1 && echo 'python-zig cc -target x86_64-windows-gnu'; })

CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Werror
INC      = -Iinclude
TESTDIR  ?= $(shell [ -d tests ] && echo tests || echo ../tests)
BUILD    = $(TESTDIR)/build

CORE_SRC = src/fm5_identity.c

DLL_SRC  = src/dinput8_proxy.c src/fm5_hooks.c src/fm5_detour.c src/fm5_identity.c src/fm5_pairing.c src/fm5_systemui.c src/fm5_event_shield.c src/fm5_visibility_shield.c
DLL_DEF  = src/dinput8.def
DLL_OUT  = dist/dinput8.dll
DLL_CFLAGS = -shared -O2 -Wall -Wextra -Wno-unused-parameter \
             -Wno-cast-function-type -DWIN32_LEAN_AND_MEAN \
             -D_WIN32_WINNT=0x0601 $(INC)
DLL_LDFLAGS_MINGW = -static-libgcc -Wl,--enable-stdcall-fixup
DLL_LDFLAGS_ZIG   = -Wno-macro-redefined

.PHONY: all test test-once test-shield test-visibility pe artifact dll install clean

all: test pe dll artifact

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/test_fm5_identity: $(TESTDIR)/test_fm5_identity.c $(CORE_SRC) include/fm5_identity.h | $(BUILD)
	$(CC) $(CFLAGS) -pthread $(INC) -o $@ $(TESTDIR)/test_fm5_identity.c $(CORE_SRC)

$(BUILD)/test_fm5_contract: $(TESTDIR)/test_fm5_contract.c $(CORE_SRC) include/fm5_identity.h | $(BUILD)
	$(CC) $(CFLAGS) -pthread $(INC) -o $@ $(TESTDIR)/test_fm5_contract.c $(CORE_SRC)

$(BUILD)/test_fm5_patch_bytes: $(TESTDIR)/test_fm5_patch_bytes.c src/fm5_patch_bytes.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -Isrc -o $@ $(TESTDIR)/test_fm5_patch_bytes.c

$(BUILD)/test_fm5_native_user: $(TESTDIR)/test_fm5_native_user.c src/fm5_native_user.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -Isrc -o $@ $(TESTDIR)/test_fm5_native_user.c

$(BUILD)/test_fm5_buttons: $(TESTDIR)/test_fm5_buttons.c src/fm5_buttons.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -Isrc -o $@ $(TESTDIR)/test_fm5_buttons.c

# TICKET-HARNESS-165: bridge sintetizada Windows.Xbox.UI.SystemUI.
$(BUILD)/test_fm5_systemui: $(TESTDIR)/test_fm5_systemui.c src/fm5_systemui.c include/fm5_systemui.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -Isrc -o $@ $(TESTDIR)/test_fm5_systemui.c src/fm5_systemui.c

# TICKET-HARNESS-169: objeto COM IControllerPairingChangedEventArgs (args do
# evento de pareamento) + snapshot dos controles rebaixados.
$(BUILD)/test_fm5_pairing: $(TESTDIR)/test_fm5_pairing.c src/fm5_pairing.c src/fm5_identity.c include/fm5_pairing.h include/fm5_identity.h | $(BUILD)
	$(CC) $(CFLAGS) -pthread $(INC) -o $@ $(TESTDIR)/test_fm5_pairing.c src/fm5_pairing.c src/fm5_identity.c

# TICKET-HARNESS-167: carregamento único serializado (race do DirectInput8Create).
$(BUILD)/test_fm5_once_loader: $(TESTDIR)/test_fm5_once_loader.c src/fm5_once_loader.h | $(BUILD)
	$(CC) $(CFLAGS) -pthread -Iinclude -Isrc -o $@ $(TESTDIR)/test_fm5_once_loader.c

# Blindagem do carregamento de corrida (crash 0xC0000005 em 0x140687f4c):
# a caverna anti-NULL é montada e EXECUTADA de verdade no host Linux.
$(BUILD)/test_fm5_event_shield: $(TESTDIR)/test_fm5_event_shield.c src/fm5_event_shield_encode.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -Isrc -o $@ $(TESTDIR)/test_fm5_event_shield.c

# Blindagem da Visibility Thread (crash 0xC0000005 em 0x1408595e0, Thread 0344):
# ancora forense no executável do título + execução real da caverna de trava
# (where/_Mylast) e controle negativo do laço de cópia para trás (SIGSEGV).
$(BUILD)/test_fm5_visibility_shield: $(TESTDIR)/test_fm5_visibility_shield.c src/fm5_visibility_shield_encode.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude -Isrc -o $@ $(TESTDIR)/test_fm5_visibility_shield.c

test: $(BUILD)/test_fm5_identity $(BUILD)/test_fm5_contract $(BUILD)/test_fm5_patch_bytes $(BUILD)/test_fm5_native_user $(BUILD)/test_fm5_buttons $(BUILD)/test_fm5_systemui $(BUILD)/test_fm5_once_loader $(BUILD)/test_fm5_pairing $(BUILD)/test_fm5_event_shield $(BUILD)/test_fm5_visibility_shield
	@echo "== test_fm5_identity =="
	@$(BUILD)/test_fm5_identity
	@echo "== test_fm5_contract =="
	@$(BUILD)/test_fm5_contract
	@echo "== test_fm5_patch_bytes =="
	@$(BUILD)/test_fm5_patch_bytes
	@echo "== test_fm5_native_user =="
	@$(BUILD)/test_fm5_native_user
	@echo "== test_fm5_buttons =="
	@$(BUILD)/test_fm5_buttons
	@echo "== test_fm5_systemui =="
	@$(BUILD)/test_fm5_systemui
	@echo "== test_fm5_once_loader =="
	@$(BUILD)/test_fm5_once_loader
	@echo "== test_fm5_pairing (TICKET-HARNESS-169) =="
	@$(BUILD)/test_fm5_pairing
	@echo "== test_fm5_event_shield (crash 0x140687f4c) =="
	@$(BUILD)/test_fm5_event_shield
	@echo "== test_fm5_visibility_shield (crash 0x1408595e0) =="
	@$(BUILD)/test_fm5_visibility_shield

test-once: $(BUILD)/test_fm5_once_loader
	@$(BUILD)/test_fm5_once_loader

test-shield: $(BUILD)/test_fm5_event_shield
	@$(BUILD)/test_fm5_event_shield

test-visibility: $(BUILD)/test_fm5_visibility_shield
	@$(BUILD)/test_fm5_visibility_shield

pe:
	@$(PYTHON) $(TESTDIR)/test_pe_targets.py

artifact:
	@$(PYTHON) $(TESTDIR)/test_dll_artifact.py

dll:
	@if command -v $(MINGW) >/dev/null 2>&1; then \
		mkdir -p dist; \
		echo "Compilando $(DLL_OUT) com $(MINGW)..."; \
		$(MINGW) $(DLL_CFLAGS) $(DLL_LDFLAGS_MINGW) -o $(DLL_OUT) \
			$(DLL_SRC) $(DLL_DEF) \
		&& echo "OK: $(DLL_OUT) gerado." \
		|| { echo "FALHA: compilacao da DLL falhou."; exit 1; }; \
	elif [ -n "$(ZIGCC)" ]; then \
		mkdir -p dist; \
		echo "Compilando $(DLL_OUT) com $(ZIGCC) (mingw-w64 ausente)..."; \
		$(ZIGCC) $(DLL_CFLAGS) $(DLL_LDFLAGS_ZIG) -o $(DLL_OUT) \
			$(DLL_SRC) $(DLL_DEF) \
		&& echo "OK: $(DLL_OUT) gerado." \
		|| { echo "FALHA: compilacao da DLL falhou."; exit 1; }; \
	else \
		echo "SKIP: $(MINGW) e zig cc nao encontrados. Instale mingw-w64 ou zig para gerar $(DLL_OUT)."; \
		echo "      Os testes nativos (make test) e a validacao do binario (make pe) rodam sem eles."; \
		exit 0; \
	fi

install:
	@if [ ! -f $(DLL_OUT) ]; then \
		echo "FALHA: $(DLL_OUT) ausente; rode 'make dll' antes de instalar."; \
		exit 1; \
	fi
	cp -f $(DLL_OUT) ../dinput8.dll
	@echo "OK: $(DLL_OUT) instalado em ../dinput8.dll"

clean:
	rm -rf $(BUILD) dist
