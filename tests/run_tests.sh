#!/usr/bin/env bash
# run_tests.sh — suíte determinística do card Player 2 / Split-Screen.
#
# Roda, sem mocks e sem rede:
#   1. testes nativos reais do núcleo de identidade (gcc + pthread);
#   2. teste multithread do carregamento único (race do DirectInput8Create);
#   3. validação byte-a-byte do binário alvo azimuth.exe 1.0.4;
#   4. validação do artefato dist/dinput8.dll (SKIP se mingw ausente);
#   5. contrato de fiação da camada Windows-only (fm5_hooks.c);
#   6. prova de sensibilidade por mutação isolada (TICKET-HARNESS-168);
#   7. guarda anti-NULL da fila de eventos, executada de verdade (crash
#      EXCEPTION_ACCESS_VIOLATION em rip 0x140687f4c);
#   8. blindagem da Visibility Thread do titulo (crash EXCEPTION_ACCESS_VIOLATION
#      em rip 0x1408595e0, Thread 0344): ancora forense no executavel do titulo,
#      execucao real da caverna where/_Mylast e controle negativo do laco de
#      copia para tras (SIGSEGV sem a blindagem).
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "$HERE/.." && pwd -P)"
cd "$ROOT"

MAKE_DIR="."
if [ -d "$ROOT/fm5-p2" ]; then
    MAKE_DIR="$ROOT/fm5-p2"
fi

echo "== 1/8 nucleo de identidade + matematica de patch (nativo) =="
make -C "$MAKE_DIR" test

echo "== 2/8 carregamento unico multithread (fm5_once_loader, TICKET-HARNESS-167) =="
make -C "$MAKE_DIR" test-once

echo "== 3/8 binario alvo (azimuth.exe 1.0.4) =="
python3 tests/test_pe_targets.py

echo "== 4/8 artefato dinput8.dll =="
python3 tests/test_dll_artifact.py

echo "== 5/8 contrato de fiacao dos hooks (TICKET-HARNESS-168) =="
python3 tests/test_fm5_hooks_contract.py

echo "== 6/8 sensibilidade por mutacao isolada (TICKET-HARNESS-168) =="
python3 tests/test_mutation_sensitivity.py

echo "== 7/8 guarda anti-NULL da fila de eventos (execucao real, crash 0x140687f4c) =="
make -C "$MAKE_DIR" test-shield

echo "== 8/8 blindagem da Visibility Thread (execucao real, crash 0x1408595e0) =="
make -C "$MAKE_DIR" test-visibility

echo "ALL GREEN"
