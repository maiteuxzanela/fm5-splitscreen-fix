/*
 * fm5_event_shield_encode.h — codificação pura da guarda anti-NULL da fila de
 * eventos do Azimuth (crash 0xC0000005 em rip=0x140687f4c).
 *
 * EVIDÊNCIA FORENSE (logs/steam-0.log, 2026-11-10, Azimuth 1.0.4):
 *
 *   23245.656:seh:dispatch_exception code=c0000005 (EXCEPTION_ACCESS_VIOLATION)
 *              addr=0000000140687F4C rip=0000000140687f4c rax=0000000000000000
 *              rcx=000004000001cc30
 *   140687f48: 48 8b 41 08   mov rax, QWORD PTR [rcx+0x8]   ; next
 *   140687f4c: 48 89 08      mov QWORD PTR [rax], rcx      ; *next = node
 *
 * `rax == 0` (o `next` do nó estava em reciclagem/transição de tela) e a
 * escrita em [rax] derrubou o processo. A guarda troca os 7 bytes da sequência
 * por um salto relativo de 5 bytes (E9 rel32) para uma caverna de código que
 * reemite a sequência com `test rax,rax; jz skip` antes da escrita.
 *
 * IMPORTANTE — por que não há assinatura estática no arquivo:
 *   A região 0x687e20..0x687f96 NÃO está em claro no `azimuth.exe` em disco:
 *   o build 1.0.4 entrega parte do .text decifrada apenas em memória (o unwind
 *   info observado em runtime para 0x687e20 não corresponde aos bytes do
 *   arquivo, e o próprio rip do crash cai em 0x687f4c). Por isso o instalador
 *   Windows valida os bytes VIVOS contra a constante abaixo e falha fechado
 *   (não patcheia) quando a região ainda não foi decifrada, rearmando nos
 *   frames seguintes (o hook de GamepadReading é chamado em alta frequência).
 *
 * Este header é portátil (só <stdint.h>/<string.h>) e é exercitado de verdade
 * pelos testes nativos Linux: eles montam a caverna em memória executável e
 * EXECUTAM a sequência, provando que a escrita em NULL deixa de acontecer.
 */
#ifndef FM5_EVENT_SHIELD_ENCODE_H
#define FM5_EVENT_SHIELD_ENCODE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* RVA do início da sequência (VA 0x140687f48 no build 1.0.4). */
#define FM5_SHIELD_RVA        0x687F48u
/* Primeira instrução APÓS a sequência (fronteira de instrução real): ponto de
 * retomada do salto de volta da caverna. */
#define FM5_SHIELD_RESUME_RVA 0x687F4Fu

#define FM5_SHIELD_ORIG_LEN   7u   /* 4 (mov rax,[rcx+8]) + 3 (mov [rax],rcx) */
#define FM5_SHIELD_PATCH_LEN  5u   /* E9 rel32                                     */

/* Sequência original byte-a-byte (crash 0x140687f4c). */
#define FM5_SHIELD_ORIG_BYTES 0x48, 0x8B, 0x41, 0x08, 0x48, 0x89, 0x08

/*
 * Opcodes da caverna (14 bytes) antes da cauda `jmp [rip+0]` + retomada:
 *
 *   48 8B 41 08   mov  rax, [rcx+8]     ; nó seguinte
 *   9C            pushfq                ; preserve EFLAGS do chamador
 *   48 85 C0      test rax, rax
 *   74 03         jz   +3               ; rax == NULL -> pula a escrita
 *   48 89 08      mov  [rax], rcx       ; caminho original
 *   9D            popfq                 ; devolve EFLAGS ao código seguinte
 *
 * O `pushfq/popfq` mantém as flags intactas: a sequência original não altera
 * EFLAGS (apenas MOVs) e o código em 0x687f4f pode depender delas.
 */
#define FM5_SHIELD_CAVE_OPCODES 0x48, 0x8B, 0x41, 0x08, 0x9C, 0x48, 0x85, 0xC0, 0x74, 0x03, 0x48, 0x89, 0x08, 0x9D

#define FM5_SHIELD_CAVE_OPCODES_LEN 14u
/* 14 (opcodes) + 14 (jmp absoluto indireto rip-relative + alvo u64). */
#define FM5_SHIELD_CAVE_LEN \
    (FM5_SHIELD_CAVE_OPCODES_LEN + 14u) /* = 28 */

/* Bytes originais esperados (constante forense). Nunca NULL. */
static inline const uint8_t *fm5_shield_original(void)
{
    static const uint8_t orig[FM5_SHIELD_ORIG_LEN] = { FM5_SHIELD_ORIG_BYTES };
    return orig;
}

/* 1 se os 7 bytes vivos casam com a sequência do crash (fail-closed). */
static inline int fm5_shield_is_original(const uint8_t *bytes)
{
    return (bytes != NULL) &&
           (memcmp(bytes, fm5_shield_original(), FM5_SHIELD_ORIG_LEN) == 0);
}

/*
 * Monta a caverna em `dst` (cap >= FM5_SHIELD_CAVE_LEN) e devolve o tamanho
 * escrito, ou 0 em erro de capacidade/argumento. A cauda salta de volta para
 * `resume_addr` (no jogo: base + FM5_SHIELD_RESUME_RVA) sem clobber de
 * registradores de uso geral (`jmp qword ptr [rip+0]`).
 */
static inline size_t fm5_shield_encode_cave(uint8_t *dst, size_t cap,
                                            uint64_t resume_addr)
{
    static const uint8_t ops[FM5_SHIELD_CAVE_OPCODES_LEN] = {
        FM5_SHIELD_CAVE_OPCODES
    };
    size_t i;

    if (dst == NULL || cap < FM5_SHIELD_CAVE_LEN) {
        return 0;
    }
    for (i = 0; i < FM5_SHIELD_CAVE_OPCODES_LEN; i++) {
        dst[i] = ops[i];
    }
    /* Cauda: ff 25 00 00 00 00 | <resume_addr: u64 LE>. */
    dst[14] = 0xFF;
    dst[15] = 0x25;
    dst[16] = 0x00;
    dst[17] = 0x00;
    dst[18] = 0x00;
    dst[19] = 0x00;
    for (i = 0; i < 8; i++) {
        dst[20 + i] = (uint8_t)((resume_addr >> (8u * i)) & 0xFFu);
    }
    return FM5_SHIELD_CAVE_LEN;
}

/*
 * Codifica o salto de entrada `E9 rel32` em `dst` (5 bytes) do endereço
 * `target_addr` para `cave_addr`. Retorna 0 em sucesso e -1 quando o destino
 * está fora do alcance de ±2 GiB (fail-closed: o alvo NÃO deve ser tocado).
 */
static inline int fm5_shield_encode_jump(uint8_t *dst, uint64_t target_addr,
                                         uint64_t cave_addr)
{
    int64_t disp;
    uint64_t u;
    int i;

    if (dst == NULL) {
        return -1;
    }
    disp = (int64_t)cave_addr - (int64_t)(target_addr + FM5_SHIELD_PATCH_LEN);
    if (disp < (int64_t)INT32_MIN || disp > (int64_t)INT32_MAX) {
        return -1;
    }
    u = (uint64_t)disp & 0xFFFFFFFFu;
    dst[0] = 0xE9;
    for (i = 0; i < 4; i++) {
        dst[1 + i] = (uint8_t)((u >> (8u * i)) & 0xFFu);
    }
    return 0;
}

#endif /* FM5_EVENT_SHIELD_ENCODE_H */
