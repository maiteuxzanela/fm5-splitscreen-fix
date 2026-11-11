/*
 * fm5_patch_bytes.h — codificação pura de bytes de patch x86-64.
 *
 * Isolado de <windows.h> para poder ser exercitado por testes nativos no host
 * Linux. É a MESMA implementação usada por fm5_detour.c na DLL Windows.
 */
#ifndef FM5_PATCH_BYTES_H
#define FM5_PATCH_BYTES_H

#include <stddef.h>
#include <stdint.h>

#define FM5_ABS_JMP_LEN 14
/* Salto absoluto indireto rip-relative: NAO clobbera nenhum registrador de
 * uso geral (o antigo `mov rax, imm64; jmp rax` destruia %rax e quebrava o
 * retorno de trampolins que interrompem uma sequencia `call; mov 0x18(%rax)`,
 * como Controller::get_User em 0x14019a4c0). */
#define FM5_TAIL_LEN    FM5_ABS_JMP_LEN

static inline void fm5_encode_abs_jmp(uint8_t *dst, uint64_t target_addr)
{
    int i;
    dst[0] = 0xFF;
    dst[1] = 0x25;
    dst[2] = 0x00;
    dst[3] = 0x00;
    dst[4] = 0x00;
    dst[5] = 0x00;
    for (i = 0; i < 8; i++) {
        dst[6 + i] = (uint8_t)((target_addr >> (8 * i)) & 0xFFu);
    }
}

/* Cauda do trampolim: `jmp qword ptr [rip+0]` seguido do endereco absoluto de
 * retorno (14 bytes). Preserva integralmente %rax e todos os demais registradores
 * de uso geral, exatamente como um salto de verdade. */
static inline void fm5_encode_tail(uint8_t *dst, uint64_t resume_addr)
{
    fm5_encode_abs_jmp(dst, resume_addr);
}

static inline void fm5_fill_nops(uint8_t *dst, size_t from, size_t to)
{
    size_t i;
    for (i = from; i < to; i++) {
        dst[i] = 0x90;
    }
}

static inline int32_t fm5_read_rel32(const uint8_t *p)
{
    uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return (int32_t)v;
}

static inline void fm5_write_rel32(uint8_t *p, int32_t v)
{
    uint32_t u = (uint32_t)v;
    p[0] = (uint8_t)(u & 0xFFu);
    p[1] = (uint8_t)((u >> 8) & 0xFFu);
    p[2] = (uint8_t)((u >> 16) & 0xFFu);
    p[3] = (uint8_t)((u >> 24) & 0xFFu);
}

/*
 * Recalcula o deslocamento rel32 de uma instrução E8/E9 copiada para o
 * trampolim, de modo que ela continue mirando o MESMO destino absoluto.
 *
 *   src          bytes copiados (início do trecho original)
 *   patch_len    quantidade de bytes copiada
 *   rel32_off    offset do opcode E8/E9 dentro do trecho (-1 = nenhum)
 *   src_start    endereço absoluto original do trecho
 *   dst_start    endereço absoluto do trampolim
 *
 * Retorna: 0 = não aplicável; 1 = ok (*out preenchido); -1 = destino fora do
 * alcance de 32 bits (o chamador DEVE abortar o hook: fail-closed).
 */
static inline int fm5_relocate_rel32_checked(const uint8_t *src,
                                             size_t patch_len, int rel32_off,
                                             uint64_t src_start,
                                             uint64_t dst_start,
                                             int32_t *out)
{
    int32_t old_disp;
    int64_t orig_target;
    int64_t dst_next;
    int64_t disp;
    if (rel32_off < 0 || (size_t)(rel32_off + 5) > patch_len) {
        return 0;
    }
    old_disp = fm5_read_rel32(src + rel32_off + 1);
    orig_target = (int64_t)src_start + (int64_t)(rel32_off + 5) +
                  (int64_t)old_disp;
    dst_next = (int64_t)dst_start + (int64_t)(rel32_off + 5);
    disp = orig_target - dst_next;
    if (disp < (int64_t)INT32_MIN || disp > (int64_t)INT32_MAX) {
        return -1;
    }
    *out = (int32_t)disp;
    return 1;
}

/* Variante sem verificação de alcance (uso interno/teste). */
static inline int32_t fm5_relocate_rel32(const uint8_t *src, size_t patch_len,
                                         int rel32_off, uint64_t src_start,
                                         uint64_t dst_start)
{
    int32_t v = 0;
    (void)fm5_relocate_rel32_checked(src, patch_len, rel32_off, src_start,
                                     dst_start, &v);
    return v;
}

#endif /* FM5_PATCH_BYTES_H */
