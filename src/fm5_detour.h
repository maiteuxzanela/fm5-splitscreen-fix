/*
 * fm5_detour.h — motor de detour x86-64 mínimo para os hooks do Azimuth.
 *
 * Estratégia: sobrescreve os primeiros `patch_len` bytes do alvo com um salto
 * absoluto de 14 bytes (`jmp qword ptr [rip+0]`) para o nosso handler. Os bytes
 * originais são copiados para um trampolim executável; se o trecho copiado
 * contiver uma chamada/salto rel32 (E8/E9), o deslocamento é recalculado no
 * trampolim. O trampolim termina com `jmp qword ptr [rip+0]` + endereço
 * absoluto de volta ao endereço `alvo + patch_len` — salto indireto que NÃO
 * clobbera nenhum registrador de uso geral (preserva %rax e o resultado de um
 * `call` que termine exatamente no fim do trecho copiado).
 *
 * Nada aqui depende de um desassemblador em tempo de execução: os alvos e
 * comprimentos são fixos e verificados por assinatura de bytes (fail-closed).
 */
#ifndef FM5_DETOUR_H
#define FM5_DETOUR_H

#include <stddef.h>
#include <stdint.h>

typedef struct fm5_hook {
    void         *target;        /* endereço absoluto do alvo */
    size_t        patch_len;     /* bytes sobrescritos (>= 14, <= 32) */
    const uint8_t *expect;       /* assinatura esperada dos bytes originais */
    size_t        expect_len;    /* tamanho da assinatura */
    int           rel32_offset;  /* offset do E8/E9 dentro do trecho, ou -1 */
    void         *hook_fn;       /* handler substituto */
    void         *trampoline;    /* preenchido por fm5_hook_install */
    uint8_t       saved[32];     /* bytes originais preservados */
    int           installed;
} fm5_hook_t;

/* Instala o hook. Retorna 0 em sucesso; <0 em falha (assinatura divergente,
 * memória, proteção). Em falha o alvo permanece intacto. */
int fm5_hook_install(fm5_hook_t *hook);

/* Remove o hook e restaura os bytes originais. */
void fm5_hook_uninstall(fm5_hook_t *hook);

#endif /* FM5_DETOUR_H */
