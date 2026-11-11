/*
 * fm5_visibility_shield.h — blindagem da Visibility Thread do título.
 *
 * Instala (Windows-only) a blindagem em quatro camadas sobre o
 * vector::insert do executável do TÍTULO (crashes 0xC0000005 em
 * rip=0x1408595e0 e rip=0x14085b77a):
 *
 *   [1] RVA 0x859516: `0f 83 8d 00 00 00` (JAE unsigned) -> `0f 8d ...`
 *       (JGE signed). Count negativo (where > _Mylast, vetor saturado em
 *       split-screen) passa a cair no caminho de inserção no fim.
 *
 *   [2] RVA 0x859500: E9 rel32 para uma caverna que reemite o prologue e,
 *       se where > _Mylast, trava as TRÊS cópias de where (r8, rbp e o
 *       spill [rsp+0x90]) em _Mylast e zera o count — protege o laço de
 *       cópia para trás mesmo se o mapeador reescrever o opcode [1].
 *
 *   [3] RVA 0x85b770: store atômico de 16 bits no word par 0x85b772 troca
 *       `74 26` (JE) por `73 26` (JAE) no helper de cópia — com
 *       where > _Mylast a cópia termina imediatamente em vez de varrer
 *       memória para a frente (crash rip=0x14085b77a).
 *
 *   [4] RVA 0x8580e0: E9 rel32 para uma caverna que reemite
 *       `mov r8,r11` + `mov [rsp+0x20],rax` e clampa where em _Mylast
 *       (global 0x24717d8) ANTES do call 0x8580e8 — a fonte do insert
 *       nunca observa where > _Mylast.
 *
 * Idempotente e fail-closed: enquanto os bytes vivos não casarem com as
 * sequências forenses do build 1.0.0.20, nada é escrito no jogo; o chamador
 * pode tentar de novo (rearme) nos frames seguintes. As camadas [2]/[3]/[4]
 * são melhor esforço: a falha de qualquer uma nunca invalida as demais.
 */
#ifndef FM5_VISIBILITY_SHIELD_H
#define FM5_VISIBILITY_SHIELD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Tenta instalar a blindagem em `base` (base do executável do título).
 * Retorna:
 *   1  -> já estava instalada e íntegra (idempotente)
 *   0  -> instalada agora
 *  -1  -> argumento inválido
 *  -2  -> bytes vivos divergem da assinatura forense (fail-closed)
 *  -6  -> falha de VirtualProtect no branch (nada escrito)
 *
 * Falha das camadas [2]/[3]/[4] (cavernas/helper) NÃO invalida a
 * instalação: a camada [1] sozinha fecha o crash. Consulte
 * fm5_visibility_shield_guard_active().
 */
int fm5_visibility_shield_install(uint8_t *base);

/* Restaura os bytes originais (branch + trava + helper + fonte) e libera as
 * cavernas (unload). Os E9 são restaurados ANTES de liberar as cavernas. */
void fm5_visibility_shield_uninstall(uint8_t *base);

/* 1 se a blindagem [1] está ativa. */
int fm5_visibility_shield_active(void);

/* 1 se a blindagem [1] está ativa, os bytes vivos são `jge` e — quando cada
 * camada [2]/[3]/[4] está ativa — o E9 da [2] resolve para a NOSSA caverna,
 * o helper está com `73` (JAE) e o E9 da [4] resolve para a NOSSA caverna. */
int fm5_visibility_shield_intact(void);

/* 1 se a camada [2] (trava de where/_Mylast) está publicada. */
int fm5_visibility_shield_guard_active(void);

#ifdef __cplusplus
}
#endif

#endif /* FM5_VISIBILITY_SHIELD_H */
