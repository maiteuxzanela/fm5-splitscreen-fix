/*
 * fm5_event_shield.h — guarda anti-NULL da fila de eventos do Azimuth.
 *
 * Instala (Windows-only) um salto relativo na sequência
 *   0x140687f48: mov rax,[rcx+8]
 *   0x140687f4c: mov [rax],rcx      <-- escrita em 0x0 quando rax == NULL
 * para uma caverna que só executa a escrita quando `rax` é válido.
 *
 * Idempotente e fail-closed: enquanto os bytes vivos não casarem com a
 * sequência do crash, nada é escrito no jogo; o chamador pode tentar de novo
 * (rearme) nos frames seguintes.
 */
#ifndef FM5_EVENT_SHIELD_H
#define FM5_EVENT_SHIELD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Tenta instalar a guarda em `base` (GetModuleHandleA(NULL)).
 * Retorna:
 *   1  -> já estava instalada (idempotente)
 *   0  -> instalada agora
 *  -1  -> argumento inválido
 *  -2  -> bytes vivos divergem da assinatura forense (fail-closed)
 *  -3  -> falha de alocação da caverna
 *  -4  -> falha ao codificar a caverna
 *  -5  -> caverna fora do alcance de ±2 GiB (fail-closed)
 *  -6  -> falha de VirtualProtect (nada escrito)
 */
int fm5_event_shield_install(uint8_t *base);

/* Restaura os 7 bytes originais e libera a caverna (unload). */
void fm5_event_shield_uninstall(uint8_t *base);

/* 1 se a guarda está ativa. */
int fm5_event_shield_active(void);

/* 1 se a guarda está ativa E o E9 publicado ainda resolve para a nossa
 * caverna (re-detecção barata de sobrescrita pelo mapeador/decifrador). */
int fm5_event_shield_intact(void);

#ifdef __cplusplus
}
#endif

#endif /* FM5_EVENT_SHIELD_H */
