/*
 * fm5_hooks.h — camada Windows de hook do Azimuth (Player 2 / split-screen).
 */
#ifndef FM5_HOOKS_H
#define FM5_HOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Instala os hooks WinRT no processo atual (azimuth.exe). Idempotente.
 * Fail-closed: se a assinatura de bytes de um alvo divergir do build 1.0.4,
 * aquele hook é ignorado e o jogo continua intacto. */
void fm5_hooks_init(void);

/* Remove os hooks instalados (usado no unload/teste). */
void fm5_hooks_shutdown(void);

/* 1 se a inicialização já ocorreu. */
int fm5_hooks_ready(void);

#ifdef __cplusplus
}
#endif

#endif /* FM5_HOOKS_H */
