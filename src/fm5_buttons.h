/*
 * fm5_buttons.h — recomposição portátil do bitmask GamepadButtons do Azimuth.
 *
 * Contexto de engenharia reversa (azimuth.exe 1.0.4, RVA 0x4b0c40 / 0x4b0ca1):
 *
 *   mov  0xf(%rbp), %eax      ; dword Windows.Gaming.Input.GamepadButtons
 *   and  $0x3fff, %eax        ; mantém os 14 bits baixos
 *   shl  $0x2, %eax           ; desloca TUDO dois bits à esquerda
 *   mov  %eax, 0x8(%rbx)      ; GamepadReading.Buttons
 *
 * TICKET-HARNESS-166 — o enum de ENTRADA é Windows.Gaming.Input.GamepadButtons
 * (Menu=0x0001, View=0x0002, A=0x0004, B=0x0008, X=0x0010, Y=0x0020,
 * DPadUp=0x0040, DPadDown=0x0080, DPadLeft=0x0100, DPadRight=0x0200,
 * LeftShoulder=0x0400, RightShoulder=0x0800, LeftThumbstick=0x1000,
 * RightThumbstick=0x2000) e o `shl $2` converte para o enum
 * Windows.Xbox.Input.GamepadButtons da geração Xbox One — que é o enum
 * CONSUMIDO pelo Forza Motorsport 5. O `shl` NÃO é um bug: ele apenas
 * reposiciona os 14 bits no layout que o jogo espera. Por isso:
 *
 *   - com `swap_start_back == 0`, fm5_buttons_recompose é PASS-THROUGH PURO:
 *     devolve `azimuth_buttons` 100% intacto (nenhum bit é apagado!);
 *   - com `swap_start_back != 0`, APENAS os bits Menu (0x0004) e View (0x0008)
 *     são permutados. Todo o resto — A/B/X/Y, o D-Pad inteiro
 *     (DPadUp 0x0100, DPadDown 0x0200, DPadLeft 0x0400, DPadRight 0x0800),
 *     ombros e analógicos — permanece 100% intacto.
 *
 * TICKET-HARNESS-166 — regressão corrigida: as versões 162/164 tratavam
 * 0x0100/0x0200 como Back/Start e os APAGAVAM. No enum real do Xbox One esses
 * bits são DPadUp e DPadDown: consumi-los destruía as setas verticais do
 * D-pad. Nenhum bit de D-Pad é tocado por este módulo.
 *
 * Este módulo é PURO (sem Windows) para ser exercitado pelos testes nativos e
 * é a MESMA unidade usada pela DLL (fm5_hooks.c) em produção.
 */
#ifndef FM5_BUTTONS_H
#define FM5_BUTTONS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Windows.Xbox.Input.GamepadButtons (enum Xbox One ERA) — valor JÁ no layout
 * que o Azimuth entrega em GamepadReading.Buttons (entrada << 2).
 */
#define FM5_GB_MENU             0x0004u  /* Start */
#define FM5_GB_VIEW             0x0008u  /* Back  */
#define FM5_GB_A                0x0010u
#define FM5_GB_B                0x0020u
#define FM5_GB_X                0x0040u
#define FM5_GB_Y                0x0080u
#define FM5_GB_DPAD_UP          0x0100u
#define FM5_GB_DPAD_DOWN        0x0200u
#define FM5_GB_DPAD_LEFT        0x0400u
#define FM5_GB_DPAD_RIGHT       0x0800u
#define FM5_GB_LEFT_SHOULDER    0x1000u
#define FM5_GB_RIGHT_SHOULDER   0x2000u
#define FM5_GB_LEFT_THUMBSTICK  0x4000u
#define FM5_GB_RIGHT_THUMBSTICK 0x8000u

/*
 * Windows.Gaming.Input.GamepadButtons (enum de ENTRADA do Azimuth, antes do
 * `shl $2`). Exposto para os testes provarem a equivalência com o binário.
 */
#define FM5_WGI_MENU             0x0001u  /* Start */
#define FM5_WGI_VIEW             0x0002u  /* Back  */
#define FM5_WGI_A                0x0004u
#define FM5_WGI_B                0x0008u
#define FM5_WGI_X                0x0010u
#define FM5_WGI_Y                0x0020u
#define FM5_WGI_DPAD_UP          0x0040u
#define FM5_WGI_DPAD_DOWN        0x0080u
#define FM5_WGI_DPAD_LEFT        0x0100u
#define FM5_WGI_DPAD_RIGHT       0x0200u
#define FM5_WGI_LEFT_SHOULDER    0x0400u
#define FM5_WGI_RIGHT_SHOULDER   0x0800u
#define FM5_WGI_LEFT_THUMBSTICK  0x1000u
#define FM5_WGI_RIGHT_THUMBSTICK 0x2000u

/* Máscara aplicada pelo Azimuth antes do shift (14 bits). */
#define FM5_AZIMUTH_BUTTON_MASK 0x3fffu

/* Bits de sistema no enum de saída (Xbox One ERA). */
#define FM5_GB_SYSTEM_MASK      (FM5_GB_MENU | FM5_GB_VIEW)

/*
 * Reproduz exatamente a saída do Azimuth 1.0.4 para um estado
 * Windows.Gaming.Input.GamepadButtons:
 *   azimuth_buttons = (gaming_buttons & 0x3fff) << 2
 * Útil para os testes provarem a equivalência com o binário.
 */
static inline uint32_t fm5_buttons_azimuth_shift(uint32_t gaming_buttons)
{
    return (gaming_buttons & FM5_AZIMUTH_BUTTON_MASK) << 2;
}

/* 1 se a leitura (já no enum Xbox One ERA) contém Start/Menu (0x0004). */
static inline int fm5_buttons_start_pressed(uint32_t azimuth_buttons)
{
    return (azimuth_buttons & FM5_GB_MENU) != 0;
}

/* 1 se a leitura (já no enum Xbox One ERA) contém Back/View (0x0008). */
static inline int fm5_buttons_back_pressed(uint32_t azimuth_buttons)
{
    return (azimuth_buttons & FM5_GB_VIEW) != 0;
}

/*
 * Recompoõe o campo Buttons a partir do valor JÁ deslocado pelo Azimuth.
 *
 * TICKET-HARNESS-166 — NÃO DESTRUTIVA:
 *   - swap_start_back == 0 -> PASS-THROUGH PURO (`return azimuth_buttons`);
 *   - swap_start_back != 0 -> troca SOMENTE Menu (0x0004) e View (0x0008).
 *     O D-Pad inteiro (0x0100..0x0800), A/B/X/Y, ombros e analógicos ficam
 *     byte-a-byte intactos nos dois modos.
 */
static inline uint32_t fm5_buttons_recompose(uint32_t azimuth_buttons,
                                             int swap_start_back)
{
    uint32_t menu;
    uint32_t view;
    uint32_t out;

    if (!swap_start_back) {
        return azimuth_buttons; /* pass-through puro */
    }

    menu = azimuth_buttons & FM5_GB_MENU;
    view = azimuth_buttons & FM5_GB_VIEW;
    out = azimuth_buttons & ~FM5_GB_SYSTEM_MASK;
    if (view) {
        out |= FM5_GB_MENU;
    }
    if (menu) {
        out |= FM5_GB_VIEW;
    }
    return out;
}

/* Conveniência: estado Windows.Gaming.Input bruto -> enum Xbox One ERA. */
static inline uint32_t fm5_buttons_from_dinput(uint32_t gaming_buttons,
                                               int swap_start_back)
{
    return fm5_buttons_recompose(fm5_buttons_azimuth_shift(gaming_buttons),
                                 swap_start_back);
}

#ifdef __cplusplus
}
#endif

#endif /* FM5_BUTTONS_H */
