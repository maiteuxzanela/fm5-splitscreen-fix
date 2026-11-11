/*
 * test_fm5_buttons.c — testes determinísticos da recomposição de GamepadButtons.
 *
 * Exercita a MESMA unidade portátil (src/fm5_buttons.h) que a DLL usa em
 * produção.
 *
 * TICKET-HARNESS-166 — o Azimuth lê Windows.Gaming.Input.GamepadButtons e
 * aplica `shl $2` para converter ao enum Windows.Xbox.Input.GamepadButtons da
 * geração Xbox One (o enum consumido pelo Forza 5):
 *   Menu=0x0004 View=0x0008 A=0x0010 B=0x0020 X=0x0040 Y=0x0080
 *   DPadUp=0x0100 DPadDown=0x0200 DPadLeft=0x0400 DPadRight=0x0800
 *   LeftShoulder=0x1000 RightShoulder=0x2000
 *   LeftThumbstick=0x4000 RightThumbstick=0x8000
 *
 * A recomposição é:
 *   - PASS-THROUGH PURO com swap_start_back == 0 (nenhum bit é apagado);
 *   - troca SOMENTE Menu (0x0004) e View (0x0008) com swap_start_back != 0.
 * O D-Pad inteiro (0x0100..0x0800) NUNCA é consumido: a versão anterior
 * tratava 0x0100/0x0200 como Back/Start e destruía DPadUp/DPadDown.
 */
#include "fm5_buttons.h"

#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_checks;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_checks++;                                                          \
        if (!(cond)) {                                                       \
            g_failures++;                                                    \
            fprintf(stderr, "FALHA %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                    \
    } while (0)

static void test_constants(void)
{
    /* Enum Windows.Xbox.Input.GamepadButtons (Xbox One ERA) — pós-shift. */
    CHECK(FM5_GB_MENU == 0x0004u);
    CHECK(FM5_GB_VIEW == 0x0008u);
    CHECK(FM5_GB_A == 0x0010u);
    CHECK(FM5_GB_B == 0x0020u);
    CHECK(FM5_GB_X == 0x0040u);
    CHECK(FM5_GB_Y == 0x0080u);
    CHECK(FM5_GB_DPAD_UP == 0x0100u);
    CHECK(FM5_GB_DPAD_DOWN == 0x0200u);
    CHECK(FM5_GB_DPAD_LEFT == 0x0400u);
    CHECK(FM5_GB_DPAD_RIGHT == 0x0800u);
    CHECK(FM5_GB_LEFT_SHOULDER == 0x1000u);
    CHECK(FM5_GB_RIGHT_SHOULDER == 0x2000u);
    CHECK(FM5_GB_LEFT_THUMBSTICK == 0x4000u);
    CHECK(FM5_GB_RIGHT_THUMBSTICK == 0x8000u);

    /* Enum de ENTRADA Windows.Gaming.Input.GamepadButtons (pré-shift). */
    CHECK(FM5_WGI_MENU == 0x0001u);
    CHECK(FM5_WGI_VIEW == 0x0002u);
    CHECK(FM5_WGI_A == 0x0004u);
    CHECK(FM5_WGI_B == 0x0008u);
    CHECK(FM5_WGI_X == 0x0010u);
    CHECK(FM5_WGI_Y == 0x0020u);
    CHECK(FM5_WGI_DPAD_UP == 0x0040u);
    CHECK(FM5_WGI_DPAD_DOWN == 0x0080u);
    CHECK(FM5_WGI_DPAD_LEFT == 0x0100u);
    CHECK(FM5_WGI_DPAD_RIGHT == 0x0200u);
    CHECK(FM5_WGI_LEFT_SHOULDER == 0x0400u);
    CHECK(FM5_WGI_RIGHT_SHOULDER == 0x0800u);
    CHECK(FM5_WGI_LEFT_THUMBSTICK == 0x1000u);
    CHECK(FM5_WGI_RIGHT_THUMBSTICK == 0x2000u);
}

static void test_azimuth_shift_maps_gaming_to_xbox_one(void)
{
    /* A conversão do Azimuth: (gaming & 0x3fff) << 2. */
    CHECK(fm5_buttons_azimuth_shift(0) == 0);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_MENU) == FM5_GB_MENU);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_VIEW) == FM5_GB_VIEW);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_A) == FM5_GB_A);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_B) == FM5_GB_B);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_X) == FM5_GB_X);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_Y) == FM5_GB_Y);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_DPAD_UP) == FM5_GB_DPAD_UP);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_DPAD_DOWN) == FM5_GB_DPAD_DOWN);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_DPAD_LEFT) == FM5_GB_DPAD_LEFT);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_DPAD_RIGHT) == FM5_GB_DPAD_RIGHT);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_LEFT_SHOULDER) ==
          FM5_GB_LEFT_SHOULDER);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_RIGHT_SHOULDER) ==
          FM5_GB_RIGHT_SHOULDER);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_LEFT_THUMBSTICK) ==
          FM5_GB_LEFT_THUMBSTICK);
    CHECK(fm5_buttons_azimuth_shift(FM5_WGI_RIGHT_THUMBSTICK) ==
          FM5_GB_RIGHT_THUMBSTICK);

    /* Máscara de 14 bits: bits acima de 0x2000 são descartados. */
    CHECK(fm5_buttons_azimuth_shift(0xFFFFu) ==
          fm5_buttons_azimuth_shift(FM5_AZIMUTH_BUTTON_MASK));
    CHECK(fm5_buttons_azimuth_shift(0xFFFFu) == 0xFFFCu);
}

/* TICKET-HARNESS-166: swap=0 é PASS-THROUGH PURO — para TODO valor de 16 bits
 * a saída é byte-a-byte igual à entrada. */
static void test_recompose_pass_through_exhaustive(void)
{
    uint32_t v;
    for (v = 0; v <= 0xFFFFu; v++) {
        CHECK(fm5_buttons_recompose(v, 0) == v);
    }
}

/* Swap=1 permuta SOMENTE Menu/View; todo o resto fica intacto. */
static void test_recompose_swap_only_system_bits(void)
{
    uint32_t v;
    for (v = 0; v <= 0xFFFFu; v++) {
        uint32_t out = fm5_buttons_recompose(v, 1);
        uint32_t in_rest = v & ~(FM5_GB_MENU | FM5_GB_VIEW);
        uint32_t out_rest = out & ~(FM5_GB_MENU | FM5_GB_VIEW);

        CHECK(out_rest == in_rest);
        CHECK(((out & FM5_GB_MENU) != 0) == ((v & FM5_GB_VIEW) != 0));
        CHECK(((out & FM5_GB_VIEW) != 0) == ((v & FM5_GB_MENU) != 0));
    }
}

static void test_system_helpers(void)
{
    /* Start/Menu = 0x0004. */
    CHECK(fm5_buttons_start_pressed(FM5_GB_MENU) == 1);
    CHECK(fm5_buttons_start_pressed(0x0004u) == 1);
    CHECK(fm5_buttons_start_pressed(0x0000u) == 0);
    CHECK(fm5_buttons_start_pressed(FM5_GB_VIEW) == 0);
    CHECK(fm5_buttons_start_pressed(FM5_GB_DPAD_UP) == 0);
    CHECK(fm5_buttons_start_pressed(FM5_GB_DPAD_DOWN) == 0);
    CHECK(fm5_buttons_start_pressed(FM5_GB_A) == 0);

    /* Back/View = 0x0008. */
    CHECK(fm5_buttons_back_pressed(FM5_GB_VIEW) == 1);
    CHECK(fm5_buttons_back_pressed(0x0008u) == 1);
    CHECK(fm5_buttons_back_pressed(0x0000u) == 0);
    CHECK(fm5_buttons_back_pressed(FM5_GB_MENU) == 0);
    CHECK(fm5_buttons_back_pressed(FM5_GB_DPAD_UP) == 0);
    CHECK(fm5_buttons_back_pressed(FM5_GB_DPAD_DOWN) == 0);
    CHECK(fm5_buttons_back_pressed(FM5_GB_A) == 0);
}

static void test_dpad_never_consumed(void)
{
    /* Setas puras: idênticas nos dois modos. */
    CHECK(fm5_buttons_recompose(FM5_GB_DPAD_UP, 0) == FM5_GB_DPAD_UP);
    CHECK(fm5_buttons_recompose(FM5_GB_DPAD_DOWN, 0) == FM5_GB_DPAD_DOWN);
    CHECK(fm5_buttons_recompose(FM5_GB_DPAD_LEFT, 0) == FM5_GB_DPAD_LEFT);
    CHECK(fm5_buttons_recompose(FM5_GB_DPAD_RIGHT, 0) == FM5_GB_DPAD_RIGHT);
    CHECK(fm5_buttons_recompose(FM5_GB_DPAD_UP, 1) == FM5_GB_DPAD_UP);
    CHECK(fm5_buttons_recompose(FM5_GB_DPAD_DOWN, 1) == FM5_GB_DPAD_DOWN);
    CHECK(fm5_buttons_recompose(FM5_GB_DPAD_LEFT, 1) == FM5_GB_DPAD_LEFT);
    CHECK(fm5_buttons_recompose(FM5_GB_DPAD_RIGHT, 1) == FM5_GB_DPAD_RIGHT);

    /* O D-Pad inteiro sobrevive junto de Menu/View nos dois modos. */
    {
        uint32_t all_dpad = FM5_GB_DPAD_UP | FM5_GB_DPAD_DOWN |
                            FM5_GB_DPAD_LEFT | FM5_GB_DPAD_RIGHT;
        uint32_t in = all_dpad | FM5_GB_MENU | FM5_GB_VIEW | FM5_GB_A |
                      FM5_GB_B | FM5_GB_X | FM5_GB_Y |
                      FM5_GB_LEFT_SHOULDER | FM5_GB_RIGHT_SHOULDER |
                      FM5_GB_LEFT_THUMBSTICK | FM5_GB_RIGHT_THUMBSTICK;
        uint32_t out = fm5_buttons_recompose(in, 0);
        CHECK(out == in); /* pass-through */

        out = fm5_buttons_recompose(in, 1);
        CHECK((out & all_dpad) == all_dpad);
        CHECK((out & FM5_GB_A) == FM5_GB_A);
        CHECK((out & FM5_GB_B) == FM5_GB_B);
        CHECK((out & FM5_GB_X) == FM5_GB_X);
        CHECK((out & FM5_GB_Y) == FM5_GB_Y);
        CHECK((out & FM5_GB_LEFT_SHOULDER) == FM5_GB_LEFT_SHOULDER);
        CHECK((out & FM5_GB_RIGHT_SHOULDER) == FM5_GB_RIGHT_SHOULDER);
        CHECK((out & FM5_GB_LEFT_THUMBSTICK) == FM5_GB_LEFT_THUMBSTICK);
        CHECK((out & FM5_GB_RIGHT_THUMBSTICK) == FM5_GB_RIGHT_THUMBSTICK);
    }
}

static void test_swap_start_back_single_button(void)
{
    /* Com swap=1 um Start isolado vira View e um Back isolado vira Menu. */
    CHECK((fm5_buttons_from_dinput(FM5_WGI_MENU, 1) & FM5_GB_VIEW) ==
          FM5_GB_VIEW);
    CHECK((fm5_buttons_from_dinput(FM5_WGI_VIEW, 1) & FM5_GB_MENU) ==
          FM5_GB_MENU);
    /* Sem swap, a conversão é exata. */
    CHECK(fm5_buttons_from_dinput(FM5_WGI_MENU, 0) == FM5_GB_MENU);
    CHECK(fm5_buttons_from_dinput(FM5_WGI_VIEW, 0) == FM5_GB_VIEW);
    /* Ambos pressionados: o conjunto permanece o mesmo. */
    CHECK(fm5_buttons_from_dinput(FM5_WGI_MENU | FM5_WGI_VIEW, 1) ==
          (FM5_GB_MENU | FM5_GB_VIEW));
}

static void test_from_dinput_matches_recompose(void)
{
    uint32_t gaming;
    for (gaming = 0; gaming <= FM5_AZIMUTH_BUTTON_MASK; gaming++) {
        uint32_t shifted = fm5_buttons_azimuth_shift(gaming);
        CHECK(fm5_buttons_from_dinput(gaming, 0) == shifted);
        CHECK(fm5_buttons_from_dinput(gaming, 1) ==
              fm5_buttons_recompose(shifted, 1));
    }
}

static void test_idempotent(void)
{
    uint32_t in = FM5_GB_MENU | FM5_GB_VIEW | FM5_GB_A | FM5_GB_DPAD_UP |
                  FM5_GB_DPAD_DOWN;
    CHECK(fm5_buttons_recompose(in, 0) == in);
    CHECK(fm5_buttons_recompose(fm5_buttons_recompose(in, 0), 0) == in);
    /* Swap aplicado duas vezes volta ao original. */
    CHECK(fm5_buttons_recompose(fm5_buttons_recompose(in, 1), 1) == in);
}

static void test_legacy_masks_removed(void)
{
    /* As máscaras destrutivas 0x0100/0x0200 do TICKET-HARNESS-164 não existem
     * mais: se alguém as reintroduzir, o teste falha na compilação. */
#ifdef FM5_SHIFTED_START_MASK
    CHECK(0 && "FM5_SHIFTED_START_MASK nao deve existir");
#endif
#ifdef FM5_SHIFTED_BACK_MASK
    CHECK(0 && "FM5_SHIFTED_BACK_MASK nao deve existir");
#endif
#ifdef FM5_BUTTON_SCRUB_MASK
    CHECK(0 && "FM5_BUTTON_SCRUB_MASK nao deve existir");
#endif
}

int main(void)
{
    test_constants();
    test_azimuth_shift_maps_gaming_to_xbox_one();
    test_recompose_pass_through_exhaustive();
    test_recompose_swap_only_system_bits();
    test_system_helpers();
    test_dpad_never_consumed();
    test_swap_start_back_single_button();
    test_from_dinput_matches_recompose();
    test_idempotent();
    test_legacy_masks_removed();

    if (g_failures) {
        fprintf(stderr, "\n%d/%d verificacoes de BOTOES FALHARAM\n",
                g_failures, g_checks);
        return 1;
    }
    printf("OK: %d verificacoes de botoes passaram\n", g_checks);
    return 0;
}
