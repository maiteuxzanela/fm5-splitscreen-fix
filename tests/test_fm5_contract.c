/*
 * test_fm5_contract.c — contrato de ABI/invariantes que a camada Windows
 * (fm5_hooks.c) depende do núcleo portátil. Se estes valores mudarem, os
 * handlers devolvem HRESULTs errados ou expõem usuários inválidos.
 *
 * TICKET-HARNESS-163: boot expõe 2 perfis e TODO controle nasce no índice 0
 * (Player 1); o primeiro A elege o P1 definitivo e PROMOVE o secundário ao
 * índice 1 (Player 2 virtual, TICKET-HARNESS-171); o primeiro Start no lobby
 * confirma o P2 definitivo.
 *
 * TICKET-HARNESS-168: contrato da identidade Guest (XUID/XboxUserHash).
 */
#include "fm5_identity.h"

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

static void *never_called(void *ctx, fm5_identity_t *id, int index)
{
    (void)ctx;
    (void)id;
    (void)index;
    return (void *)0xDEAD;
}

int main(void)
{
    /* 1) Enum de status mapeia 1:1 para os HRESULTs usados nos hooks. */
    CHECK((int)FM5_DELEGATE == 0);
    CHECK((int)FM5_HANDLED == 1);
    CHECK((int)FM5_SERVED_NULL == 2);
    CHECK((int)FM5_E_POINTER == -1);
    CHECK((int)FM5_E_OUTOFMEMORY == -2);

    /* 1b) Botões (enum Windows.Xbox.Input.GamepadButtons, Xbox One ERA) e
     * índice neutro canônicos — TICKET-HARNESS-166. */
    CHECK(FM5_IDENTITY_BUTTON_MENU == 0x0004u); /* Start */
    CHECK(FM5_IDENTITY_BUTTON_VIEW == 0x0008u); /* Back  */
    CHECK(FM5_IDENTITY_BUTTON_A == 0x0010u);
    CHECK(FM5_INDEX_NEUTRAL == -1);

    /* 1c) TICKET-HARNESS-168 — XUID base é o imediato nativo de
     * User::get_XboxUserId (0x042150): 0x9000000000000. */
    CHECK(FM5_XBOX_USER_ID_BASE == 0x9000000000000ULL);
    CHECK(FM5_XBOX_USER_ID_BASE == 2533274790395904ULL);
    CHECK(FM5_XBOX_USER_ID_PLAYER1 == FM5_XBOX_USER_ID_BASE);
    CHECK(FM5_XBOX_USER_ID_PLAYER2 == FM5_XBOX_USER_ID_BASE + 1ULL);
    CHECK(FM5_XBOX_USER_ID_PLAYER1 != FM5_XBOX_USER_ID_PLAYER2);
    CHECK(strcmp(FM5_XBOX_USER_HASH_PLAYER1, "1") == 0);
    CHECK(strcmp(FM5_XBOX_USER_HASH_PLAYER2, "2") == 0);

    /* 1d) Guest: P1 assinado (0) e todo índice virtual (>=1) Convidado. */
    {
        fm5_identity_t id;
        char buf[24];
        fm5_identity_init(&id, 4, NULL);
        CHECK(fm5_identity_is_guest(&id, 0) == 0);
        CHECK(fm5_identity_is_guest(&id, 1) == 1);
        CHECK(fm5_identity_is_guest(&id, 3) == 1);
        CHECK(fm5_identity_is_guest(&id, 4) == 0);
        CHECK(fm5_identity_xbox_user_id(&id, 0, buf, sizeof(buf)) == buf);
        CHECK(strcmp(buf, "2533274790395904") == 0);
        CHECK(fm5_identity_xbox_user_id(&id, 1, buf, sizeof(buf)) == buf);
        CHECK(strcmp(buf, "2533274790395905") == 0);
        CHECK(fm5_identity_xbox_user_hash(&id, 0, buf, sizeof(buf)) == buf);
        CHECK(strcmp(buf, "1") == 0);
        CHECK(fm5_identity_xbox_user_hash(&id, 1, buf, sizeof(buf)) == buf);
        CHECK(strcmp(buf, "2") == 0);
        fm5_identity_destroy(&id);
    }

    /* 2) IDs nunca zero e nunca colidem entre si (todos os índices). */
    {
        fm5_identity_t id;
        uint64_t seen[FM5_P2_MAX_USERS];
        int i, j;
        fm5_identity_init(&id, FM5_P2_MAX_USERS, NULL);
        for (i = 0; i < FM5_P2_MAX_USERS; i++) {
            seen[i] = fm5_identity_user(&id, i)->user_id;
            CHECK(seen[i] != 0);
            for (j = 0; j < i; j++) {
                CHECK(seen[i] != seen[j]);
            }
        }
        CHECK(seen[0] == FM5_USER_ID_PLAYER1);
        fm5_identity_destroy(&id);
    }

    /* 3) Boot: 2 perfis expostos, todo controle no índice 0 (Player 1). */
    {
        fm5_identity_t id;
        int c1 = 0, c2 = 1;
        fm5_identity_init(&id, 2, NULL);
        CHECK(fm5_identity_active_users(&id) == 2);
        CHECK(fm5_identity_console_count(&id) == 2);
        CHECK(fm5_identity_index_for_controller(&id, &c1) == 0);
        CHECK(fm5_identity_index_for_controller(&id, &c2) == 0);
        CHECK(fm5_identity_p1_locked(&id) == 0);
        CHECK(fm5_identity_p2_locked(&id) == 0);
        CHECK(fm5_identity_index_claimed(&id, 0) == 0);
        CHECK(fm5_identity_index_claimed(&id, 1) == 0);
        fm5_identity_destroy(&id);
    }

    /* 4) get_User: boot -> delegate (NUNCA NULL); A -> P1; Start -> P2. */
    {
        fm5_identity_t id;
        void *out = (void *)0x1;
        int c1 = 0, c2 = 1;
        fm5_identity_init(&id, 2, NULL);

        CHECK(fm5_resolve_get_user(&id, &c1, &out, NULL, never_called, NULL) ==
              FM5_DELEGATE);
        CHECK(out == (void *)0x1); /* delegate: o hook serve o nativo */

        CHECK(fm5_identity_claim_player(&id, &c1,
                                        FM5_IDENTITY_BUTTON_A) == 0);
        out = NULL;
        CHECK(fm5_resolve_get_user(&id, &c1, &out, NULL, never_called, NULL) ==
              FM5_DELEGATE);
        CHECK(out == NULL);

        /* TICKET-HARNESS-171: após o P1 eleito o controle secundário já é o
         * Player 2 VIRTUAL (índice 1) — get_User materializa o virtual, nunca
         * delega ao User do Player 1. */
        CHECK(fm5_identity_index_for_controller(&id, &c2) == 1);
        CHECK(fm5_identity_is_assigned_controller(&id, &c2) == 1);
        out = (void *)0x1;
        CHECK(fm5_resolve_get_user(&id, &c2, &out, NULL, never_called, NULL) ==
              FM5_HANDLED);
        CHECK(out == (void *)0xDEAD);

        /* Start só elege P2 quando P1 já existe. Back/View (0x0008), B
         * (0x0020) e o D-pad (0x0100/0x0200) NÃO elegem ninguém. */
        CHECK(fm5_identity_claim_player(&id, &c2, 0x0002u) == -1);
        CHECK(fm5_identity_claim_player(&id, &c2,
                                        FM5_IDENTITY_BUTTON_VIEW) == -1);
        CHECK(fm5_identity_claim_player(&id, &c2, 0x0020u) == -1);
        CHECK(fm5_identity_claim_player(&id, &c2, 0x0100u) == -1);
        CHECK(fm5_identity_claim_player(&id, &c2, 0x0200u) == -1);
        CHECK(fm5_identity_claim_player(&id, &c2,
                                        FM5_IDENTITY_BUTTON_MENU) == 1);
        out = NULL;
        CHECK(fm5_resolve_get_user(&id, &c2, &out, NULL, never_called, NULL) ==
              FM5_HANDLED);
        CHECK(out == (void *)0xDEAD);

        fm5_identity_destroy(&id);
    }

    /* 5) get_users: no boot devolve 2 (P1 nativo + P2 virtual) e respeita cap. */
    {
        fm5_identity_t id;
        void *users[FM5_P2_MAX_USERS];
        int p1 = 0;
        memset(users, 0xEE, sizeof(users));
        fm5_identity_init(&id, 2, NULL);
        CHECK(fm5_resolve_get_users(&id, &p1, users, FM5_P2_MAX_USERS,
                                    never_called, NULL) == 2);
        CHECK(users[0] == &p1);
        CHECK(users[1] == (void *)0xDEAD);
        memset(users, 0xEE, sizeof(users));
        CHECK(fm5_resolve_get_users(&id, &p1, users, 1, never_called, NULL) ==
              1);
        CHECK(users[1] == (void *)0xEEEEEEEEEEEEEEEEULL);
        fm5_identity_destroy(&id);
    }

    /* 6) get_users: nunca escreve mais que cap; cascata elege só P1/P2. */
    {
        fm5_identity_t id;
        void *users[2] = {NULL, NULL};
        int keys[FM5_P2_MAX_USERS];
        int p1 = 0;
        int i;
        fm5_identity_init(&id, FM5_P2_MAX_USERS, NULL);
        for (i = 0; i < FM5_P2_MAX_USERS; i++) {
            keys[i] = i;
            CHECK(fm5_identity_index_for_controller(&id, &keys[i]) == 0);
        }
        CHECK(fm5_identity_claim_player(&id, &keys[0],
                                        FM5_IDENTITY_BUTTON_A) == 0);
        /* TICKET-HARNESS-171: o secundário já está no índice 1 e os demais em
         * 2, 3, ... (ordem de registro). */
        for (i = 1; i < FM5_P2_MAX_USERS; i++) {
            CHECK(fm5_identity_index_for_controller(&id, &keys[i]) == i);
        }
        CHECK(fm5_identity_claim_player(&id, &keys[1],
                                        FM5_IDENTITY_BUTTON_MENU) == 1);
        for (i = 2; i < FM5_P2_MAX_USERS; i++) {
            CHECK(fm5_identity_index_for_controller(&id, &keys[i]) == i);
            CHECK(fm5_identity_claim_player(&id, &keys[i],
                                            FM5_IDENTITY_BUTTON_MENU) == -1);
        }
        CHECK(fm5_resolve_get_users(&id, &p1, users, 2, never_called, NULL) ==
              2);
        fm5_identity_destroy(&id);
    }

    /* 7) snapshot respeita o cap e devolve ponteiros internos estáveis. */
    {
        fm5_identity_t id;
        const fm5_user_t *snap[FM5_P2_MAX_USERS];
        fm5_identity_init(&id, 3, NULL);
        CHECK(fm5_identity_snapshot(&id, snap, 0) == 0);
        CHECK(fm5_identity_snapshot(&id, NULL, 3) == 0);
        CHECK(fm5_identity_snapshot(&id, snap, 3) == 2);
        CHECK(snap[0] == fm5_identity_user(&id, 0));
        CHECK(snap[1] == fm5_identity_user(&id, 1));
        fm5_identity_destroy(&id);
    }

    /* 8) gamer tags padrão determinísticas e não vazias. */
    {
        fm5_identity_t id;
        int i;
        fm5_identity_init(&id, FM5_P2_MAX_USERS, NULL);
        for (i = 0; i < FM5_P2_MAX_USERS; i++) {
            CHECK(fm5_identity_user(&id, i)->gamer_tag[0] != '\0');
        }
        CHECK(strcmp(fm5_identity_user(&id, 0)->gamer_tag, "Player 1") == 0);
        CHECK(strcmp(fm5_identity_user(&id, 1)->gamer_tag, "Player 2") == 0);
        CHECK(strcmp(fm5_identity_user(&id, 2)->gamer_tag, "Player 3") == 0);
        fm5_identity_destroy(&id);
    }

    if (g_failures) {
        fprintf(stderr, "\n%d/%d verificacoes de CONTRATO FALHARAM\n",
                g_failures, g_checks);
        return 1;
    }
    printf("OK: %d verificacoes de contrato passaram\n", g_checks);
    return 0;
}
