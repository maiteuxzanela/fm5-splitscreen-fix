/*
 * test_fm5_native_user.c — testes reais do caminho nativo de get_User.
 *
 * Exercita a MESMA implementação usada pela DLL (src/fm5_native_user.h), sem
 * Windows e sem mocks da lógica sob teste: apenas um objeto de dados com o
 * layout real do singleton (user no offset +0x18) e um AddRef observável.
 */
#include "fm5_native_user.h"

#include <stdint.h>
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

/* Layout do UserStatics: o ponteiro do User vive exatamente em +0x18. */
typedef struct fake_user_statics {
    uint8_t pad[FM5_NATIVE_USER_OFFSET];
    void   *user;
} fake_user_statics_t;

static int  g_addref_calls;
static void *g_addref_obj;
static void **g_observed_out;
static int  g_out_matches;

static void spy_addref(void *obj)
{
    g_addref_calls++;
    g_addref_obj = obj;
    if (g_observed_out) {
        /* O original escreve *out ANTES do AddRef (0x14019a4e3 / 0x14019a4ee). */
        g_out_matches = (*g_observed_out == obj);
    }
}

static void reset_spy(void)
{
    g_addref_calls = 0;
    g_addref_obj = NULL;
    g_observed_out = NULL;
    g_out_matches = -1;
}

static void test_layout(void)
{
    fake_user_statics_t mgr;
    CHECK(FM5_NATIVE_USER_OFFSET == 0x18);
    CHECK((size_t)((uint8_t *)&mgr.user - (uint8_t *)&mgr) ==
          FM5_NATIVE_USER_OFFSET);
}

static void test_null_mgr_fails_closed(void)
{
    void *out = (void *)0x1;
    reset_spy();
    CHECK(fm5_native_user_serve(NULL, &out, spy_addref) == FM5_HR_E_FAIL);
    CHECK(out == (void *)0x1); /* nao escreve em out */
    CHECK(g_addref_calls == 0);
}

static void test_null_out_e_pointer(void)
{
    int user_token = 0;
    fake_user_statics_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.user = &user_token;
    reset_spy();
    CHECK(fm5_native_user_serve(&mgr, NULL, spy_addref) == FM5_HR_E_POINTER);
    CHECK(g_addref_calls == 0);
}

static void test_null_user_ok_without_addref(void)
{
    fake_user_statics_t mgr;
    void *out = (void *)0x1;
    memset(&mgr, 0, sizeof(mgr));
    reset_spy();
    CHECK(fm5_native_user_serve(&mgr, &out, spy_addref) == FM5_HR_S_OK);
    CHECK(out == NULL);
    CHECK(g_addref_calls == 0);
}

static void test_user_served_with_addref(void)
{
    int user_token = 0;
    fake_user_statics_t mgr;
    void *out = NULL;
    memset(&mgr, 0, sizeof(mgr));
    mgr.user = &user_token;
    reset_spy();
    g_observed_out = &out;
    CHECK(fm5_native_user_serve(&mgr, &out, spy_addref) == FM5_HR_S_OK);
    CHECK(out == &user_token);
    CHECK(g_addref_calls == 1);
    CHECK(g_addref_obj == &user_token);
    CHECK(g_out_matches == 1); /* *out ja estava preenchido no AddRef */
}

static void test_addref_null_tolerated(void)
{
    int user_token = 0;
    fake_user_statics_t mgr;
    void *out = NULL;
    memset(&mgr, 0, sizeof(mgr));
    mgr.user = &user_token;
    CHECK(fm5_native_user_serve(&mgr, &out, NULL) == FM5_HR_S_OK);
    CHECK(out == &user_token);
}

int main(void)
{
    test_layout();
    test_null_mgr_fails_closed();
    test_null_out_e_pointer();
    test_null_user_ok_without_addref();
    test_user_served_with_addref();
    test_addref_null_tolerated();

    if (g_failures) {
        fprintf(stderr, "\n%d/%d verificacoes do caminho nativo FALHARAM\n",
                g_failures, g_checks);
        return 1;
    }
    printf("OK: %d verificacoes do caminho nativo de get_User passaram\n",
           g_checks);
    return 0;
}
