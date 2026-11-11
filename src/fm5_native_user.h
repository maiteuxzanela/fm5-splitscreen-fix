/*
 * fm5_native_user.h — caminho NATIVO de Controller::get_User (portátil).
 *
 * Reproduz byte-a-byte a semântica do corpo original do exe:
 *
 *   14019a4c9: call 0x140042980        ; UserStatics singleton
 *   14019a4cf: mov  0x18(%rax),%rcx    ; user = *(mgr + 0x18)
 *   14019a4e3: mov  %rcx,(%rbx)        ; *out = user   (rbx = out)
 *   14019a4eb: mov  (%rcx),%rax        ; AddRef via vtable[1]
 *   14019a4ee: call *0x8(%rax)
 *   14019a4f2: xor  %eax,%eax          ; S_OK
 *
 * Chamar a função nativa do singleton diretamente (em vez de voltar pelo
 * trampolim) elimina o retorno instável `call; mov 0x18(%rax)` quebrado ao
 * meio. Este header é isolado de <windows.h> para ser exercitado por testes
 * nativos no host Linux com a MESMA implementação usada pela DLL.
 */
#ifndef FM5_NATIVE_USER_H
#define FM5_NATIVE_USER_H

#include <stdint.h>

#define FM5_NATIVE_USER_OFFSET 0x18u

#define FM5_HR_S_OK      ((int32_t)0)
#define FM5_HR_E_POINTER ((int32_t)0x80004003u)
#define FM5_HR_E_FAIL    ((int32_t)0x80004005u)

typedef void (*fm5_addref_fn)(void *obj);

/*
 * Espelha o caminho nativo de get_User para o Player 1:
 *   - mgr == NULL              -> E_FAIL (fail-closed; o original crasharia);
 *   - out == NULL              -> E_POINTER;
 *   - user == NULL             -> S_OK com *out = NULL (sem AddRef), igual ao
 *                                 binário original;
 *   - user != NULL             -> *out = user e AddRef(user), S_OK.
 */
static inline int32_t fm5_native_user_serve(void *mgr, void **out,
                                            fm5_addref_fn addref)
{
    void *user;

    if (!mgr) {
        return FM5_HR_E_FAIL;
    }
    user = *(void **)((uint8_t *)mgr + FM5_NATIVE_USER_OFFSET);
    if (!out) {
        return FM5_HR_E_POINTER;
    }
    *out = user;
    if (user && addref) {
        addref(user);
    }
    return FM5_HR_S_OK;
}

#endif /* FM5_NATIVE_USER_H */
