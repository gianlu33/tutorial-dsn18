#include "encl_t.h"

/*
 * NOTE: for demonstration purposes, we hard-code secrets at compile time and
 * abstract away how they are securely provisioned at runtime.
 */
int super_secret_constant   = 0xdeadbeef;
int super_secret_pin        = 1234;

int ecall_dummy(int i)
{
    ocall_print("hello world from ecall_dummy!");
    return super_secret_constant + i;
}

/* =========================== START SOLUTION =========================== */


int ecall_get_secret(int *secret_pt) {
  int i, rv;

  for(i=0; i<3; i++) {
    ocall_get_pin(&rv);

    if(rv == super_secret_pin) {
      *secret_pt = super_secret_constant;
      return 1;
    }
  }

  super_secret_constant = 0;
  super_secret_pin = 0;

  return 0;
}

/* ============================ END SOLUTION ============================ */
