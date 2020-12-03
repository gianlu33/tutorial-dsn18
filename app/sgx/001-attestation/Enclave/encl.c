#include "libspongent/spongewrap.h"
#include <sgx_trts.h>
#include "encl_t.h"

/*
 * XXX Fill in the correct Sancus-specific key computed from the final foo.c enclave source code:
 *
 * $ sancus-crypto --key 0b7bf3ae40880a8be430d0da34fb76f0 --gen-sm-key foo --c-array main.elf
 */
uint8_t key[] = { 0x2a, 0x43, 0xd7, 0xdf, 0x7d, 0x3d, 0xad, 0xc5, 0xd7, 0x85, 0x8e, 0xde, 0xe7, 0x4b, 0x6b, 0x14};
uint64_t challenge;

uint64_t ecall_get_challenge(void)
{
    /* =========================== START SOLUTION =========================== */
    if( sgx_read_rand((unsigned char *) &challenge, sizeof(uint64_t)) != SGX_SUCCESS ) {
      challenge = 0;
      return -1;
    }

    return challenge;
    /* ============================ END SOLUTION ============================ */
}

int ecall_verify_response(uint8_t *sm_mac)
{
    /* =========================== START SOLUTION =========================== */
    uint8_t my_mac[SPONGENT_TAG_SIZE];
    int i;

    if( spongent_mac((void*) key, (uint8_t*) &challenge, sizeof(uint64_t), my_mac) ) return 0;

    for (i = 0; (i < SPONGENT_TAG_SIZE) && (my_mac[i] == sm_mac[i]); i++);
    return i >= SPONGENT_TAG_SIZE;
    /* ============================ END SOLUTION ============================ */
}
