#include "libspongent/spongewrap.h"
#include <sgx_trts.h>
#include "encl_t.h"
#include <string.h>

/*
 * XXX Fill in the correct Sancus-specific key computed from the final foo.c enclave source code:
 *
 * $ sancus-crypto --key 0b7bf3ae40880a8be430d0da34fb76f0 --gen-sm-key foo --c-array main.elf
 */
uint8_t key[] = { 0xa4, 0x4e, 0x57, 0x19, 0x34, 0x9d, 0x18, 0xa2, 0xe1, 0x06, 0x0b, 0xf8, 0x72, 0x63, 0xba, 0x9d};
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

/*
 * We create a MAC over: challenge (8B) | PMODBTN sensor reading (2B)
 *
 * NOTE: we use a 2B sensor reading size to ensure the total size of the buffer
 * is a multiple of 2 (to work around a known erratum in the Sancus crypto HW
 * instructions).
 */
#define ATTEST_MSG_SIZE (sizeof(uint64_t) + sizeof(uint16_t))

int ecall_verify_response(uint8_t *sm_mac, uint16_t btn)
{
    /* =========================== START SOLUTION =========================== */
    uint8_t my_mac[SPONGENT_TAG_SIZE];
    uint8_t msg[ATTEST_MSG_SIZE];
    int i;

    memcpy(msg, &challenge, sizeof(uint64_t));
    memcpy(msg + sizeof(uint64_t), &btn, sizeof(uint16_t));

    if( spongent_mac((void*) key, msg, ATTEST_MSG_SIZE, my_mac) ) return 0;

    for (i = 0; (i < SPONGENT_TAG_SIZE) && (my_mac[i] == sm_mac[i]); i++);
    return i >= SPONGENT_TAG_SIZE;
    /* ============================ END SOLUTION ============================ */
}
