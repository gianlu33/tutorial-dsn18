/* utility headers */
#include "debug.h"
#include "can.h"

/* for configurable SPONGENT_KEY_SIZE */
#include "../libspongent/libspongent/spongewrap.h"
#include "../libspongent/libspongent/config.h"

#if SPONGENT_TAG_SIZE != (CAN_PAYLOAD_SIZE*2)
    #error expecting 128-bit Sancus core
#endif

#define CAN_INTERFACE       "slcan0"
#define CAN_ATTEST_ID        0x40

int can_socket = -1;

/*
 * XXX Fill in the correct Sancus-specific key computed from the final foo.c enclave source code:
 *
 * $ sancus-crypto --key 0b7bf3ae40880a8be430d0da34fb76f0 --gen-sm-key foo --c-array main.elf
 */
const uint8_t key[SPONGENT_KEY_SIZE] = { 0xe8, 0xa6, 0xdf, 0xca, 0x8d, 0x21, 0xaf, 0xb3, 0x2b, 0x44, 0xfd, 0xe6, 0x12, 0xe2, 0x3c, 0x35};

int main( int argc, char **argv )
{
    uint64_t challenge = 0x0;
    uint8_t my_mac[SPONGENT_TAG_SIZE] = {0x0};
    uint8_t sm_mac[SPONGENT_TAG_SIZE] = {0x0};
    uint16_t id = 0x0;
    int i, len;

    info("setup");
    ASSERT( (can_socket = can_open(CAN_INTERFACE)) >= 0 );

    /* ---------------------------------------------------------------------- */
    info_event("remote attestation challenge");
    printf("enter attesation challenge (64-bit number) > ");
    scanf("%llu", &challenge);
    ASSERT( can_send(can_socket, CAN_ATTEST_ID, (uint8_t*) &challenge, sizeof(uint64_t)) > 0 );

    /* ---------------------------------------------------------------------- */
    info_event("remote attestation response");

    info("waiting for CAN response messages...");
    len = can_recv(can_socket, &id, &sm_mac[0]);
    ASSERT( (id == CAN_ATTEST_ID) && (len == CAN_PAYLOAD_SIZE) &&
            "unexpected CAN attestation challenge message format" );

    len = can_recv(can_socket, &id, &sm_mac[CAN_PAYLOAD_SIZE]);
    ASSERT( (id == CAN_ATTEST_ID) && (len == CAN_PAYLOAD_SIZE) &&
            "unexpected CAN attestation challenge message format" );
    dump_hex("SM_MAC", sm_mac, SPONGENT_TAG_SIZE);

    /* ---------------------------------------------------------------------- */
    info_event("comparing expected and received MACs...");

    info("calculating expected MAC...");
    ASSERT( !spongent_mac((void*) key, (uint8_t*) &challenge, sizeof(uint64_t), my_mac) );
    dump_hex("MY_MAC", my_mac, SPONGENT_TAG_SIZE);

    for (i = 0; (i < SPONGENT_TAG_SIZE) && (my_mac[i] == sm_mac[i]); i++);

    if (i >= SPONGENT_TAG_SIZE)
        info("OK   : remote attestation succeeded!");
    else
        info("FAIL : remote attestation failed!");

    /* ---------------------------------------------------------------------- */
    can_close(can_socket);

	return 0;
}
