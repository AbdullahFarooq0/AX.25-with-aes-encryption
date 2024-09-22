#ifndef CUSTOMPACKET_H
#define CUSTOMPACKET_H

#include <stdint.h>

#define START_FLAG 0x7E
#define END_FLAG 0x7E

typedef struct {
    uint8_t startFlag;
    uint16_t opcode;
    uint16_t packetCount;
    uint16_t expectedPacketCount;
    uint8_t dataField[22];
    uint16_t checksum;
    uint8_t endFlag;
} CustomPacket;

#endif // CUSTOMPACKET_H
