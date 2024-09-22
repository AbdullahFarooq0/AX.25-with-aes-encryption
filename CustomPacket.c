#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"

// Define the CRC-16-CCITT polynomial
#define POLY 0x1021

// Define the maximum frame size
#define MAX_FRAME_SIZE 32
#define HEADER_SIZE (1 + 2 + 2 + 2 + 2 + 1) // Start Flag (1) + Opcode (2) + Packet Count (2) + Expected Packet Count (2) + Checksum (2) + End Flag (1)
#define PAYLOAD_SIZE (MAX_FRAME_SIZE - HEADER_SIZE) // Calculate payload size

// Define the packet structure
typedef struct {
    uint8_t start_flag;          // Start flag (0x7E)
    uint16_t opcode;             // Opcode (2 bytes)
    uint16_t packet_count;       // Packet count (2 bytes)
    uint16_t expected_count;     // Expected packet count (2 bytes)
    uint8_t data[PAYLOAD_SIZE];  // Data payload
    uint16_t checksum;           // CRC-16 checksum (2 bytes)
    uint8_t end_flag;            // End flag (0x7E)
} AX25Frame;

// AES key (16 bytes)
static const uint8_t AES_KEY[16] = "your-16-byte-key"; // Replace with your AES key

// Function prototypes
uint16_t calculate_crc(const uint8_t* data, size_t len);
void fragment_data(const uint8_t* data, size_t len, AX25Frame frames[], int* frame_count);
void defragment_data(const AX25Frame frames[], int frame_count, uint8_t* output_data, size_t* output_len);
void print_bytes(const uint8_t* data, size_t len);

// Function to calculate CRC-16-CCITT
uint16_t calculate_crc(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ POLY;
            }
            else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

// Function to fragment data into frames with AES encryption
void fragment_data(const uint8_t* data, size_t len, AX25Frame frames[], int* frame_count) {
    *frame_count = (len + PAYLOAD_SIZE - 1) / PAYLOAD_SIZE; // Calculate number of frames

    struct AES_ctx aes_ctx;
    AES_init_ctx(&aes_ctx, AES_KEY);

    for (int i = 0; i < *frame_count; i++) {
        frames[i].start_flag = 0x7E;                       // Start flag
        frames[i].opcode = 0x1234;                         // Example opcode
        frames[i].packet_count = *frame_count - i;         // Descending packet count
        frames[i].expected_count = *frame_count;           // Expected packet count

        size_t data_len = (i == *frame_count - 1) ? (len % PAYLOAD_SIZE) : PAYLOAD_SIZE; // Last frame size
        if (data_len == 0) data_len = PAYLOAD_SIZE;        // Fix for last frame being exactly PAYLOAD_SIZE bytes

        memcpy(frames[i].data, &data[i * PAYLOAD_SIZE], data_len); // Copy data payload

        if (data_len < PAYLOAD_SIZE) {
            memset(frames[i].data + data_len, 0, PAYLOAD_SIZE - data_len); // Zero out remaining space
        }

        // Print data before encryption
        printf("\nData before encryption (Frame %d):\n", i + 1);
        print_bytes(frames[i].data, PAYLOAD_SIZE);

        // Encrypt the payload
        AES_ECB_encrypt(&aes_ctx, frames[i].data);

        // Print data after encryption
        printf("\nData after encryption (Frame %d):\n", i + 1);
        print_bytes(frames[i].data, PAYLOAD_SIZE);

        // Calculate CRC
        frames[i].checksum = calculate_crc((uint8_t*)&frames[i], HEADER_SIZE - sizeof(frames[i].checksum) - 1);
        frames[i].end_flag = 0x7E; // End flag

        // Print each fragmented frame's data
        printf("\nFrame %d (Total bytes: %d):\n", i + 1, MAX_FRAME_SIZE);
        print_bytes((uint8_t*)&frames[i], MAX_FRAME_SIZE);
    }
}

// Function to defragment frames into original data with AES decryption
void defragment_data(const AX25Frame frames[], int frame_count, uint8_t* output_data, size_t* output_len) {
    struct AES_ctx aes_ctx;
    AES_init_ctx(&aes_ctx, AES_KEY);

    *output_len = 0;
    for (int i = 0; i < frame_count; i++) {
        // Print encrypted data before decryption
        printf("\nData before decryption (Frame %d):\n", i + 1);
        print_bytes(frames[i].data, PAYLOAD_SIZE);

        // Decrypt the payload
        AES_ECB_decrypt(&aes_ctx, frames[i].data); // Decrypt the payload

        // Print data after decryption
        printf("\nData after decryption (Frame %d):\n", i + 1);
        print_bytes(frames[i].data, PAYLOAD_SIZE);

        size_t data_len = (i == frame_count - 1) ? (strlen((const char*)frames[i].data)) : PAYLOAD_SIZE; // Last frame size
        if (data_len > PAYLOAD_SIZE) data_len = PAYLOAD_SIZE; // Limit to PAYLOAD_SIZE bytes

        memcpy(&output_data[*output_len], frames[i].data, data_len);
        *output_len += data_len;
    }
}

// Function to print byte values of data
void print_bytes(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]); // Print each byte as hex
        if ((i + 1) % 16 == 0) printf("\n"); // Break line after 16 bytes
    }
    printf("\n");
}

int main() {
    uint8_t data[] = "a";

    // Print bytes before fragmentation
    printf("Bytes before fragmentation (Total bytes: %ld):\n", sizeof(data) - 1);
    print_bytes(data, sizeof(data) - 1); // Exclude null terminator

    // Fragmentation with AES encryption
    AX25Frame frames[8]; // Adjust based on data length and frame size
    int frame_count = 0;
    fragment_data(data, sizeof(data) - 1, frames, &frame_count); // Exclude null terminator

    // Print fragmented frames
    printf("\nFragmented Frames:\n");
    for (int i = 0; i < frame_count; i++) {
        printf("Frame %d - Packet Count: %d, CRC: %04x\n", i + 1, frames[i].packet_count, frames[i].checksum);
    }

    // Defragmentation with AES decryption
    uint8_t defragmented_data[100]; // Adjusted size
    size_t defragmented_len = 0;
    defragment_data(frames, frame_count, defragmented_data, &defragmented_len);

    // Null-terminate defragmented data
    if (defragmented_len < sizeof(defragmented_data)) {
        defragmented_data[defragmented_len] = '\0'; // Null-terminate
    }
    else {
        defragmented_data[sizeof(defragmented_data) - 1] = '\0'; // Force null-termination
    }

    // Print defragmented data
    printf("\nBytes after defragmentation (Total bytes: %ld):\n", defragmented_len);
    print_bytes(defragmented_data, defragmented_len);

    // Print defragmented data as a string
    printf("\nDefragmented Data:\n%s\n", defragmented_data);

    return 0;
}
