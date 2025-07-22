#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XOR_KEY 0xAB  // Simple XOR key

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    FILE* in = fopen(argv[1], "rb");
    if (!in) {
        printf("Error: Cannot open input file %s\n", argv[1]);
        return 1;
    }

    FILE* out = fopen(argv[2], "wb");
    if (!out) {
        printf("Error: Cannot create output file %s\n", argv[2]);
        fclose(in);
        return 1;
    }

    // Get file size
    fseek(in, 0, SEEK_END);
    long size = ftell(in);
    fseek(in, 0, SEEK_SET);

    printf("Encoding %ld bytes with XOR key 0x%02X\n", size, XOR_KEY);

    // XOR encode the file
    for (long i = 0; i < size; i++) {
        int byte = fgetc(in);
        if (byte == EOF) break;
        byte ^= XOR_KEY;
        fputc(byte, out);
    }

    fclose(in);
    fclose(out);

    printf("Encoded file saved as %s\n", argv[2]);
    return 0;
}