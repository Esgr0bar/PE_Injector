# Makefile for PE injector (cross-compilation to Windows x64)

# Cross-compilation tools for Windows targets
NASM       = nasm
WINDRES    = x86_64-w64-mingw32-windres
CC         = x86_64-w64-mingw32-gcc
UPX        = upx

# Compiler flags for x64 Windows
CFLAGS     = -Wall -O2 -DWIN64 -m64
LDFLAGS    = -luser32 -lkernel32 -static-libgcc
NASMFLAGS  = -f win64

# UPX packing options
UPX_FLAGS  = --best --lzma

TARGET     = injector.exe
TARGET_UPX = injector_packed.exe

all: $(TARGET_UPX)

# Use "-f win64" so NASM generates 64-bit Windows code
payload.bin: payload.asm
	$(NASM) $(NASMFLAGS) payload.asm -o payload.bin

# Wrap payload.bin into an RCDATA resource (ID 101) using windres
payload.res: payload.rc payload.bin
	$(WINDRES) payload.rc -O coff -o payload.res

# Compile + link injector.c with the .res for Windows x64
$(TARGET): injector.c payload.res
	$(CC) $(CFLAGS) injector.c payload.res -o $(TARGET) $(LDFLAGS)

# Pack the executable with UPX
$(TARGET_UPX): $(TARGET)
	$(UPX) $(UPX_FLAGS) -o $(TARGET_UPX) $(TARGET)

# Build unpacked version only
unpacked: $(TARGET)

# Pack existing executable with different compression levels
pack-fast: $(TARGET)
	$(UPX) --fast -o injector_fast.exe $(TARGET)

pack-best: $(TARGET)
	$(UPX) --best -o injector_best.exe $(TARGET)

pack-ultra: $(TARGET)
	$(UPX) --ultra-brute -o injector_ultra.exe $(TARGET)

clean:
	-rm -f payload.bin payload.res $(TARGET) $(TARGET_UPX) injector_*.exe

.PHONY: all clean unpacked pack-fast pack-best pack-ultra
