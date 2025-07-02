# Makefile pour injector (Windows x64)

NASM       = nasm
RC         = rc
CC         = cl
LINK       = link

# Compiler flags for x64
CFLAGS     = /W4 /O2 /MT /DWIN64 user32.lib
LDFLAGS    = /SUBSYSTEM:CONSOLE /MACHINE:X64

RESFLAGS   = /fo
TARGET     = injector.exe

all: $(TARGET)

#    Use "-f win64" so NASM generates 64-bit code, not flat DOS .COM
payload.bin: payload.asm
	$(NASM) -f win64 payload.asm -o payload.bin

#  Wrap payload.bin into an RCDATA resource (ID 101)
payload.res: payload.rc payload.bin
	$(RC) $(RESFLAGS) payload.res payload.rc

#  Compile + link injector.c with the .res
#    We pass /DWIN64 so your code can #ifdef any 64-bit only branches if needed
$(TARGET): injector.c payload.res
	$(CC) $(CFLAGS) injector.c payload.res /link $(LDFLAGS)

clean:
	-@if exist payload.bin del payload.bin
	-@if exist payload.res del payload.res
	-@if exist injector.obj del injector.obj
	-@if exist injector.exe del injector.exe

.PHONY: all clean
