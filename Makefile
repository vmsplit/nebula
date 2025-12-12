CC        := gcc
AS        := gcc
LD        := ld
OBJCOPY   := objcopy
OBJDUMP   := objdump

OUT       := bin
SRC       := src
INC       := include

TARGET    := $(OUT)/nebula

CFLAGS    := -std=gnu11 -Wall -Wextra -Os \
              -fno-builtin -fno-stack-protector \
              -fno-asynchronous-unwind-tables -fno-unwind-tables \
              -fPIE -ffreestanding -fomit-frame-pointer \
              -fno-plt -fno-jump-tables -mcmodel=tiny \
              -I$(INC)

ASFLAGS   := -fPIE
LDFLAGS   := -T linker.ld -nostdlib -static

OBJS      := $(OUT)/entry.o $(OUT)/nebula.o

.PHONY: all clean dump

all: $(OUT) $(TARGET).bin

$(OUT):
	@mkdir -p $@

$(OUT)/entry.o: $(SRC)/entry.S
	@echo "  AS      $<"
	@$(AS) $(ASFLAGS) -c $< -o $@

$(OUT)/nebula.o: $(SRC)/nebula.c
	@echo "  CC      $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(TARGET).elf: $(OBJS)
	@echo "  LD      $@"
	@$(LD) $(LDFLAGS) $^ -o $@

$(TARGET).bin: $(TARGET).elf
	@echo "  BIN     $@"
	@$(OBJCOPY) -O binary --set-section-flags .bss=alloc,load,contents $< $@
	@echo "  SIZE    $$(stat -c %s $@) bytes"

dump: $(TARGET).elf
	@echo "  OBJDUMP $<"
	@$(OBJDUMP) -d $<

clean:
	@echo "  CLEAN"
	@rm -rf $(OUT)/*.o $(OUT)/*.elf $(OUT)/*.bin
