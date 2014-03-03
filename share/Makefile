
all:
	as entry.S -o entry.o
	ld entry.o -Ttext 0x500 -s -r -o entry.tmp
	objcopy -O binary -j .text entry.tmp entry
	rm -f entry.tmp
	as isr.S -o isr.o
	ld isr.o -Ttext 0x500 -s -r -o isr.tmp
	objcopy -O binary -j .text isr.tmp isr
	rm -f isr.tmp
	as signal.S -o signal.o
	ld signal.o -Ttext 0x500 -s -r -o signal.tmp
	objcopy -O binary -j .text signal.tmp signal
	rm -f signal.tmp

clean:
	rm -f isr entry signal isr.o entry.o signal.o
