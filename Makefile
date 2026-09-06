.SUFFIXES:
.DEFAULT_GOAL: all
.PHONY: all
all: bcfwd-debug bcfwd bcfwd.tar

CC := gcc
STRIP := strip

bcfwd-debug: bcfwd.c
	$(CC) -o $@ $^ -Wall -Wextra -pedantic

bcfwd: bcfwd.c
	$(CC) -o $@ $^ -Wall -Wextra -pedantic -Os -static -DNDEBUG=1 -Wa,--gsframe=no -fomit-frame-pointer -ffunction-sections -fdata-sections -Wl,--gc-sections
	$(STRIP) $@

rootfs.tar: bcfwd
	tar -cf $@ $^

bcfwd.tar: rootfs.tar manifest.json config.json
	tar -cf $@ $^

.PHONY: clean
clean:
	rm -f bcfwd-debug bcfwd rootfs.tar bcfwd.tar
