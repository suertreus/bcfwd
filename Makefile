.SUFFIXES:
.DEFAULT_GOAL: all
.PHONY: all
all: bcfwd-debug bcfwd bcfwd.tar

bcfwd-debug: bcfwd.c
	$(CC) -o $@ $^ -Wall -Wextra -pedantic

bcfwd: bcfwd.c
	aarch64-unknown-linux-musl-gcc -o $@ $^ -Wall -Wextra -pedantic -Os -static -DNDEBUG=1 -Wa,--gsframe=no -fomit-frame-pointer -ffunction-sections -fdata-sections -Wl,--gc-sections
	aarch64-unknown-linux-musl-strip $@

rootfs.tar: bcfwd
	tar -cf $@ $^

bcfwd.tar: rootfs.tar manifest.json config.json
	tar -cf $@ $^

.PHONY: clean
clean:
	rm -f bcfwd-debug bcfwd rootfs.tar bcfwd.tar
