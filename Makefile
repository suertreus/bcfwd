.SUFFIXES:
.DEFAULT_GOAL: all
.EXTRA_PREREQS += $(lastword $(MAKEFILE_LIST))
.PHONY: all
all: bcfwd-debug bcfwd bcfwd.tar

bcfwd-debug: bcfwd.cc
	clang++ -o $@ $^ -std=c++26 -Wall -Wextra -pedantic -Wno-deprecated-declarations $(shell pkg-config --cflags --libs absl_str_format absl_strerror)

bcfwd: bcfwd.cc
	aarch64-unknown-linux-musl-g++ -o $@ $^ -std=c++26 -Wall -Wextra -pedantic -Os -static -DNDEBUG=1 -Wa,--gsframe=no -fomit-frame-pointer -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--strip-all -Wl,--discard-all
	aarch64-unknown-linux-musl-strip $@

rootfs.tar: bcfwd
	tar -cf $@ $^

bcfwd.tar: rootfs.tar manifest.json config.json
	tar -cf $@ $^

.PHONY: clean
clean:
	rm -f bcfwd-debug bcfwd rootfs.tar bcfwd.tar

.PHONY: tidy
tidy: bcfwd.cc
	clang-tidy $^ --checks=*,-llvmlibc-*,-llvm-prefer-static-over-anonymous-namespace,-modernize-use-trailing-return-type,-readability-identifier-length,-cppcoreguidelines-avoid-magic-numbers,-readability-magic-numbers

.PHONY: format
format: bcfwd.cc
	diff --unified --color=always bcfwd.cc <(clang-format -style=Google bcfwd.cc)
