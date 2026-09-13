.SUFFIXES:
.DEFAULT_GOAL: all
.EXTRA_PREREQS += $(lastword $(MAKEFILE_LIST))
.PHONY: all
all: bcfwd-debug bcfwd bcfwd.tar

CXX_DEBUG := clang++
CXX := aarch64-unknown-linux-musl-g++
CXXFLAGS_COMMON := -std=c++26 -Wall -Wextra -pedantic
CXXFLAGS_DEBUG := -Wno-deprecated-declarations
CXXFLAGS := -Os -static -DNDEBUG=1

TIDY_CHECKS := *
TIDY_CHECKS += -llvmlibc-* -llvm-prefer-static-over-anonymous-namespace
TIDY_CHECKS += -modernize-use-trailing-return-type
TIDY_CHECKS += -readability-identifier-length
TIDY_CHECKS += -cppcoreguidelines-avoid-magic-numbers -readability-magic-numbers
TIDY_CHECKS += -cppcoreguidelines-pro-bounds-avoid-unchecked-container-access
TIDY_CHECKS += -readability-uppercase-literal-suffix -hicpp-uppercase-literal-suffix
TIDY_CHECKS += -altera-struct-pack-align -altera-unroll-loops -altera-id-dependent-backward-branch
TIDY_CHECKS += -fuchsia-statically-constructed-objects -cppcoreguidelines-avoid-non-const-global-variables
TIDY_CHECKS += -readability-function-cognitive-complexity
TIDY_CHECKS += -llvm-header-guard -misc-include-cleaner
TIDY_CHECKS += -cppcoreguidelines-pro-type-member-init -hicpp-member-init -cppcoreguidelines-init-variables
TIDY_CHECKS += -fuchsia-default-arguments-calls -fuchsia-overloaded-operator
TIDY_CHECKS += -bugprone-easily-swappable-parameters

bcfwd-debug: bcfwd.cc
	$(CXX_DEBUG) -o $@ $^ $(CXXFLAGS_COMMON) $(CXXFLAGS_DEBUG) $(shell pkg-config --cflags --libs absl_str_format absl_strerror)

bcfwd: bcfwd.cc
	$(CXX) -o $@ $^ $(CXXFLAGS_COMMON) $(CXXFLAGS)
	aarch64-unknown-linux-musl-strip $@

rootfs.tar: bcfwd
	tar -cf $@ $^

bcfwd.tar: rootfs.tar manifest.json config.json
	tar -cf $@ $^

.PHONY: clean
clean:
	rm -f bcfwd-debug bcfwd rootfs.tar bcfwd.tar

COMMA = ,
EMPTY =
SPACE = $(EMPTY) $(EMPTY)
.PHONY: tidy
tidy: bcfwd.cc
	clang-tidy $^ --checks=$(subst $(SPACE),$(COMMA),$(TIDY_CHECKS)) -- $(CXXFLAGS_COMMON) $(CXXFLAGS_DEBUG)

.PHONY: format
format: bcfwd.cc
	diff --unified --color=always bcfwd.cc <(clang-format -style=Google bcfwd.cc)
