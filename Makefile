CXX      ?= g++
CXXFLAGS ?= -O3 -Wall -Wextra
LIBTOOL ?= libtool

ENABLE_VM         ?= 0
ENABLE_PERF_TESTS ?= 0

ifeq ($(ENABLE_VM),1)
_options += -DRE2JIT_VM
endif

ifeq ($(ENABLE_PERF_TESTS),1)
_testopt += -DRE2JIT_DO_PERF_TESTS
endif

_require_vendor = \
	re2/obj/libre2.a \
	libjit/jit/libjit.la


_require_headers = \
	re2/.git       \
	re2jit/it.h    \


_require_objects = \
	obj/it.lo       \


_require_library = \
	obj/libre2jit.la


_require_test_run =     \
	test/10-literal     \
	test/11-anchoring   \
	test/12-branching   \
	test/13-exponential \
	test/20-submatching \
	test/30-long        \
	test/31-unicode


ARCHIVE = $(LIBTOOL) --mode=link $(CXX) $(CXXFLAGS) -o
INSTALL = $(LIBTOOL) --mode=install install -D
PYTHON3 = /usr/bin/python3
CCFLAGS = ./ccflags
DYNLINK = $(LIBTOOL) --mode=link $(CXX) $(CXXFLAGS) -shared -o
INCLUDEOPTS = -I. -I./libjit/include -I./re2
COMPILE = $(LIBTOOL) --mode=compile $(CXX) $(CXXFLAGS) $(_options) -std=c++11 $(INCLUDEOPTS)
CMPTEST = $(LIBTOOL) --mode=link $(CXX) $(CXXFLAGS) $(_testopt) -std=c++11 $(INCLUDEOPTS) -pthread


.PHONY: all clean test test/%
.PRECIOUS: \
	obj/%.o \
	obj/libre2jit.a \
	obj/libre2jit.so \
	obj/test/%


test: $(_require_test_run)
test/%: ./obj/test/%; ./$<


clean:
	rm -rf obj


re2/.git: .gitmodules
	git submodule update --init re2

libjit/.git: .gitmodules
	git submodule update --init libjit


re2/obj/libre2.a: re2/.git .git/modules/re2/refs/heads/master
	$(MAKE) -C re2 obj/libre2.a

libjit/jit/libjit.la: libjit/.git .git/modules/libjit/refs/heads/master
	$(MAKE) -C libjit jit/libjit.la


obj/libre2jit.la: $(_require_objects)
	$(ARCHIVE) $@ $^


obj/libre2jit.so: $(_require_objects)
	$(DYNLINK) $@ $^


obj/it.lo: re2jit/it.cc re2jit/it.vm.cc re2jit/it.x64.cc $(_require_headers)
	@mkdir -p $(dir $@)
	$(COMPILE) -c -o $@ $<


obj/%.lo: re2jit/%.cc $(_require_headers)
	@mkdir -p $(dir $@)
	$(COMPILE) -c -o $@ $<


obj/test/%: test/%.cc test/%.h test/framework.cc $(_require_library) $(_require_vendor)
	@mkdir -p $(dir $@)
	$(CMPTEST) -DTEST=$< -DTESTH=$(basename $<).h -o $@ test/framework.cc `$(CCFLAGS) $(basename $<).h` obj/libre2jit.la re2/obj/libre2.a
