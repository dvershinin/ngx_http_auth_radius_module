NGX_VER = 1.20.1

NGX_DISTR_BASE_URL = http://nginx.org/download
NGX_DIR = nginx-$(NGX_VER)
NGX_TAR = $(NGX_DIR).tar.gz
NGX_DISTR_URL = $(NGX_DISTR_BASE_URL)/$(NGX_TAR)
DISTR_BASE_PATH = distr
NGX_TAR_PATH = $(DISTR_BASE_PATH)/$(NGX_TAR)
NGX_SRC_PATH = src/nginx

PREFIX = /usr/local/nginx
RUN_PATH = run

WGET = wget
MKDIR = mkdir
TAR = tar
CC ?= cc
PKG_CONFIG ?= pkg-config

TEST_CPPFLAGS = -Itests/include -Isrc $(shell $(PKG_CONFIG) --cflags openssl)
TEST_CFLAGS = -std=gnu99 -Wall -Wextra -Werror -Wno-deprecated-declarations -g
TEST_LDLIBS = $(shell $(PKG_CONFIG) --libs openssl)
TEST_SOURCES = tests/radius_lib_test.c src/radius_lib.c

ifneq "$(NB)" "1"
GDB_BREAK = $(addprefix -ex 'b ,$(addsuffix ',$B))
endif

GDB_FLAGS = -ex "set breakpoint pending on" \
			-ex "set follow-fork-mode child" \
			-ex "handle SIGPIPE nostop" \
			-ex "handle SIGHUP nostop" \
			-ex "set detach-on-fork on" \
			-ex "break ngx_http_auth_radius_handler"
GDB_RUN = -ex r

.PHONY: src clean getsrc debug run test test-asan lint

all: build

getsrc:
	[ -d $(DISTR_BASE_PATH) ] || $(MKDIR) -p $(DISTR_BASE_PATH)
	[ -f $(NGX_TAR_PATH) ] || $(WGET) $(NGX_DISTR_URL) -O $(NGX_TAR_PATH)

src:
	@if test -d $(NGX_SRC_PATH); then \
		echo "source dir \"$(NGX_SRC_PATH)\" exists!"; \
	else \
		$(MKDIR) -p $(NGX_SRC_PATH); \
		$(TAR) xzf $(NGX_TAR_PATH) --strip-components=1 -C $(NGX_SRC_PATH); \
	fi

build:
	@if test ! -d $(NGX_SRC_PATH); then \
		echo -e "source dir \"$(NGX_SRC_PATH)\" not exists.\nTry: make getsrc && make src"; exit 1; \
	fi
	cd $(NGX_SRC_PATH) \
		&& make

build_all:
	@if test ! -d $(NGX_SRC_PATH); then \
		echo -e "source dir \"$(NGX_SRC_PATH)\" not exists.\nTry: make getsrc && make src"; exit 1; \
	fi
	cd $(NGX_SRC_PATH) \
		&& CFLAGS="-g -O0 -W -Wall -Wno-unused-parameter -Werror" ./configure \
			--add-module=../.. \
			--with-debug \
		&& $(MAKE)

install:
	cd $(NGX_SRC_PATH) && $(MAKE) install

runenv:
	mkdir -p $(RUN_PATH)/logs

run: runenv
	cd $(RUN_PATH) && \
		../$(NGX_SRC_PATH)/objs/nginx -p . -c ../conf/nginx.conf

test:
	mkdir -p .build
	$(CC) $(TEST_CPPFLAGS) $(TEST_CFLAGS) $(TEST_SOURCES) \
		$(TEST_LDLIBS) -o .build/radius_lib_test
	.build/radius_lib_test

test-asan:
	mkdir -p .build
	$(CC) $(TEST_CPPFLAGS) $(TEST_CFLAGS) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		$(TEST_SOURCES) $(TEST_LDLIBS) -fsanitize=address,undefined \
		-o .build/radius_lib_test_asan
	ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		.build/radius_lib_test_asan

lint:
	cppcheck --enable=warning,portability,performance \
		--check-level=exhaustive --error-exitcode=1 \
		--suppressions-list=.cppcheck-suppressions --std=c99 \
		-I tests/include -I src src/radius_lib.c

gdb: runenv
	cd $(RUN_PATH) && \
		gdb $(GDB_FLAGS) $(GDB_BREAK) $(GDB_RUN) --args \
		../$(NGX_SRC_PATH)/objs/nginx -p . -c ../conf/nginx.conf

clean:
	rm -rf $(NGX_SRC_PATH) $(RUN_PATH) .build tags

clean_all: clean
	rm -rf $(DISTR_BASE_PATH)
