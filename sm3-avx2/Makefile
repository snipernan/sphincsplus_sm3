PARAMS = sphincs-sm3-128f
THASH = robust

CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -flto -fomit-frame-pointer -DPARAMS=$(PARAMS) $(EXTRA_CFLAGS)


SOURCES =          hash_sm3.c hash_sm3x8.c thash_sm3_$(THASH).c thash_sm3_$(THASH)x8.c sm3.c sm3x8.c  sm3avx.c address.c randombytes.c merkle.c wots.c utils.c utilsx8.c fors.c sign.c uintx.c
HEADERS = params.h hash.h        hashx8.h        thash.h                 thashx8.h               sm3.h sm3x8.h  sm3avx.h address.h randombytes.h merkle.h wots.h utils.h utilsx8.h fors.h api.h uintx.h

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS = test/fors \
		test/spx \
		test/thashx8 \

BENCHMARK = test/benchmark

.PHONY: clean test benchmark

default: PQCgenKAT_sign

all: PQCgenKAT_sign tests benchmarks

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmarks: $(BENCHMARK)

benchmark: $(BENCHMARK:=.exec)

PQCgenKAT_sign: PQCgenKAT_sign.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

test/%: test/%.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/%.exec: test/%
	@$<

clean:
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARK)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
