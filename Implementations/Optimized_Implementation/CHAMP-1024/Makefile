CC ?= gcc
EXTRA_CFLAGS ?=

all: ; $(CC) -std=c99 -O3 -DNDEBUG -Wall -Wextra -pedantic $(EXTRA_CFLAGS) -o KAT KAT_CryptHash.c CryptHash_AlgorithmInstance.c drng.c
