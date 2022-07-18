# ======================================================================
# Useful for feedback

CC = clang

TARGETS := utils stats
TARGETS += ios crypto get
TARGETS += set
TARGETS += new

EXECS=$(foreach name,$(TARGETS),unit-test-$(name))

.PHONY: unit-tests all $(TARGETS) execs

# first creates all exec, **then** launch them
all: execs unit-tests
	echo $(EXECS)

unit-tests: $(TARGETS)

execs: $(EXECS)

# some target shortcuts : compile & run the tests
utils: unit-test-utils
	./unit-test-utils
stats: unit-test-stats
	./unit-test-stats
ios: unit-test-ios
	./unit-test-ios
crypto: unit-test-crypto
	./unit-test-crypto
get: unit-test-get
	./unit-test-get
set: unit-test-set
	./unit-test-set
new: unit-test-new
	./unit-test-new

# ======================================================================
SRC_DIR ?=../../done
CFLAGS  += -I$(SRC_DIR) -DCS212_TEST
LDFLAGS += -L$(SRC_DIR)
LDLIBS  += -lm -lssl -lcrypto -lcurl -ljson-c

CFLAGS  += -fsanitize=address
LDFLAGS += -fsanitize=address
LDLIBS  += -fsanitize=address

ckvs_test_util.o: ckvs_test_util.c

unit-test-utils.o: unit-test-utils.c
unit-test-utils: LDLIBS += -lcheck -lm -lrt -pthread -lsubunit
unit-test-utils: unit-test-utils.o ckvs_test_util.o \
   $(SRC_DIR)/error.o $(SRC_DIR)/ckvs_utils.o

unit-test-crypto.o: unit-test-crypto.c
unit-test-crypto: LDLIBS += -lcheck -lm -lrt -pthread -lsubunit
unit-test-crypto: unit-test-crypto.o ckvs_test_util.o \
   $(SRC_DIR)/error.o $(SRC_DIR)/ckvs_utils.o $(SRC_DIR)/ckvs_crypto.o

unit-test-ios.o: unit-test-ios.c
unit-test-ios: LDLIBS += -lcheck -lm -lrt -pthread -lsubunit
unit-test-ios: unit-test-ios.o ckvs_test_util.o \
   $(SRC_DIR)/error.o $(SRC_DIR)/ckvs_utils.o $(SRC_DIR)/ckvs_io.o

unit-test-stats.o: unit-test-stats.c
unit-test-stats: LDLIBS += -lcheck -lm -lrt -pthread -lsubunit
unit-test-stats: unit-test-stats.o ckvs_test_util.o \
   $(SRC_DIR)/error.o $(SRC_DIR)/ckvs_utils.o $(SRC_DIR)/ckvs_crypto.o $(SRC_DIR)/ckvs_io.o $(SRC_DIR)/ckvs_local.o

unit-test-get.o: unit-test-get.c
unit-test-get: LDLIBS += -lcheck -lm -lrt -pthread -lsubunit
unit-test-get: unit-test-get.o ckvs_test_util.o \
   $(SRC_DIR)/error.o $(SRC_DIR)/ckvs_utils.o $(SRC_DIR)/ckvs_crypto.o $(SRC_DIR)/ckvs_io.o $(SRC_DIR)/ckvs_local.o

unit-test-set.o: unit-test-set.c
unit-test-set: LDLIBS += -lcheck -lm -lrt -pthread -lsubunit
unit-test-set: unit-test-set.o ckvs_test_util.o \
   $(SRC_DIR)/error.o $(SRC_DIR)/ckvs_utils.o $(SRC_DIR)/ckvs_crypto.o $(SRC_DIR)/ckvs_io.o $(SRC_DIR)/ckvs_local.o

unit-test-new.o: unit-test-new.c
unit-test-new: LDLIBS += -lcheck -lm -lrt -pthread -lsubunit
unit-test-new: unit-test-new.o ckvs_test_util.o \
   $(SRC_DIR)/error.o $(SRC_DIR)/ckvs_utils.o $(SRC_DIR)/ckvs_crypto.o $(SRC_DIR)/ckvs_io.o $(SRC_DIR)/ckvs_local.o

# ======================================================================
.PHONY: clean dist-clean reset

clean::
	-$(RM) *.o *~

dist-clean: clean
	-$(RM) $(foreach T,$(TARGETS),unit-test-$(T))

reset: dist-clean all