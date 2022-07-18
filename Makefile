# Makefile for CS-212 course - spring 2022
# Author: Jean-Cédric Chappelier & Édouard Bugnion
# Date: Jan 2022

# main targets
# 		all: build the cryptkvs program
# 		style: astyle formatting
# 		doc: documentation


# To run the client and the server, you will need to make sure that
#   mongoose is LD_LIBRARY_PATH export; e.g.:


LIBMONGOOSEDIR = libmongoose/

# Note: builds with address sanitizer by default
TARGETS += lib cryptkvs

CC=gcc

# ======================================================================
# Compiler and Link

# a bit more checks
CFLAGS += -g
CFLAGS += -pedantic -Wall
CFLAGS += -Wextra -Wfloat-equal -Wshadow -Wpointer-arith -Wbad-function-cast -Wwrite-strings \
-Wconversion -Wunreachable-code -Wcast-qual -W -Wformat=2 -Winit-self -Wuninitialized
#CFLAGS += -Wcast-align

LDLIBS += -lm -lssl -lcrypto -lcurl -ljson-c
LDDEPS =

## may require: export ASAN_OPTIONS=allocator_may_return_null=1
#               export ASAN_OPTIONS=verify_asan_link_order=0

CPPFLAGS += -fsanitize=address #-fsanitize=memory #-fsanitize=leak -fsanitize=undefined ### -fsanitize=address
LDFLAGS  += -fsanitize=address
LDLIBS   += -fsanitize=address

# add the debug flag, may need to comment this line when doing make feedback
#CPPFLAGS += -DDEBUG

LDFLAGS += -L$(LIBMONGOOSEDIR)
LDLIBS += -lmongoose -lssl
CFLAGS += -I$(LIBMONGOOSEDIR)

.PHONY: all

all:: $(TARGETS)

SRCS = cryptkvs.c error.c ckvs_utils.c ckvs_local.c ckvs_crypto.c ckvs_io.c ckvs_rpc.c ckvs_client.c ckvs_httpd.c

error.o: error.c #temp fix

OBJS=$(subst .c,.o,$(SRCS))

cryptkvs: $(OBJS) $(LDDEPS)
	make lib
	$(export LD_LIBRARY_PATH="${PWD}/libmongoose")
	$(LINK.o) -o $@ $(OBJS) $(LDLIBS)

lib: $(LIBMONGOOSEDIR)/libmongoose.so

$(LIBMONGOOSEDIR)/libmongoose.so: $(LIBMONGOOSEDIR)/mongoose.c  $(LIBMONGOOSEDIR)/mongoose.h
	make -C $(LIBMONGOOSEDIR)


#########################################################################
# DO NOT EDIT BELOW THIS LINE
#

.PHONY: depend clean new static-check check release doc

# automatically generate the dependencies
# including .h dependencies !

depend: .depend

.depend: $(SRCS)
	bash -c "cat $(foreach SRC,$(SRCS),<($(CC) $(CFLAGS) -I$(LIBMONGOOSEDIR) -MM -MT $(SRC:.c=.o) $(SRC))) > ./.depend"

ifneq ($(MAKECMDGOALS),clean)
-include .depend
endif

clean::
	-@/bin/rm -f *.o *~  .depend $(TARGETS)

new: clean all

static-check:
	CCC_CC=$(CC) scan-build -analyze-headers --status-bugs -maxloop 64 make -j1 new

style:
	astyle -n -o -A8 -xt0 *.[ch]

check:
	make SRC_DIR=$${PWD} -B -C ../provided/tests/unit
##	make -B -C ../tests/fuzzing

## --------------------------------------------------
# target to do all checks before releasing a new version by staff
release: new check style static-check clean

## --------------------------------------------------
# target to make documentation
doc: Doxyfile
	doxygen Doxyfile

## ======================================================================
## Feedback

IMAGE := chappeli/pps22-feedback:latest
## Note: vous pouvez changer le tag latest pour week04, ou week05, etc.

REPO := $(shell git config --get remote.origin.url)
SSH_DIR := $(HOME)/.ssh

.PHONY: feedback feedback-pull feedback-debug feedback-VM-CO feedback-debug-VM-CO clone-ssh clean-fake-ssh

feedback-pull:
	@echo Will use $(REPO) inside container
	@docker pull $(IMAGE)
feedback: feedback-pull
	@docker run -it --rm -e REPO=$(REPO) -v $(SSH_DIR):/opt/.ssh $(IMAGE)
feedback-debug: feedback-pull
	@docker run -it --rm --entrypoint=./debugmode.sh -e REPO=$(REPO) -v $(SSH_DIR):/opt/.ssh $(IMAGE)

clone-ssh:
	@-$(eval SSH_DIR := $(HOME)/.$(shell date "+%s;$$"|sha256sum|cut -c-32))
	@cp -r $(HOME)/.ssh/. $(SSH_DIR)

clean-fake-ssh:
	@case $(SSH_DIR) in $(HOME)/\.????????????????????????????????) $(RM) -fr $(SSH_DIR) ;; *) echo "Dare not remove \"$(SSH_DIR)\"" ;; esac

feedback-VM-CO: clone-ssh feedback clean-fake-ssh

feedback-debug-VM-CO: clone-ssh feedback-debug clean-fake-ssh

## ======================================================================
## Submit

SUBMIT_SCRIPT=../provided/submit.sh

.PHONY: submit1 submit2 submit

submit1: $(SUBMIT_SCRIPT)
	@$(SUBMIT_SCRIPT) 1

submit2: $(SUBMIT_SCRIPT)
	@$(SUBMIT_SCRIPT) 2

submit:
	@printf 'what "make submit"??\nIt'\''s either "make submit1" or "make submit2"...\n'