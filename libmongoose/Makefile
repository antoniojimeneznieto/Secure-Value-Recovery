#
# Makefile to create local libmongoose
# Author: J.-C. Chappelier & E. Bugnion
#

CC       = gcc
#CC       = clang
CPPFLAGS =

CFLAGS += -DMG_ENABLE_OPENSSL=1 -DSSL=OPENSSL
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	CFLAGS += -DLINUX -D_XOPEN_SOURCE=500
endif
ifeq ($(UNAME_S),Darwin)
	CFLAGS += -DOSX -I/usr/local/opt/openssl/include/
endif

CFLAGS   += -std=c99
##CFLAGS   += -g
CFLAGS   += -pedantic -Wall -Wextra -Wfloat-equal -Wshadow \
-Wpointer-arith -Wbad-function-cast -Wcast-align  \
-Wwrite-strings -Wconversion -Wunreachable-code -Winit-self -Wuninitialized
##CFLAGS   += -Wcast-qual
CFLAGS   += -fPIC
RM       = /bin/rm -f

TARGETS = libmongoose.so
OBJS = *.o
RUBS = $(OBJS) *~ core

all:: $(TARGETS)
	@echo All done.

libmongoose.so: mongoose.o
	$(CC) -shared -o $@ $^

clean:
	-@$(RM) $(RUBS)
	@echo Cleaned.

new: mrproper all

mrproper: clean
	-@$(RM) $(TARGETS)
