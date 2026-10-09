CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=gnu11 -Iinclude
LDFLAGS ?=

SRCS := $(shell find src -name '*.c')
OBJS := $(SRCS:.c=.o)
BIN  := reconpulse

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

ifeq ($(UNAME_S),Linux)
    LDFLAGS += -lpthread
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -lpthread
endif
ifneq (,$(findstring MINGW,$(UNAME_S))$(findstring Windows,$(UNAME_S)))
    LDFLAGS += -lws2_32 -liphlpapi -lwinpthread
    BIN := reconpulse.exe
endif

.PHONY: all clean run embed
all: $(BIN)

# Regenerates src/web/dashboard_html_gen.c from web/index.html. Only needed
# after editing the dashboard; the generated file is checked in so a plain
# `make` never requires xxd.
embed:
	cd web && xxd -i index.html > ../src/web/dashboard_html_gen.c

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(BIN)

run: all
	./$(BIN) --help
