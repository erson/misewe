# Compiler settings
CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -pedantic -std=c11
CFLAGS += -D_FORTIFY_SOURCE=2 -fstack-protector-strong
CFLAGS += -O2 -g
LDFLAGS = -pthread

# Debug flags
DBGFLAGS = -g3 -DDEBUG -fsanitize=address,undefined

# Source files
SRCS = main.c server.c
OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

# Output binary
TARGET = server

# Targets
.PHONY: all clean debug

all: $(TARGET)

debug: CFLAGS += $(DBGFLAGS)
debug: clean $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)