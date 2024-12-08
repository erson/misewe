# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -lpthread -lm

# System detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS specific settings
    CFLAGS += -I/usr/include -I/usr/local/include
    LDFLAGS += -L/usr/local/lib
endif
ifeq ($(UNAME_S),Linux)
    # Linux specific settings
    CFLAGS += -D_GNU_SOURCE
    LDFLAGS += -lrt
endif

# Source files
SRCS = main.c \
       server.c \
       http.c \
       secure_log.c \
       security_monitor.c \
       request_filter.c

# Object files
OBJS = $(SRCS:.c=.o)

# Output binary
TARGET = secure_server

# Default target
all: $(TARGET)

# Link object files
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build
clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean