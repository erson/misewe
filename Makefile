# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include
LDFLAGS = -lpthread

# Directories
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TARGET = $(BIN_DIR)/secure_server

# Default target
all: setup $(TARGET)

# Create necessary directories
setup:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR) www logs

# Link the final binary
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build files
clean:
	rm -rf $(OBJ_DIR)/* $(BIN_DIR)/*

# Run the server
run: all
	./$(BIN_DIR)/secure_server

.PHONY: all clean setup run