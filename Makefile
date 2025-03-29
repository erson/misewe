CC = gcc
CFLAGS = -Wall -Wextra -pedantic -I./include
DEBUG ?= 0

ifeq ($(DEBUG), 1)
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

LDFLAGS = -lpthread

SRC_DIR = src
TEST_DIR = test
OBJ_DIR = obj
BIN_DIR = bin

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_OBJS = $(TEST_SRCS:$(TEST_DIR)/%.c=$(OBJ_DIR)/%.o)

TARGET = $(BIN_DIR)/zircon
TEST_TARGET = $(BIN_DIR)/test_suite

all: setup $(TARGET)

test: setup $(TEST_TARGET)
	@echo "Running tests..."
	@./$(TEST_TARGET)

setup:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR) www

$(TARGET): $(OBJS)
	@echo "Linking $(TARGET)..."
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Build complete: $@"

$(TEST_TARGET): $(TEST_OBJS) $(filter-out $(OBJ_DIR)/main.o, $(OBJS))
	@echo "Linking $(TEST_TARGET)..."
	@$(CC) $^ -o $@ $(LDFLAGS)
	@echo "Test build complete: $@"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(TEST_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning build files..."
	@rm -rf $(OBJ_DIR)/* $(BIN_DIR)/*

install: $(TARGET)
	@echo "Installing to /usr/local/bin (requires sudo)..."
	@sudo cp $(TARGET) /usr/local/bin/
	@sudo mkdir -p /usr/local/share/zircon
	@sudo cp -r www/* /usr/local/share/zircon/
	@echo "Installation complete"

uninstall:
	@echo "Uninstalling (requires sudo)..."
	@sudo rm -f /usr/local/bin/zircon
	@sudo rm -rf /usr/local/share/zircon
	@echo "Uninstallation complete"

distclean: clean
	@echo "Removing all generated files and directories..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR)

help:
	@echo "Available targets:"
	@echo "  all        - Build the server (default)"
	@echo "  test       - Build and run tests"
	@echo "  clean      - Remove object files and binaries"
	@echo "  distclean  - Remove all generated files and directories"
	@echo "  install    - Install to /usr/local/bin (requires sudo)"
	@echo "  uninstall  - Remove from /usr/local/bin (requires sudo)"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  DEBUG=1    - Build with debug symbols and without optimization"

.PHONY: all clean setup test install uninstall distclean help