# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -g
LDFLAGS = -lpthread -lm

# Source files
SRCS = main.c \
       server.c \
       http.c \
       security.c \
       config.c \
       logger.c

# Object files
OBJS = $(SRCS:.c=.o)

# Output binary
TARGET = secure_server

# Test files
TEST_SRCS = test/test_main.c \
            test/test_http.c \
            test/test_security.c
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_TARGET = run_tests

# Default target
all: setup $(TARGET)

# Build targets
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Build tests
$(TEST_TARGET): $(TEST_OBJS) $(filter-out main.o, $(OBJS))
	$(CC) $(TEST_OBJS) $(filter-out main.o, $(OBJS)) -o $@ $(LDFLAGS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Create necessary directories
setup:
	@mkdir -p logs www

# Clean build files
clean:
	rm -f $(TARGET) $(OBJS) $(TEST_TARGET) $(TEST_OBJS)
	rm -f logs/*

# Run the server
run: all
	./$(TARGET)

# Run tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Install (to /usr/local/bin)
install: all
	install -m 755 $(TARGET) /usr/local/bin/

# Security test targets
test-dos:
	@echo "Testing DoS protection..."
	@for i in $$(seq 1 100); do \
		curl -s http://localhost:8000/ > /dev/null; \
	done

test-injection:
	@echo "Testing SQL injection protection..."
	@curl -s "http://localhost:8000/page?id=1'%20OR%20'1'='1"

test-xss:
	@echo "Testing XSS protection..."
	@curl -s "http://localhost:8000/<script>alert(1)</script>"

test-traversal:
	@echo "Testing path traversal protection..."
	@curl -s "http://localhost:8000/../etc/passwd"

# Generate test files
setup-test-files:
	@echo "Creating test files in www/..."
	@echo "<html><body><h1>Test Page</h1></body></html>" > www/index.html
	@echo "body { background: #eee; }" > www/style.css
	@echo "console.log('test');" > www/script.js

.PHONY: all clean setup run test install test-dos test-injection test-xss test-traversal setup-test-files