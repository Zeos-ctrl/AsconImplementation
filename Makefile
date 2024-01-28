# Compiler and flags
CC = gcc
CFLAGS = -Wall -O2

# Program source files
SRC_MAIN = src/Ascon.c

# Program executable name
TARGET_MAIN = Main

all: $(TARGET_MAIN)

$(TARGET_MAIN): $(SRC_MAIN)
	$(CC) $(CFLAGS) -o $(TARGET_MAIN) $(SRC_MAIN)

clean:
	rm -f $(TARGET_MAIN)
