CC = gcc
CFLAGS = -Wall -g

TARGET = sdb
SRC = sdb.c

all: clean $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -lcapstone -lelf

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
