# Makefile

CC = gcc
CFLAGS = -Wall -Wextra 
LDFLAGS = -lssl -lcrypto -fsanitize=address -ltss2-esys -ltss2-mu -lcbor -lcurl 

AGENT_SRC = agent.c devid.c
VERIFY_SRC = $(wildcard ../common/ima_log_lib/src/*.c)
COMMON_SRC = $(wildcard ../common/*.c)
OBJS = $(AGENT_SRC) $(VERIFY_SRC) $(COMMON_SRC)

TARGET = agent

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

clean:
	rm -f $(TARGET)
