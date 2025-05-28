# Compilers
CXX = g++
CC = gcc

# Flags
CXXFLAGS = -Wall -Wextra -O2 -fpermissive -fsanitize=address
CFLAGS = -Wall -Wextra -O2 -fsanitize=address
LDFLAGS = -luuid -lcrypto -lcbor -ltss2-esys -ltss2-mu -fsanitize=address

# Sources
CPP_SRCS := $(wildcard src/*.cpp)
C_SRCS := ../common/encoding.c $(wildcard ../common/ima_log_lib/src/*.c)

# Objects
CPP_OBJS := $(CPP_SRCS:.cpp=.o)
C_OBJS := $(C_SRCS:.c=.o)
OBJS := $(CPP_OBJS) $(C_OBJS)

# Output
TARGET = app

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Compile C++ source files
src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile C source files (handle ../ paths)
../%.o: ../%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
