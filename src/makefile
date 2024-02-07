# 编译器和选项
CC = g++
CFLAGS = -Wall -Wextra -std=c++11

# 目标文件
TARGET1 = send
TARGET2 = recv
TARGET3 = host


# 源文件
SRCS1 = send.cpp tcp.cpp socket.cpp routing.cpp ip.cpp packetio.cpp device.cpp
SRCS2 = recv.cpp tcp.cpp socket.cpp routing.cpp ip.cpp packetio.cpp device.cpp
SRCS3 = host.cpp tcp.cpp socket.cpp routing.cpp ip.cpp packetio.cpp device.cpp

all: $(TARGET1) $(TARGET2) $(TARGET3)

$(TARGET1): $(SRCS1)
	$(CC) $(CFLAGS) -o $(TARGET1) $(SRCS1) -lpcap

$(TARGET2): $(SRCS2)
	$(CC) $(CFLAGS) -o $(TARGET2) $(SRCS2) -lpcap

$(TARGET3): $(SRCS3)
	$(CC) $(CFLAGS) -o $(TARGET3) $(SRCS3) -lpcap



clean:
	rm -f $(TARGET1) $(TARGET2)
