# Makefile for compiling UDP packet listener using pcap library

# 編譯器設置
CXX = g++
CXXFLAGS = -Wall -std=c++11

# 程式名稱
TARGET = receiver

# 來源程式
SRCS = receiver.cpp

# 目標物件檔案
OBJS = $(SRCS:.cpp=.o)

# 依賴庫
LIBS = -lpcap

# 編譯規則
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LIBS)

# 物件檔案編譯規則
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

# 清理編譯產物
clean:
	rm -f $(TARGET) $(OBJS)

# 執行程式
run: $(TARGET)
	sudo ./$(TARGET) enp2s0
