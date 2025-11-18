# Makefile for UDP Listener program

# 編譯器設定
CXX = g++
CXXFLAGS = -Wall -std=c++11

# 程式名稱
TARGET = receiver

# 來源程式
SRCS = receiver.cpp

# 目標檔案
OBJS = $(SRCS:.cpp=.o)

# 編譯與連結規則
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS)

# 目標檔案編譯規則
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

# 清除編譯產物
clean:
	rm -f $(TARGET) $(OBJS)

# 執行程序
run: $(TARGET)
	sudo ./$(TARGET)
