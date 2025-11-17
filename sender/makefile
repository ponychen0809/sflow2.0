# 指定編譯器
CXX = g++
# 指定編譯選項
CXXFLAGS = -std=c++11 -Wall -g
# 指定目標檔案名稱
TARGET = udp_sender

# 預設目標
all: $(TARGET)

# 編譯 main.cpp 生成可執行檔
$(TARGET): udp_sender.cpp
	$(CXX) $(CXXFLAGS) -o $(TARGET) udp_sender.cpp

# 清理編譯過程中產生的檔案
clean:
	rm -f $(TARGET)

# 如果沒有參數，執行 make 時會執行 all，使用 clean 時清除檔案
.PHONY: all clean
