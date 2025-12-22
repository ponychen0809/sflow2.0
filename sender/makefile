CXX      := g++
CXXFLAGS := -O2 -std=c++17 -Wall -Wextra
LDFLAGS  :=

TARGETS := l2_bcast l2_mcast l2_ucast

all: $(TARGETS)

l2_bcast: l2_bcast.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

l2_mcast: l2_mcast.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

l2_ucast: l2_ucast.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean
