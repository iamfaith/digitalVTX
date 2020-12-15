
# bring in the helper from the parent / src / HelperSources File
HELPER_FILES := $(wildcard ../../src/HelperSources/*.hpp)

test : test.cpp $(HELPER_FILES)
	g++ -std=c++17 test.cpp UDPReceiver.cpp UDPSender.cpp -o test -lpthread -I Helper/