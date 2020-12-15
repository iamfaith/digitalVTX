HELPER_FILES := $(wildcard Helper/*.cpp Helper/*.hpp)

test : test.cpp $(HELPER_FILES)
	g++ -std=c++17 test.cpp Helper/UDPReceiver.cpp Helper/UDPSender.cpp -o test -lpthread -I Helper/