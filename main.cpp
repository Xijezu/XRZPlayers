#include <iostream>
#include <fstream>
#include <boost/system/error_code.hpp>
#include <asio.hpp>
#include "XRc4Cipher.h"
#include <boost/array.hpp>

// GCC have alternative #pragma pack(N) syntax and old gcc version not support pack(push, N), also any gcc version not support it at some platform
#if defined(__GNUC__)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif
struct TS_MESSAGE {
	uint32_t size;
	uint16_t id;
	uint8_t msg_check_sum;

	inline void SetChecksum() {

		msg_check_sum += size & 0xFF;
		msg_check_sum += (size >> 8) & 0xFF;
		msg_check_sum += (size >> 16) & 0xFF;
		msg_check_sum += (size >> 24) & 0xFF;

		msg_check_sum += id & 0xFF;
		msg_check_sum += (id >> 8) & 0xFF;
	}
	static inline uint8_t GetChecksum(int id, int size) {
		uint8_t value = 0;

		value += size & 0xFF;
		value += (size >> 8) & 0xFF;
		value += (size >> 16) & 0xFF;
		value += (size >> 24) & 0xFF;

		value += id & 0xFF;
		value += (id >> 8) & 0xFF;

		return value;
	}
};


typedef struct TS_CA_VERSION : public TS_MESSAGE {
	char szVersion[20] = {};
}s_Version_CA;

typedef struct TS_AC_RESULT : public TS_MESSAGE {
	uint16_t request_message_id;
	uint16_t result;
	int32_t value;
};

// GCC have alternative #pragma pack() syntax and old gcc version not support pack(pop), also any gcc version not support it at some platform
#if defined(__GNUC__)
#pragma pack()
#else
#pragma pack(pop)
#endif

int main(int argc,  char** argv) {

	std::unique_ptr<XRC4Cipher> ptr_encrypt(new XRC4Cipher), ptr_decrypt(new XRC4Cipher);
	ptr_encrypt->SetKey("}h79q~B%al;k'y $E");
	ptr_decrypt->SetKey("}h79q~B%al;k'y $E");

	s_Version_CA ca;
	ca.id = 10001;
	strcpy(ca.szVersion, "TEST");
	ca.size = 20;


	asio::io_service io_service;
	asio::ip::tcp::socket socket(io_service);

	asio::ip::tcp::endpoint endpoint(
			asio::ip::address::from_string("163.172.51.240"), 6723);

	socket.connect(endpoint);
	if(socket.is_open()) {
		std::cout << "Open, attempt to send packet..." << std::endl;
		auto t = reinterpret_cast<char*>(&ca);
		std::vector<char> buffer(t, t + sizeof(TS_CA_VERSION));
		ptr_encrypt->Encode(&buffer[0], &buffer[0], sizeof(TS_CA_VERSION), false);
		socket.send(asio::buffer(buffer));
		boost::array<char, 2560> buf;
		auto tf = socket.receive(asio::buffer(buf));
		if(tf > 0) {
			std::cout << "Received packet from server!" << std::endl;
			ptr_decrypt->Decode(&buf[0], &buf[0], tf, false);
			TS_AC_RESULT result = *reinterpret_cast<TS_AC_RESULT *>(buf.data());
			std::cout << "request_message_id: " << result.request_message_id<< std::endl;
			std::cout << "result: " << result.result<< std::endl;
			std::cout << "value: " << (result.value ^ 0xADADADAD) << std::endl;

		}
	} else {
		std::cerr << "Cannot establish connection." << std::endl;
	}

	std::cout << "Closing socket and exiting..." << std::endl;

	socket.close();
	io_service.stop();

	return 0;
}