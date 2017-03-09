/*
 * More or less taken from my previous, non-released Rappelz Emulator project
 * Packet structures are based on own .pdb dumps, Pyrok's/NCarbons Rappelz Emulator as well as glandu2's rzauth
 */

#include <cstdint>

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


struct TS_CA_VERSION : public TS_MESSAGE {
	char szVersion[20] = {};
};

struct TS_AC_RESULT : public TS_MESSAGE {
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