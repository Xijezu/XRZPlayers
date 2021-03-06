#include "XRc4Cipher.h"
#include "Packets.hpp"

// Boost stuff
#include <boost/system/error_code.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>

#include <iostream>

int main(int argc, char **argv)
{

	// Making sure the args are there
	if (argc != 3)
	{
		std::cout << "You're missing the IP and port:" << std::endl;
		std::cout << "XRZPlayers [IP] [PORT]" << std::endl;
		return 0;
	}

	/* We need a separate Cipher class for encryption and decryption
	 * because the index differs (e.g. if you encrypted a packet with a length of 20
	 * the current index would be at 20, making decryption useless. The game server uses
	 * 2 separate classes, too. Yes, I suck at explaining.
	*/
	std::unique_ptr<XRC4Cipher> ptr_encrypt{new XRC4Cipher}, ptr_decrypt{new XRC4Cipher};
	ptr_encrypt->SetKey("}h79q~B%al;k'y $E");
	ptr_decrypt->SetKey("}h79q~B%al;k'y $E");

	// Creating a TS_CA_VERSION packet
	TS_CA_VERSION pktVersion;
	pktVersion.id = 50; // the ID of the packet is 10001
	strcpy(pktVersion.szVersion, "TEST");
	pktVersion.size = 20; // Size is always 20. I honestly can't remember if the header counts to that, too,
						  // but in this case I used the size of the inner packet. Works with glandu2's auth.

	// Initializing our network stuff
	boost::asio::io_service io_service;
	boost::asio::ip::tcp::socket socket{io_service};
	// Create an endpoint: address & port taken from args
	boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(argv[1]), (uint16_t)atoi(argv[2]));

	try
	{
		// Connect to the endpoint
		socket.connect(endpoint);
	}
	catch (std::system_error ex)
	{
		std::cerr << "Error in " << __FILE__ << ":" << __LINE__ << ": socket.connect(endpoint);" << std::endl;
		std::cerr << "Probably not connected. Error message:" << std::endl;
		std::cerr << ex.what() << std::endl;
		return 0;
	}

	if (socket.is_open())
	{

		std::cout << "Open, attempting to send packet..." << std::endl;
		// Don't mind the casting here, that's the easiest way to do stuff
		// We need to cast the struct itself into a char ptr so it'll be usable
		// as a buffer
		auto pktArray = reinterpret_cast<char *>(&pktVersion);
		// Encode the packet
		ptr_encrypt->Encode(pktArray, pktArray, sizeof(TS_CA_VERSION), false);
		// And finally send it
		socket.send(boost::asio::buffer(pktArray, sizeof(TS_CA_VERSION)));

		// Now we're creating a buffer for the response
		boost::array<char, 1024> bufResponse;
		size_t nReceived{0};
		try
		{
			nReceived = socket.receive(boost::asio::buffer(bufResponse));
		}
		catch (std::system_error ex)
		{
			std::cerr << "Error in " << __FILE__ << ":" << __LINE__ << ": socket.receive()" << std::endl;
			std::cerr << "Probably not using glandu2's auth emu. Error message:" << std::endl;
			std::cerr << ex.what() << std::endl;
			return 0;
		}
		// Now, nReceived contains the length of the array we just received.
		// So if there was a response (if the length is greater than zero) we try to process it
		if (nReceived > 0)
		{
			std::cout << "Received packet from server!" << std::endl;
			// Decrypting the response. Btw, don't mind the uint-cast there, just wanna get rid of
			// the warning
			ptr_decrypt->Decode(&bufResponse[0], &bufResponse[0], (uint32_t)nReceived, false);
			// Casting the result as packet
			TS_AC_RESULT result = *reinterpret_cast<TS_AC_RESULT *>(bufResponse.data());
			/* And finally giving the output.
			 * When you set the szVersion of the version packet to "TEST" it returns the amount of people
			 * online on the server.
			 * When you set it to INFO it gives you the version of the auth server.
			 * NOTE: This only works on glandu2's rzauth emulator!
			 */
			std::cout << "request_message_id: " << result.request_message_id << std::endl;
			std::cout << "result: " << result.result << std::endl;
			// We need to xor it back to the actual value - glandu2 "encrypted" it.
			std::cout << "value: " << (result.value ^ 0xADADADAD) << std::endl;
		}
	}
	else
	{
		std::cerr << "Cannot establish connection." << std::endl;
	}

	std::cout << "Closing socket and exiting..." << std::endl;

	// Closing all the stuff
	socket.close();
	io_service.stop();

	return 0;
}
