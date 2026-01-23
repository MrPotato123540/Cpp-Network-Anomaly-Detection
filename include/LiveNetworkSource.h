#pragma once
#include "IPacketSource.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include <functional>
#include <pcapplusplus/RawPacket.h>
#include <string>
#include <iostream>

class LiveNetworkSource : public IPacketSource {
private:
	std::string interfaceName;
	pcpp::PcapLiveDevice* dev;
	
	//volatile to prevent compiler optimization
	//we use it to stop the loop safely
	volatile bool isClosed = false; 

	//we need to save callback to access it in static function
	std::function<void(pcpp::Packet&)> savedCallback;

	//callback wrapper
	static bool onPacketArrivesBlocking(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* /*dev*/, void* cookie) { 

		//we take back class instance which we sent as cookie
		auto* instance = (LiveNetworkSource*) cookie;

		pcpp::Packet parsedPacket(packet);

		//call the saved callback function
		//we access it through instance pointer
		if (instance->savedCallback) {
			instance->savedCallback(parsedPacket);
		}

		//return true stops the capture loop in PcapPlusPlus
		//so if isClosed is true, loop ends
		return instance->isClosed;
	}

public:
	//constructor
	//we will check interface and assign first index as nullptr
	LiveNetworkSource(const std::string& iface) : interfaceName(iface), dev(nullptr) {}

	//destructor to clean up resources properly
	~LiveNetworkSource() {
		if (dev != nullptr) {
			if (dev->captureActive()) {
				dev->stopCapture();
			}
			dev->close();
		}
	}

	void run(std::function<void(pcpp::Packet&)> onPacketArrived) override {
		isClosed = false;
		
		//save callback to member variable
		this->savedCallback = onPacketArrived;

		dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIpOrName(interfaceName);
		if (dev == nullptr) {
			std::cerr << "[ERROR] Could not find interface: " << interfaceName << std::endl;
			return;
		}

		if (!dev->open()) {
			std::cerr << "[ERROR] Could not open the interface (could be due to root)" << std::endl;
			return;
		}

		std::cout << "[INFO] Live Flow: " << interfaceName << "(Ctrl+C for exit)" << std::endl;

		//startCaptureBlockingMode infinitely loops
		//we pass 'this' as cookie to access class members (isClosed) inside static function
		dev->startCaptureBlockingMode(onPacketArrivesBlocking, this, 0);
	}

	void close() override {
		//we just set the flag
		//loop will check this flag in next packet and stop
		isClosed = true;
	}
};
