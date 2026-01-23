 #pragma once
#include "IPacketSource.h"
#include "pcapplusplus/PcapFileDevice.h"
#include <functional>
#include <iterator>
#include <pcapplusplus/RawPacket.h>
#include <string>
#include <iostream>

//for pcap file's detection
class PcapFileSource : public IPacketSource {
private:
	std::string filename;
	pcpp::PcapFileReaderDevice* reader;

public:
	PcapFileSource(const std::string& file) : filename(file), reader(nullptr) {}

	~PcapFileSource() {
		close();
	}

	void run(std::function<void(pcpp::Packet&)> onPacketArrived) override {
		reader = new pcpp::PcapFileReaderDevice(filename);

		if (!reader->open()) {
			std::cerr << "[ERROR] File could not open: " << filename << std::endl;
		       return;
		}
		
		pcpp::RawPacket rawPacket;

		while (reader->getNextPacket(rawPacket)) {
			pcpp::Packet parsedPacket(&rawPacket);
			//gice packet to PacketReceiver
			onPacketArrived(parsedPacket);
		}
	}

	void close() override {
		if (reader != nullptr) {
			reader->close();
			delete reader;
			reader = nullptr;
		}
	}
};
 
