#pragma once
#include "pcapplusplus/Packet.h"
#include <functional>

//we seperate this part for isp and dip principle of solid
class IPacketSource {
public:
	virtual ~IPacketSource() = default;

	//this will start flow
	//and call callback function in every packet
	virtual void run(std::function<void(pcpp::Packet&)> onPacketArrived) = 0;

	virtual void close() = 0;
};
