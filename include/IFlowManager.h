#pragma once
#include "pcapplusplus/Packet.h"
#include "FlowDef.h"
#include <vector>

// this is for dip principle of S.O.L.I.D
// it will indicate what is it doing. But it will not how is doing
class IFlowManager {
public:
	virtual	~IFlowManager() = default;

        //for packet decomposition, key and checking
        virtual void processPacket(pcpp::Packet& packet) = 0;

        //this is for training k-means and z-score
        virtual std::vector<std::vector<double>> getAllFlowFeatures() const = 0;

        //for timeouts
        virtual std::vector<FlowData> checkTimeouts(double currentTime) = 0;

	//snapshot which will control active flows
	virtual std::vector<FlowData> getActiveFlowsSnapshot() const = 0;
};
