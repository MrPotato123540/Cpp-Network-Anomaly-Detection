#pragma once
#include <cwchar>
#include <unordered_map>
#include <memory>
#include <vector>
#include "FlowDef.h"
#include "IFlowManager.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"

//flows that last longer than 120 seconds or that remain silent for 15 seconds are marked as "completed"
const double FLOW_IDLE_TIMEOUT = 15.0;
const double FLOW_ACTIVE_TIMEOUT = 120.0;

class FlowManager : public IFlowManager  {
private: 
	//hash map for storing all flow
	std::unordered_map<FlowKey, FlowData, FlowKeyHash> activeFlows;
public:
	FlowManager() = default;

	//we will make overrides for dip principle of S.O.L.I.D
	
	//for packet decomposition, key and checking
	void processPacket(pcpp::Packet& packet) override;

	//this is for training k-means and z-score
	std::vector<std::vector<double>> getAllFlowFeatures() const override;

	//for anomaly control
	std::vector<double> getFlowFeature(const FlowKey& key);

	//for timeouts
	std::vector<FlowData> checkTimeouts(double currentTime) override;

	std::vector<FlowData> getActiveFlowsSnapshot() const override;
};

