#pragma once
#include "FlowDef.h"
#include "IAnomalyListener.h"
#include <iostream>
#include <iterator>
#include <string>

class ConsoleAnomalyLogger : public IAnomalyListener {
public:
	//it will take all of this info from the notifyListener on PacketReceiver.h
	void onAnomalyDetected(const FlowKey& /*key*/ /* for disabling not used notification */, double score, const std::string& srcIP, const std::string& dstIP) override {
		std::cout << "[WARN] Anomaly Detected" << srcIP << " -> " << dstIP << " Score: " << score << std::endl;
	}

	void onFalsePositiveDetected(const FlowKey& /*key*/, double score, const std::string& srcIP, const std::string& dstIP) override {
		std::cout << "[FALSE-POSITIVE] Suppressed: " << srcIP << " -> " << dstIP << " (Known Benign) Score: " << score << std::endl;
	}
};
