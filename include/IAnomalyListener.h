#pragma once
#include "FlowDef.h"
#include <string>

class IAnomalyListener {
public:
	virtual ~IAnomalyListener() = default;
	
	//we will call this function on every anomaly detection
	virtual void onAnomalyDetected(const FlowKey& key, double score, const std::string& srcIP, const std::string& dstIP) = 0;
	
	//false positive
	virtual void onFalsePositiveDetected(const FlowKey& key, double score, const std::string& srcIP, const std::string& dstIP) = 0;
};
