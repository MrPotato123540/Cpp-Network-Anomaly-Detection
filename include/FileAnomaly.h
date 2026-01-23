#pragma once
#include "FlowDef.h"
#include "IAnomalyListener.h"
#include <fstream>
#include <iostream>
#include <string>

class FileAnomalyLogger : public IAnomalyListener {
private:
	std::ofstream logFile; //object for writing files
	
public:
	//constructor
	FileAnomalyLogger(const std::string& filename) {
		//open in append mode to not delete anything
		logFile.open(filename, std::ios::out | std::ios::app);

		if (!logFile.is_open()) {
			std::cerr << "Error: Could not open the file: " << filename << std::endl;
		}
	}

	//closes the file while using destructor
	~FileAnomalyLogger() {
		if (logFile.is_open()) {
			logFile.close();
		}
	}

	void onAnomalyDetected(const FlowKey& key, double score, const std::string& srcIP, const std::string& dstIP) override {
		if (logFile.is_open()) {
			logFile << " [ANOMALY] " << "Src: " << srcIP << " -> Dst: " << dstIP << " | Score: " << score << " | Protocol: " << (int)key.protocol << std::endl;

		//to guarantee to write on disk
		logFile.flush();
		}
	}

	void onFalsePositiveDetected(const FlowKey& /*key*/, double score, const std::string& srcIP, const std::string& dstIP) override {
		if (logFile.is_open()) {
			logFile << "[FALSE-POSITIVE] " << "Src: " << srcIP << " -> Dst: " << dstIP << " | Score: " << score << " | (Suppressed by Whitelist)" << std::endl;
			logFile.flush();
		}
	}
};



