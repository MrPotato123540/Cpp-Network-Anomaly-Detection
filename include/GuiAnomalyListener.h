#pragma once
#include "FlowDef.h"
#include "IAnomalyListener.h"
#include <vector>
#include <mutex>
#include <string>

struct LogEntry {
	std::string timestamp; 
	std::string srcIP;
	std::string dstIP;
	double score;
	bool isFalsePositive;
};

class GuiAnomalyListener : public IAnomalyListener {
private:
	std::vector<LogEntry> logs;
	std::mutex mtx; //thread-safe

public:
	//call packets from packet's thread
	void onAnomalyDetected(const FlowKey& /*key*/, double score, const std::string& srcIP, const std::string& dstIP) override {
		std::lock_guard<std::mutex> lock(mtx);
		logs.push_back({"Now", srcIP, dstIP, score, false});
	}

	void onFalsePositiveDetected(const FlowKey& /*key*/, double score, const std::string& srcIP, const std::string& dstIP) override {
		std::lock_guard<std::mutex> lock(mtx);
		logs.push_back({"Now", srcIP, dstIP, score, true});
	}

	//it will call from gui thread
	//we take copy of the data because we don't want mutex stay locked too much while GUI is preparing
	std::vector<LogEntry> getLogsSnapshot() {
		std::lock_guard<std::mutex> lock(mtx);
		return logs;
	}

	void clearLogs() {
		std::lock_guard<std::mutex> lock(mtx);
		logs.clear();
	}
};
