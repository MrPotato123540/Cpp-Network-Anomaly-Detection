#pragma once
#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <vector>
#include "FlowDef.h"
#include "IPacketSource.h"
#include "IFlowManager.h"
#include "IAnomalyListener.h"
#include "IDetectionStrategy.h"
#include "IFalsePositiveEvaluator.h"

//to store training data and ips
struct TrainingSample {
	FlowKey key;
	std::vector<double> features;	
};

class PacketReceiver {
private:
	IPacketSource& packetSource;
	std::string pcapFileName; //for .pcap file
	IFlowManager& flowManager; //passing reference to save from memory 
	IDetectionStrategy& strategy;
	IFalsePositiveEvaluator* evaluator;

	long packetCounter;
	std::set<std::string> seenIPs;

	long totalFlowsChecked = 0;
	long totalAnomalies = 0;
	long totalFalsePositives = 0;

	//list of listeners
	std::vector<IAnomalyListener*> listeners;

	//will use it to not lose datas after checkTimeouts function
	std::vector<TrainingSample> collectedTrainingSamples;
	
	//to process packet in the flow (DRY principle)
	void processSinglePacket(pcpp::Packet& packet, bool isTraining);

public:
	//which file to read
	PacketReceiver(IPacketSource& source, IFlowManager& manager, IDetectionStrategy& strat) : packetSource(source), flowManager(manager), strategy(strat), evaluator(nullptr), packetCounter(0) {}
	
	//to add evaluator later
	void setEvaluator(IFalsePositiveEvaluator* eval) {
		this->evaluator = eval;
	}

	//to write statistics
	void printStats() const {
		std::cout << " \n Detection Statistics" << std::endl;
		std::cout << "Total Flows Checked: " << totalFlowsChecked << std::endl;
		std::cout << "Total Alerts: " << totalAnomalies << std::endl;
		std::cout << "False Positives (Whitelist): " << totalFalsePositives << std::endl;
		
		if (totalAnomalies + totalFalsePositives > 0) {
			double suppressionRate = ((double)totalFalsePositives / (totalAnomalies + totalFalsePositives)) * 100.0;
			std::cout << "Whitelist Suppression Rate: %" << suppressionRate << std::endl;
		}

		std::cout << "-------------------------------------" << std::endl;

		//calculating final rate for project goal
		//formula = alerts / total flows checked
		double finalRate = 0.0;
		
		//prevent divide by 0
		if (totalFlowsChecked > 0) {
			finalRate = ((double)totalAnomalies / totalFlowsChecked) * 100.0;
		}

		std::cout << "Final Anomaly Rate: %" << finalRate << std::endl;

		//check if we met the target (< 5%)
		std::cout << "Project Target (< %5): ";
		if (finalRate < 5.0) {
			std::cout << "[SUCCESS]" << std::endl;
		} else {
			std::cout << "[FAIL]" << std::endl;
		}
	}
	//add new listener to list
	void addListener(IAnomalyListener* listener) {
		listeners.push_back(listener);
	}
		 
	//notify on anomalies
	void notifyListener(const FlowKey& key, double score, const std::string& srcIP, const std::string& dstIP);

	//read file, train and save model
	void runTrainingMode(const std::string& outputModelFile);

	//load model, read file and search for anomaly
	void runDetectMode(const std::string& inputModelFile);
};
