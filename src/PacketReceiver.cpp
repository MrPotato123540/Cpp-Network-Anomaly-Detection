#include "PacketReceiver.h"
#include "FlowDef.h"
#include <iostream>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>
#include <set>
#include <pcapplusplus/IpAddress.h>
#include "pcapplusplus/IPv4Layer.h"

//notify function from header file
//notify all anomalies
void PacketReceiver::notifyListener(const FlowKey& key,  double score, const std::string& srcIP, const std::string& dstIP) {
	for (auto listener : listeners) {
		listener->onAnomalyDetected(key, score, srcIP, dstIP);
	}
}

void PacketReceiver::processSinglePacket(pcpp::Packet& packet, bool isTraining) {
	
	/*if (packet.isPacketOfType(pcpp::IPv4)) {
		std::cout << "IPv4" << std::flush;
	}*/


	//this code takes struct timeval
	//which stores the time in tv_sec and tv_usec
        //tv_sec = takes the time from January 1st 1970 00:00:00
        //tv_nsec = nanoseconds and reset in every 1000000
        //1e-9 = 1 x 10^(-9)
       	//which will takes us the decimal places		
	double timestamp = packet.getRawPacket()->getPacketTimeStamp().tv_sec + (packet.getRawPacket()->getPacketTimeStamp().tv_nsec * 1e-9);

	//sends it to flowManager
	flowManager.processPacket(packet);
	packetCounter++;

	//it will control in every 1000 iteration for performance
	if (packetCounter % 1000 == 0) {
			
		//timeout check
		std::vector<FlowData> expiredFlows = flowManager.checkTimeouts(timestamp);
		
		if (!isTraining) {
			//check anomalies in expired flows
			for (const auto& flow : expiredFlows) {
				//statistics
				totalFlowsChecked++;

				//features in them
				std::vector<double> features = flow.toFeatureVector();
				double anomalyScore = strategy.detect(features);

				if (anomalyScore > 0.0) {
					//in first design, it was giving output in there
					//but for adding observer pattern and not break srp principle of S.O.L.I.D
					//added this part
					
					//change IP addresses to string for the output 
					std::string srcIP = pcpp::IPv4Address(flow.key.srcIP).toString();
					std::string dstIP = pcpp::IPv4Address(flow.key.dstIP).toString();
					
					//statistics for false positive
					bool isFP = false;
					if (evaluator != nullptr) {
						isFP = evaluator->isKnownBenign(flow.key);
					}

					if (isFP) {
						//if it is in whitelist, mark it as FP
						totalFalsePositives++;

						//fp to listener
						for (auto listener : listeners) {
							listener->onFalsePositiveDetected(flow.key, anomalyScore, srcIP, dstIP);
						}
					} else {
						//if there is no whitelist
						totalAnomalies++;
						notifyListener(flow.key, anomalyScore, srcIP, dstIP);
					}
				}
			}

			std::vector<FlowData> activeFlows = flowManager.getActiveFlowsSnapshot();
			for (const auto& flow : activeFlows) {

				totalFlowsChecked++;

				//we check activeFlows for statistics
				std::vector<double> features = flow.toFeatureVector();
				double anomalyScore = strategy.detect(features);

				if (anomalyScore > 0.0) {
					std::string srcIP = pcpp::IPv4Address(flow.key.srcIP).toString();
					std::string dstIP = pcpp::IPv4Address(flow.key.dstIP).toString();

					bool isFP = false;
					if (evaluator != nullptr) {
						isFP = evaluator->isKnownBenign(flow.key);
					}

					if (isFP) {
						totalFalsePositives++;
						std::cout << "[FP] Suppressed: " << srcIP << " -> " << dstIP << std::endl;
					} else {
						totalAnomalies++;
						std::cout << " LIVE DETECT] ";
						notifyListener(flow.key, anomalyScore, srcIP, dstIP);
					}
				}
			}
		}
		else {
			for (const auto& flow : expiredFlows) {
				collectedTrainingSamples.push_back({flow.key, flow.toFeatureVector()});
			}
		}
	}
}

void PacketReceiver::runTrainingMode(const std::string& outputModelFile) {

	//delete the old datas
	collectedTrainingSamples.clear();

	//clear ip list
	seenIPs.clear();

	std::cout << "Extracting features for training..." << std::endl;

	//execute source
	//we call processFile function in every packet
	//lambda expression [this] for accesing the function
	packetSource.run([this](pcpp::Packet& packet) {
		this->processSinglePacket(packet, true);

		
		if (packet.isPacketOfType(pcpp::IPv4)) {
			pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
			if (ipLayer != nullptr) {
				seenIPs.insert(ipLayer->getSrcIPv4Address().toString());
				seenIPs.insert(ipLayer->getDstIPv4Address().toString());
			}
		}
		
	});

	//take files that does not timeout too
	std::vector<FlowData> remainingFlows = flowManager.getActiveFlowsSnapshot();

	//take variables as FlowData and change to struct
	for (const auto& flow : remainingFlows) {
		collectedTrainingSamples.push_back({flow.key, flow.toFeatureVector()});
	}

	if (collectedTrainingSamples.empty()) {
		std::cerr << "[Error] No flow data found for training!" << std::endl;
		return;
	}

	//sorting features for training model
	std::vector<std::vector<double>> rawFeatures;
	rawFeatures.reserve(collectedTrainingSamples.size());
	for (const auto& sample : collectedTrainingSamples) {
		rawFeatures.push_back(sample.features);
	}

	std::cout << "Training model with " << collectedTrainingSamples.size() << " flows..." << std::endl;
	strategy.train(rawFeatures); //train model with numerical data
	
	//after model trained, it will test it
	//if it detects its normal data as anomaly, it is an error
	//the ips which do that will add to whitelist
	std::cout << "[INFO] Auto-Whitelisting" << std::endl;
	std::set<uint32_t> autoTrustedIPs;

	for (const auto& sample : collectedTrainingSamples) {
		//for anomaly detection
		double score = strategy.detect(sample.features);

		// if score greater than 0, than it is an anomaly
		// but it is in whitelist so it is false positive
		if (score > 0.0) {
			autoTrustedIPs.insert(sample.key.srcIP);
			autoTrustedIPs.insert(sample.key.dstIP);
		}
	}
	
	//add to trusted ip list
	std::ofstream ipFile("trusted_ips.txt");
	if (ipFile.is_open()) {
		for (const auto& ipInt : autoTrustedIPs) {
			std::string ipStr = pcpp::IPv4Address(ipInt).toString();
			ipFile << ipStr << "\n";
		}
		ipFile.close();
		std::cout << "[INFO] trusted_ips.txt created( " << seenIPs.size() << " IPs)." << std::endl;
	}
	
	
	strategy.saveModel(outputModelFile);
	collectedTrainingSamples.clear();
	packetSource.close();
}

void PacketReceiver::runDetectMode(const std::string& inputModelFile) {
	strategy.loadModel(inputModelFile);
	packetCounter = 0;

	totalFlowsChecked = 0;
	totalAnomalies = 0;
	totalFalsePositives = 0;

	std::cout << "[INFO] Detect Mode" << std::endl;

	packetSource.run([this](pcpp::Packet& packet) {
			this->processSinglePacket(packet, false);
	});

	this->printStats();

	packetSource.close();
}
