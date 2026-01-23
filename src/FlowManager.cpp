#include "FlowManager.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"
#include <pcapplusplus/ProtocolType.h>
#include <cstddef>
#include <cstdint>
#include <endian.h>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

//taking IPv4
//S.O.L.I.D's single responsibilty principle
void FlowManager::processPacket(pcpp::Packet& packet) {
	if (!packet.isPacketOfType(pcpp::IPv4)) {
		return;
	}

	pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
	if (ipLayer == nullptr) return;
	
	//5-tuple
	uint32_t srcIP = ipLayer->getSrcIPv4Address().toInt();
	uint32_t dstIP  = ipLayer->getDstIPv4Address().toInt();
	uint16_t srcPort = 0;
	uint16_t dstPort = 0;
	uint8_t protocol = ipLayer->getIPv4Header()->protocol;

	bool isTcp = false;
	bool hasSyn = false, hasAck = false, hasRst = false;
	uint16_t currentWinSize = 0;

	//taking tcp/udp like this is not suitable for ocp principle in S.O.L.I.D but I dont want to change it 
	if (packet.isPacketOfType(pcpp::TCP)) {
		isTcp = true;
		pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
		srcPort = tcpLayer->getSrcPort();
		dstPort = tcpLayer->getDstPort();

		if (tcpLayer->getTcpHeader()->synFlag == 1) hasSyn = true;
		if (tcpLayer->getTcpHeader()->ackFlag == 1) hasAck = true;
		if (tcpLayer->getTcpHeader()->rstFlag == 1) hasRst = true;

		currentWinSize = tcpLayer->getTcpHeader()->windowSize;
	}
	else if (packet.isPacketOfType(pcpp::UDP)) {
		pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
		srcPort = udpLayer->getSrcPort();
		dstPort = udpLayer->getDstPort();
	}

	//we will make canonicalization (normalization)
	//this prevents seperation of A->B and B->A 
	//we will compare IPs and sort them
	//A->B and B->A packages will have same key
	FlowKey key;

	//string comparasion
	//if source IP lower than destination IP, we will not change anything
	if (srcIP < dstIP) {
		key.srcIP = srcIP;
		key.dstIP = dstIP;
		key.srcPort = srcPort;
		key.dstPort = dstPort;
	}

	//otherwise swap
	else {
		key.srcIP = dstIP;
		key.dstIP = srcIP;
		key.srcPort = dstPort;
		key.dstPort = srcPort;
	}

		key.protocol = protocol;

	//this code takes struct timeval
	//which stores the time in tv_sec and tv_usec
	//tv_sec = takes the time from January 1st 1970 00:00:00
	//tv_usec = nanoseconds and reset in every 1000000
	//1e-9 = 1 x 10^(-9)
	//which will takes us the decimal places
	double timestamp = packet.getRawPacket()->getPacketTimeStamp().tv_sec + (packet.getRawPacket()->getPacketTimeStamp().tv_nsec * 1e-9);

	//taking length of all payload, ethernet header, IP header and TCP/UDP header
	long packetLen = packet.getRawPacket()->getFrameLength();

	//check all flows saved to hash
	//A->B and B->A all in same flow
	auto it = activeFlows.find(key);
	
	//if it show end of the hash, it means it the first package of the flow
	//because it means it couldn't find the flow in the activeFlows
	if (it == activeFlows.end()) {
		FlowData newFlow;
		newFlow.key = key;
		newFlow.startTime = timestamp;
		newFlow.lastPacketTime = timestamp;
		newFlow.packetCount = 1;
		newFlow.byteCount = packetLen;
		newFlow.iatSum = 0;
		newFlow.iatSqSum = 0;
		
		//take this value from FlowDef.h
		if (isTcp) {
			if (hasSyn) newFlow.synCount = 1;
			if (hasAck) newFlow.ackCount = 1;
			if (hasRst) newFlow.rstCount = 1;
			newFlow.winSizeSum = currentWinSize;
		}

		//copy all to activeFlows map
		activeFlows[key] = newFlow;
	} else {
		//else we start new flow
		//it makes a data - key pair
		FlowData& flow = it->second;

		double iat = timestamp - flow.lastPacketTime;

		//error correction for timestamps
		if (iat < 0) iat = 0;

		flow.packetCount++;
		flow.byteCount += packetLen;
		flow.iatSum += iat;
		flow.lastPacketTime = timestamp;

		//update TCP info
		if (isTcp) {
			if (hasSyn) flow.synCount++;
			if (hasAck) flow.ackCount++;
			if (hasRst) flow.rstCount++;
			flow.winSizeSum += currentWinSize;
		}
	}
}

//to not keep broken connections forever
std::vector<FlowData> FlowManager::checkTimeouts(double currentTime) {
	//to store expired flows
	std::vector<FlowData> expiredFlows;

	auto it = activeFlows.begin();
	while (it != activeFlows.end()) {
		//it->second for giving for actual data at the index it is looking
		//it: activeFlows map pointer
		//first: FlowKey
		//second: FlowData
		FlowData& flow = it->second;

		//check arrival of the last packet
		bool isIdleTimeout = (currentTime - flow.lastPacketTime) > FLOW_IDLE_TIMEOUT;

		//check how long flow lasted
		bool isActiveTimeout = (currentTime - flow.startTime) > FLOW_ACTIVE_TIMEOUT;
		
		
		if (isIdleTimeout || isActiveTimeout) {
			
			if (flow.packetCount > 5) {
				//before we erase it, we add it to the expiredFlows
				expiredFlows.push_back(flow);
			}

			//erasing
			it = activeFlows.erase(it);
		} else {
			//we make it ++it not it++ because if we don't erase anything, it can break the program
			++it;
		}
	}
	return expiredFlows;
}

//matrix for flow
//it will use for training
std::vector<std::vector<double>> FlowManager::getAllFlowFeatures() const {
	//reserve memory according to data number
	std::vector<std::vector<double>> trainingData;
	trainingData.reserve(activeFlows.size());

	//go through all map's records
	for (const auto& pair : activeFlows) {
		trainingData.push_back(pair.second.toFeatureVector());
	}
	return trainingData;
}

//detection after training
std::vector<double> FlowManager::getFlowFeature(const FlowKey& key) {
	if (activeFlows.find(key) != activeFlows.end()) {
		return activeFlows[key].toFeatureVector();
	}
	return {}; //empty
}
	
std::vector<FlowData> FlowManager::getActiveFlowsSnapshot() const {
	std::vector<FlowData> activeFlowList;

	//single thread hashmap for active flows
	activeFlowList.reserve(activeFlows.size());

	//std::unordered_map<FlowKey, FlowData> key-value pair
	//pair.first key (FlowKey)
	//pair.second value (FlowData)
	for (const auto& pair : activeFlows) {
		//if the number of packet in a flow is 20, than it will analyse the flow
		if (pair.second.packetCount > 20) {
			//we add new datas to vector
			activeFlowList.push_back(pair.second);
		}
	}
	return activeFlowList;
}



