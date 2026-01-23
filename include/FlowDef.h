#pragma once
#include <cstddef>
#include <functional>
#include <math.h>
#include <string>
#include <cstdint>
#include <type_traits>
#include <vector>
#include <cmath>
#include "FlowFeature.h"
#include "pcapplusplus/IPv4Layer.h"

//5-tuple 
struct FlowKey {
	uint32_t srcIP; //IPv4 is 4 byte
	uint32_t dstIP;
	uint16_t srcPort; //between 0 - 2^16
	uint16_t dstPort; 
	uint8_t protocol; //such as TCP, UDP - IP protocol is 8-bit and 1 byte unsigned char is enough 

	//operator overloading
	//we will check IPs of FlowKey and hash table
	//to compare they are equal or not
	bool operator == (const FlowKey& other) const {
		return srcIP == other.srcIP && dstIP == other.dstIP && srcPort == other.srcPort && dstPort == other.dstPort && protocol == other.protocol;
	}
};

//we need client->server and server->client same in network
//so we need to make same hashes (symmetric hash) for source and destinations
//so A->B and B->A needs to have same hashes
struct FlowKeyHash {
	//we're making another operator overloading for hashing
	//we're using it because we need a funciton for hashing
	//so we're making it callable
	std::size_t operator()(const FlowKey& k) const {
		//this was for string in srcIP and dstIP
		//return std::hash<std::string>()(k.srcIP) ^ 
			//std::hash<std::string>()(k.dstIP) ^
		       	//std::hash<uint16_t>()(k.srcPort) ^
		       	//std::hash<uint16_t>()(k.dstPort) ^
		       	//std::hash<uint8_t>()(k.protocol);
		//An example for it
		//SrcIP: 192.168.1.5 - Hash: 100
		//DstIP: 8.8.8.8 - Hash: 200
		//SrcPort: 50000 - Hash: 30
		//DstPort: 443 - 40
		//Protocol: 6 (TCP) - Hash: 5
		//Hash: 100 XOR 200 XOR 30 XOR 40 XOR 5
		//ID: 215 
		//we will put it to FlowData
		//reverse will be same too
		//Hash: 200 XOR 100 XOR 40 XOR 30 XOR 5
		//ID: 215
		
		//this code is more optimized
		//for example, now 192.168.1.5 is 32 bit and works in 1 cycle
		//so for example, SrcPort: 80 (0x0050) and DstPort: 54321 (0xD431)
		//SrcPort: 0000 0000 0101 0000 
		//Shift: 0101 0000 0000 0000 
		//DstPort: 0000 0000 1101 0100
		//XOR: 0101 0000 1101 0100
		//so we avoid the collision, we didnt lose any information
		return k.srcIP ^ k.dstIP ^ (k.srcPort << 16) ^ k.dstPort ^ k.protocol;

	}
};

struct FlowData {
	FlowKey key; 	//id for FlowKey, it will take flow of network
	double startTime; 
	double lastPacketTime; //for iat
	long packetCount;
	long byteCount;
	double iatSum;
	double iatSqSum; //square of Iat for variance
	
	//TCP Flags
	long synCount;
	long ackCount;
	long rstCount;

	long long winSizeSum; //for mean

	FlowData() : startTime(0), lastPacketTime(0), packetCount(0), byteCount(0), iatSum(0), iatSqSum(0), synCount(0), ackCount(0), rstCount(0), winSizeSum(0) {}

	std::vector<double> toFeatureVector() const {
		double duration = lastPacketTime - startTime;
		
		double iatMean = 0.0;
		double iatStd = 0.0;	

		if (packetCount > 1) {
			//packetCount - 1 is using because: [Packet 1] -> [IAT 1] -> [Packet 2]...
			iatMean = iatSum / (packetCount - 1);

			//Varianca: E[X^2] - (E[X])^2
			double variance = (iatSqSum / (packetCount - 1)) - (iatMean * iatMean);
			//variance can't be negative
			if (variance > 0) iatStd = std::sqrt(variance);
	}

	double winSizeAvg = (packetCount > 0) ? ((double)winSizeSum / packetCount) : 0.0;	        
	
	//to put features to vector table
	//algorithms will use this table for Euclidean distance, anomaly detection etc.
	//we are making log transformation for distrubition
	//in network traffic, datas are in Pareto distrubition not Gaussian distrubition
	//for example, while one packet is 60 byte, other one could be 1GB
	//so this can be break ZScore algorithm (mean/stdDev) and could cause overgrowth in standard deviations
	//to prevent this we are making std::log1p(x)
	//this will make log(1 + x) and compress the data to make it close to normal distrubition
	std::vector<double> v(FeatureIndex::FEATURE_COUNT);
	v[FeatureIndex::DURATION] = std::log1p(duration);
	v[FeatureIndex::PACKET_COUNT] = std::log1p((double)packetCount);
       	v[FeatureIndex::BYTE_COUNT] = std::log1p((double)byteCount);
       	v[FeatureIndex::IAT_MEAN] = log1p(iatMean);
       	v[FeatureIndex::IAT_STD] = log1p(iatStd);
       	v[FeatureIndex::SYN_COUNT] = log1p((double)synCount);
       	v[FeatureIndex::ACK_COUNT] = log1p((double)ackCount);
       	v[FeatureIndex::RST_COUNT] = log1p((double)rstCount);
       	v[FeatureIndex::WIN_SIZE_AVG] = log1p(winSizeAvg);

       	return v;
}



};



