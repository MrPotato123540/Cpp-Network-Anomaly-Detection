#pragma once
#include "IFalsePositiveEvaluator.h"
#include <cstdint>
#include <ostream>
#include <sstream>
#include <unordered_set>
#include <string>
#include <fstream>
#include <iostream>
#include "pcapplusplus/IpAddress.h"

class WhitelistEvaluator : public IFalsePositiveEvaluator {
private:
	//hash table for IPv4 (32 bit)
	//it will store only keys(IPs)
	std::unordered_set<uint32_t> trustedIPs;

public:
	//to read trusted IP's list
	void loadWhitelist(const std::string& filename) {
		std::ifstream file(filename);
		std::string ipStr;
		if (file.is_open()) {
			//read file line by line and assing them to ipStr
			while (std::getline(file, ipStr)) {
				if (ipStr.empty()) continue;

				//error handling for words other than ips
				try {
					//ipv4->32 bit integer
					//and add it to hash
					pcpp::IPv4Address ip(ipStr);
					trustedIPs.insert(ip.toInt());
				} catch (...) {
					std::cerr << "[WARN] Invalid IP in whitelist" << ipStr << std::endl;
				}
			}
			file.close();
			std::cout << "[INFO] Whitelist loaded with " << trustedIPs.size() << " IPs." << std::endl;
		}
	}

	bool isKnownBenign(const FlowKey& key) override {
		//find keys in hash table
		if (trustedIPs.find(key.srcIP) != trustedIPs.end()) return true;
		//if (trustedIPs.find(key.dstIP) != trustedIPs.end()) return true;

		return false;
	}
};
		


