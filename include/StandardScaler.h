#pragma once
#include <cstddef>
#include <vector>
#include <cmath>
#include <limits>
#include "FlowFeature.h" //FeatureIndex enum
#include "json.hpp"

using json = nlohmann::json;

class StandardScaler {
private:
	std::vector<double> means; //mean of every feature
	std::vector<double> stdDevs; //standard deviation of every feature

public:
	StandardScaler() = default;

	void fit(const std::vector<std::vector<double>>& data) {
		if (data.empty()) return;

		size_t featureCount = data[0].size(); //featureCount through the flow
		size_t sampleCount = data.size(); //amount of flow

		means.assign(featureCount, 0.0);
		stdDevs.assign(featureCount, 0.0);

		for (const auto& row : data) { //go through all rows
			for (size_t i = 0; i < featureCount; ++i) { 
				means[i] += row[i]; //add the following row
			}
		}
		for (size_t i = 0; i < featureCount; ++i) {
			//mean formula
			//μ = Σx / N
			means[i] /= sampleCount; 
		}

		//standard deviation
		for (const auto& row : data) {
			for (size_t i = 0; i < featureCount; ++i) {
				stdDevs[i] += std::pow(row[i] - means[i], 2); //data - mean
									      //power is for same numbers with - and + signs
			}
		}
		//variance->standard deviation
		for (size_t i =0; i < featureCount; ++i) {
			stdDevs[i] = std::sqrt(stdDevs[i] / sampleCount);

			//we add a control for deviation by zero error
			//if in transform mean and tcp has same numbers
			//standard deviation is 0
			//so we add i < 0.000000001 control
			//which means data is constant and has no deviation
			//so we divide it 1.0 for not effecting anything
			//if (stdDevs[i] < 1e-9) stdDevs[i] = 1.0;
			if (stdDevs[i] < 0.5) stdDevs[i] = 0.5;
		}
	}

	//transform a single data to normalized 
	std::vector<double> transform(const std::vector<double>& features) const {
		std::vector<double> scaled = features;
		if (means.empty() || stdDevs.empty()) return scaled; //control for fit()

		//Formula: (x - u) / s
		for (size_t i = 0; i < features.size(); ++i) { //iterate through all features

			//control flow vector size and training vector size
			//if vector has 5 element and training has 4, this will vause us segfault
			//this will save us from segfault
			if (i < means.size() && i < stdDevs.size()) {
				scaled[i] = (features[i] - means[i]) / stdDevs[i];
			}
		}
		return scaled;
	}

	//to normalize matrix
	std::vector<std::vector<double>> transformMatrix(const std::vector<std::vector<double>>& data) const {
		std::vector<std::vector<double>> scaledData; //empty matrix to store
		scaledData.reserve(data.size()); //for not use reallocation
		for (const auto& row : data) {
			//transform(row) is for DRY(Don't Repeat Yourself Principle)
			scaledData.push_back(transform(row));
		}
		return scaledData;
	}

	//change datas to JSON	
	json toJson() const {
		return json{
			{"means", means},
			{"stdDevs", stdDevs}
		};
	}

	//load datas from JSON
	void fromJson(const json& j) {
		if (j.contains("means"))
			means = j.at("means").get<std::vector<double>>();
		if (j.contains("stdDevs"))
			stdDevs = j.at("stdDevs").get<std::vector<double>>();
	}
};

