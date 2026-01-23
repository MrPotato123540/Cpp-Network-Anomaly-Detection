#include "ZScoreStrategy.h"
#include "FlowFeature.h"
#include "json.hpp"
#include <cstdint>
#include <fstream>
#include <numeric>
#include <algorithm>
#include <cmath>
#include <iostream>
#include <type_traits>

using json = nlohmann::json;

//writes anomaly normal value (3.5) to class
//prevents divide by 0
//Formula = x - median / mad
ZScoreStrategy::ZScoreStrategy(double threshold) : threshold(threshold) {
	medians.resize(FeatureIndex::FEATURE_COUNT, 0.0);
	mads.resize(FeatureIndex::FEATURE_COUNT, 1.0);
}

double ZScoreStrategy::calculateMedian(std::vector<double>& data) {
	if (data.empty()) return 0.0;
	size_t n = data.size();
	size_t mid = n / 2;

	//nth_element is for finding median (some kind of quick sort)
	//it's time complexity is better than std::sort (o(n log n) vs O(n))
	std::nth_element(data.begin(), data.begin() + mid, data.end());
	double median = data[mid];

	//even number control
	//we make it because if n is even, we will divide by 2
	if (n % 2 == 0) {
		std::nth_element(data.begin(), data.begin() + mid - 1, data.end());
		median = (data[mid - 1] + median) / 2.0;
	}
	return median;
}

//matrix to save flow
void ZScoreStrategy::train(const std::vector<std::vector<double>>& trainingData) {
	if (trainingData.empty()) return;

	size_t numSamples = trainingData.size();

	//transpoze
	for (int i = 0; i < FeatureIndex::FEATURE_COUNT; ++i) {
		//copy list of rows of matrix
		std::vector<double> columnData;
		columnData.reserve(numSamples);

		for (const auto& row : trainingData) {
			columnData.push_back(row[i]);
		}

		//finding median
		//it is for effect of outliers
		//mean is robust towards them
		double medianVal = calculateMedian(columnData);
		medians[i] = medianVal;

		//this will find the distance of values with median
		//Formula = |Xi - Median|
		std::vector<double> absoluteDeviations;
		absoluteDeviations.reserve(numSamples);
		for (double val : columnData) {
			absoluteDeviations.push_back(std::abs(val - medianVal));
		}

		//median of all absoluteDeviations
		//more robust version of standard deviation (mad)
		double madVal = calculateMedian(absoluteDeviations);

		//divide by 0 protection
		//if all packet's sizes are same, mad becomes 0
		//Score = absoluteDeviations / mad
		if (madVal < 1e-9) madVal = 1e-6;

		mads[i] = madVal;
	}

	std::cout << "[Z-Score] Training complete" << std::endl;
}

//this will give us the anomaly score
double ZScoreStrategy::detect(const std::vector<double>& features) {
	double maxZScore = 0.0;

	//mad formula for outlier detection
	//Formula: 0.6745(xi - x) / mad 
	//x = median of dataset
	for (int i = 0; i < FeatureIndex::FEATURE_COUNT; ++i) {
		double score = std::abs(0.6745 * (features[i] - medians[i]) / mads[i]);

		//we have 4 features
		//so a single deviation makes it an anomaly
		if (score > maxZScore) {
			maxZScore = score;
		}
	}

	if (maxZScore > threshold) {
		return maxZScore - threshold;
	}

	return 0.0;
}

void ZScoreStrategy::saveModel(const std::string& filename) {
	json j;
	j["type"] = "ZScore";
	j["medians"] = medians;
	j["mads"] = mads;
	j["threshold"] = threshold;

	std::ofstream file(filename);
	file << j.dump(4);
	std::cout << "ZScore Model saved" << std::endl;
}

void ZScoreStrategy::loadModel(const std::string& filename) {
	std::ifstream file(filename);
	if (!file.is_open()) return;

	json j;
	file >> j;
	if (j["type"] != "ZScore") return;

	medians = j["medians"].get<std::vector<double>>();
	mads = j ["mads"].get<std::vector<double>>();
	threshold = j["threshold"];
	std::cout << "ZScore Model loaded." << std::endl;
}
