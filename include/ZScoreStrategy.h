#pragma once
#include "IDetectionStrategy.h"
#include <vector>
#include <cmath>
#include <algorithm>

class ZScoreStrategy : public IDetectionStrategy {
private:
	std::vector<double> medians; //median for all features, we use it for Z-score
	std::vector<double> mads; //median absolute deviation, we use it calculate better
	double threshold; // if a flow pass this threshold, we will say this is an anomaly

	double calculateMedian(std::vector<double>& data);

public:
	ZScoreStrategy(double threshold = 3.5);

	void train(const std::vector<std::vector<double>>& trainingData) override;

	double detect(const std::vector<double>& features) override;

	std::string getName() const override {
		return "Z-Score Strategy";
	}

	void saveModel(const std::string& filename) override;
	void loadModel(const std::string& filename) override;
};
