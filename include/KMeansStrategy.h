#pragma once
#include "IDetectionStrategy.h"
#include "StandardScaler.h"
#include <string>
#include <type_traits>
#include <vector>
#include <limits>

//choose random centers
//assign points in the clusters to nearest center
//update centers according to clusters
//control convergence
//determine the thresholds
class KMeansStrategy : public IDetectionStrategy {
private:
	int k; //k value
	int maxIterations;
	StandardScaler scaler;

	std::vector<std::vector<double>> centroids; //cluster centers for k-mean
	
	std::vector<double> clusterThresholds; //maximum threshold for clusters (will use for anomaly)
	double euclideanDistance(const std::vector<double>& a, const std::vector<double>& b);

public:
	KMeansStrategy(int k = 5, int maxIterations = 100);

	void train(const std::vector<std::vector<double>>& trainingData) override;

	//if distance is greater than threshold, anomaly score will be greater
	double detect(const std::vector<double>& features) override;

	std::string getName() const override {
		return "K-Means Clustering";
	}

	void saveModel(const std::string& filename) override;
	void loadModel(const std::string& filename) override;

};
