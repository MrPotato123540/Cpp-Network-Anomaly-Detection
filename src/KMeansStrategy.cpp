#include "KMeansStrategy.h"
#include "FlowFeature.h"
#include "json.hpp"
#include <cmath>
#include <cstddef>
#include <exception>
#include <fstream>
#include <limits>
#include <cstdlib>
#include <iostream>
#include <type_traits>
#include <vector>

using json = nlohmann::json;

//constructor
KMeansStrategy::KMeansStrategy(int k, int maxIterations) : k(k), maxIterations(maxIterations) {
	//assign ks with 0.0
	clusterThresholds.resize(k, 0.0);
}

double KMeansStrategy::euclideanDistance(const std::vector<double>& a, const std::vector<double>& b) {
	//Pythagorean theorem in multidimensional space
	//d(a, b) = sqrt(Sigma(i=0 to k) (ai - bi)^2 )
	double sum = 0.0;
	
	//find lowest one prevent segfault
	size_t dims = std::min(a.size(), b.size());
	for (size_t i = 0; i < dims; ++i) {
		double diff = a[i] - b[i];
		sum += diff * diff;
	}
	return std::sqrt(sum);
}

void KMeansStrategy::train(const std::vector<std::vector<double>>& trainingData) {
	if ((int)trainingData.size() < k) {
		std::cerr << "Not enough data" << std::endl;
		return;
	}

	//check data and normalize it
	scaler.fit(trainingData);

	//we will use not raw data but normalized data
	std::vector<std::vector<double>> normalizedData = scaler.transformMatrix(trainingData);

	//clearing centroids for grouping and resetting it for other iterations
	centroids.clear();

	//we use forgy method in here
	//will choose k observations and use it as initial mean
	for (int i = 0; i < k; ++i) {
		//copy trainingData vector's feature list to centroids
		centroids.push_back(normalizedData[i]);
	}

	//this is for optimization
	//it will store which data point belongs to which cluster
	std::vector<int> assignments(normalizedData.size());

	//it limits the algorithm for finite iterations
	//because we can not converge a center infinite times
	for (int iter = 0; iter < maxIterations; ++iter) {
		//flag for a center to change place
		bool changed = false;

		//2-dimensional vector for collection of all features
		//assign all features with 0.0
		//Example newClusterSums[1][BYTE_COUNT]
		//Byte number of first cluster
		std::vector<std::vector<double>> newClusterSums(k, std::vector<double>(FeatureIndex::FEATURE_COUNT, 0.0));

		//1 dimensional vector
		//it counts how many points from flow assigned
		//it will be denominator of followinf formula
		//New Center = Collection of Cluster Sums(newClusterSums) / Count of points(newClusterCounts)
		std::vector<int> newClusterCounts(k, 0);


		for (size_t i = 0; i < normalizedData.size(); ++i) {
			//we assign the highest number possible for distance calculation
			double minDist = std::numeric_limits<double>::max();

			//for which point belongs to which cluster
			int bestCluster = 0;

			//now we calculate distance to centroids (k-means algorithm)
			for (int j = 0; j < k; ++j) {
				double dist = euclideanDistance(normalizedData[i], centroids[j]);
				//calculate new distance and new center
				if (dist < minDist) {
					minDist = dist;
					bestCluster = j;
				}
			}

			//check if this bestCluster already in cluster
			if (assignments[i] != bestCluster) {
				assignments[i] = bestCluster;
				changed = true;
			}

			//this is for assigning new center with average of values
			//takes bestCluster's fth feature and adds to trainingData(normalizedData)
			for (int f = 0; f < FeatureIndex::FEATURE_COUNT; ++f) {
				newClusterSums[bestCluster][f] += normalizedData[i][f];
			}
			//add one more value for average
			newClusterCounts[bestCluster]++;
		}

		//updates for every k
		for (int j = 0; j < k; ++j) {
			if (newClusterCounts[j] > 0) { //divide by zero control
				//iterate through all features
				for (int f = 0; f < FeatureIndex::FEATURE_COUNT; ++f) {
					//calculate average
					centroids[j][f] = newClusterSums[j][f] / newClusterCounts[j];
				}
			}
		}

		//breaks the loop because of convergence
		if (!changed) {
			std::cout << "Finished at " << iter << std::endl;
			break;
		}
	}

	std::vector<std::vector<double>> clusterDistances(k);

		
	//we will read the data
	for (const auto& point : normalizedData) {
		int bestCluster = 0;
		//gives the max number whihc a double can take
		double minDist = std::numeric_limits<double>::max();

		//we calculate the distance towards k pieces of centroids
		for (int j = 0; j < k; ++j) {
			double dist = euclideanDistance(point, centroids[j]);
			if (dist < minDist) {
				minDist = dist;
				bestCluster = j;
			}
		}

		clusterDistances[bestCluster].push_back(minDist);
	}

		for (int j = 0; j < k; ++j) {
			if (clusterDistances[j].empty()) {
				clusterThresholds[j] = 0.5;
				continue;
			}

			std::sort(clusterDistances[j].begin(), clusterDistances[j].end());

			size_t index = (size_t)(clusterDistances[j].size() * 0.99);

			if (index >= clusterDistances[j].size()) index = clusterDistances[j].size() - 1;

			double threshold99 = clusterDistances[j][index];

			clusterThresholds[j] = std::max(threshold99, 0.5);

			std::cout << "Cluster " << j << " Threshold (%99): " << clusterThresholds[j] << std::endl;
		}

}

double KMeansStrategy::detect(const std::vector<double>& features) {
	if (centroids.empty()) return 0.0;

	//normalized version will have values between 0.0 and 1.0
	//so if we dont add this code block, it can't detect normalized version and normal version
	//for example, we have 1000000 byte data and it is 0.5 in normalized
	//without this codeblock it can understand 100000 byte as an anomaly
	std::vector<double> normalizedFeatures = scaler.transform(features);

	double minDist = std::numeric_limits<double>::max(); //set limit to maximum number
	int bestCluster = 0;

	for (int j = 0; j < k; ++j) {
		double dist = euclideanDistance(normalizedFeatures, centroids[j]);
		if (dist < minDist) {
			minDist = dist;
			bestCluster = j;
		}
	}

	//this is for detecting anomaly
	double threshold = clusterThresholds[bestCluster];

	if (minDist > threshold) {
		return minDist - threshold; //anomaly score
	}

	return 0.0;
}

void KMeansStrategy::saveModel(const std::string& filename) {
	json j;
	j["type"] = "KMeans";
	j["k"] = k;
	j["centroids"] = centroids;
	j["thresholds"] = clusterThresholds;
        j["scaler"] = scaler.toJson();

	std::ofstream file(filename);
	if (file.is_open()) {
		file << j.dump(4); //pretty print
		file.close();
		std::cout << "Model saved to " << filename << std::endl;
	} else {
		std::cerr << "Could not save model!" << std::endl;
	}
}

void KMeansStrategy::loadModel(const std::string& filename) {
	std::ifstream file(filename);
	if (!file.is_open()) {
		std::cerr << "Could not open model file!" << std::endl;
		return;
	}
	
	//for reading file
	json j;
	file >> j;

	k = j["k"];
	centroids = j["centroids"].get<std::vector<std::vector<double>>>();
	clusterThresholds = j["thresholds"].get<std::vector<double>>();

	if (j.contains("scaler"))	 {
		scaler.fromJson(j["scaler"]);
	}

	std::cout << "Model loaded from" << filename << std::endl;
}
