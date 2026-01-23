#pragma once //calling once for compiling
#include <vector>
#include <string>

//strategy pattern
class IDetectionStrategy {
public:
	virtual ~IDetectionStrategy() = default;

	//pure virtual function for model's training
	//we will use 2-dimensional vector for structured data of ml
	//rows will represent one packet and flow of network
	//colums will represent packet's features
	virtual void train(const std::vector<std::vector<double>>& trainingData) = 0;

	//this funciton is for detection and model's return value
	virtual double detect(const std::vector<double>& features) = 0;

	//for returning name of strategy (for logging)
	virtual std::string getName() const = 0;

	//for saving and loading model
	virtual void saveModel(const std::string& filename) = 0;
	virtual void loadModel(const std::string& filename) = 0;
};
