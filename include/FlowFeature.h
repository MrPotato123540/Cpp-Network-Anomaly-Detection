#pragma once
#include <vector>

//enum for all features
//we're using enum for make it easier to read
//for example v[0] is not readable if you forget what it is 
enum FeatureIndex {
	DURATION = 0, //duration of transmisson between two devices to understand port scan attacks
	PACKET_COUNT = 1, 
	BYTE_COUNT = 2, //total size of data
	IAT_MEAN = 3, //mean of the time between two packets arrive
	IAT_STD = 4, //standard deviation version
	SYN_COUNT = 5, //TCP SYN
	ACK_COUNT = 6, //TCP ACK 
	RST_COUNT = 7, //TCP RST
	WIN_SIZE_AVG = 8, //mean of window size
	FEATURE_COUNT = 9 //total feature count
};

