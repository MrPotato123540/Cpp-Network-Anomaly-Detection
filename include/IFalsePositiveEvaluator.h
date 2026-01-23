#pragma once
#include "FlowDef.h"

//dip principle for PacketReceiver
//it will take interface from here
class IFalsePositiveEvaluator {
public:
	virtual ~IFalsePositiveEvaluator() = default;

	virtual bool isKnownBenign(const FlowKey& key) = 0;
};
