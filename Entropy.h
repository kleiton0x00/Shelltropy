#pragma once
#include <cmath>
#include <map>


template <typename T>
static float shannon_entropy(T data[], int elements)
{
	float entropy = 0;
	std::map<T, long> counts;
	typename std::map<T, long>::iterator it;
	for (int data_index = 0; data_index < elements; ++data_index)
	{
		++counts[data[data_index]];
	}
	it = counts.begin();
	while (it != counts.end())
	{
		const float p_x = static_cast<float>(it->second) / elements;
		if (p_x > 0) entropy -= std::log(p_x) * p_x / log(2);
		++it;
	}
	return entropy;
}

inline float calculate_entropy(char* memory, const int count)
{
	return shannon_entropy(memory, count);;
}
