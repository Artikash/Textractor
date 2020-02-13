#pragma once

#include "common.h"
#include <variant>

template <typename C, typename V>
struct Trie
{
	struct Node
	{
		union
		{
			std::basic_string<C> chars;
			std::vector<std::pair<C, std::unique_ptr<Node>>> charMap;
		};
		uint64_t packedValue;
		const C* Tail() const
		{
			return packedValue >> 63 ? chars.c_str() : nullptr;
		}
		V* Value() const
		{
			return (V*)((packedValue << 2) >> 2);
		}
		void SetValue(V value)
		{
			if (V* oldValue = Value()) *oldValue = std::move(value);
			else packedValue = (1LL << (62 + (packedValue >> 63))) | (uint64_t)new V(std::move(value));
		}
		Node(bool map) :
			packedValue(1LL << (62 + !map))
		{
			if (map) new (&charMap) decltype(charMap)();
			else new (&chars) decltype(chars)();
		}
		~Node()
		{
			if (packedValue >> 63) chars.~basic_string();
			else charMap.~vector();
			delete Value();
		}
	};

		template <typename Node>
		static Node* Next(Node* node, C ch, bool makeMap = false)
		{
			if (node->packedValue >> 63) return nullptr;
			auto it = std::lower_bound(node->charMap.begin(), node->charMap.end(), ch, [](const auto& one, auto two) { return one.first < two; });
			if (it != node->charMap.end() && it->first == ch) return it->second.get();
			if constexpr (!std::is_const_v<Node>) return node->charMap.insert(it, { ch, std::make_unique<Node>(makeMap) })->second.get();
			return nullptr;
		}

		static void Clear(Node* node)
		{
			if (node->packedValue >> 63) node->chars.clear();
			else for (auto& [_, child] : node->charMap) Clear(child.get());
		}

	std::unique_ptr<Node> root = std::make_unique<Node>(true);

	Node* Insert(std::basic_string_view<C> key)
	{
		Node* current = root.get();
		for (int i = 0; i < key.size(); ++i)
		{
			if (Node* next = Next(current, key[i], i + 1 == key.size())) current = next;
			else
			{
				if (current->chars.empty()) // FIXME: how to represent last character inside map?
				{
					current->chars = std::basic_string(key.begin() + i, key.end());
					if(current->chars.empty())throw;
					break;
				}
				else if (current->chars == key.substr(i))
				{
					break;
				}
				else
				{
					auto oldChars = std::move(current->chars);
					assert(current->Value());
					auto oldValue = std::move(*current->Value());
					auto keyRemaining = key.substr(i);
					current->chars.~basic_string();
					new (&current->charMap) decltype(current->charMap)();
					current->packedValue ^= 3ULL << 62;
					for (i = 0; i < oldChars.size() && i < keyRemaining.size(); ++i)
					{
						if (oldChars[i] == keyRemaining[i]) current = Next(current, oldChars[i], true);
						else break;
					}
					if (i == oldChars.size())
					{
						current->SetValue(std::move(oldValue));
					}
					else
					{
						auto relocated = Next(current, oldChars[i]);
						relocated->chars = oldChars.substr(i);
						relocated->SetValue(std::move(oldValue));
					}
					if (i != keyRemaining.size()) (current = Next(current, keyRemaining[i]))->chars = std::basic_string(keyRemaining.begin() + i, keyRemaining.end());
					break;
				}
			}
		}
		return current;
	}

	const Node* Root() const
	{
		return root.get();
	}

	bool Empty() const
	{
		return root->charMap.empty();
	}
};
