#pragma once
#include "CClientLogic.h"
#include <string>       // std::to_string
#include <iomanip>      // std::setw

class CClientEngine
{
public:
	CClientEngine() : _registered(false) {}
	void initialize();
	void display() const;
	void startFlow();

	void clear() const { system("cls"); }
	void pause() const { system("pause"); }

private:
	CClientLogic                   _clientLogic;
	bool                           _registered;
	void clientStop(const std::string& error) const;
	
};

