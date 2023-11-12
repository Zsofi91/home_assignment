#include "CClientEngine.h"

int main(int argc, char* argv[])
{
	CClientEngine engine;
	engine.initialize();
	
	engine.display();
	engine.startFlow();
	
	return 0;
}

