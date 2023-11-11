#include "CClientEngine.h"

int main(int argc, char* argv[])
{
	CClientEngine engine;
	engine.initialize();
	
	engine.display();
	engine.startFlow();
	engine.pause();
	
	return 0;
}

