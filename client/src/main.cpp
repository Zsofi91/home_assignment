#include "CClientMenu.h"

int main(int argc, char* argv[])
{
	CClientMenu menu;
	menu.initialize();
	
	for (;;)
	{
		menu.display();
		menu.handleUserChoice();
		menu.pause();
	}
	
	return 0;
}

