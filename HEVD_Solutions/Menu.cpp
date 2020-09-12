#include <iostream>

#include "utils.h"

VOID print_menu() {
	std::cout << "1. Exploit buffer overflow" << std::endl;
	std::cout << "2. Exploit integer overflow " << std::endl;
	std::cout << "3. Exploit write what where" << std::endl;
	std::cout << "4. Exploit null pointer dereference" << std::endl;
	std::cout << "5. Exploit use after free in non paged pool" << std::endl;
	std::cout << "6. Exploit non paged pool overflow" << std::endl;
	std::cout << "7. Exploit unintialized stack variable" << std::endl;
	std::cout << "8. Exploit unintialized heap variable" << std::endl;
}

int get_user_choice() {
	int choice = 0;
	std::cin >> choice;
	return choice;
}