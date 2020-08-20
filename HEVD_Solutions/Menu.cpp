#include <iostream>

#include "utils.h"

using namespace std;

VOID printMenu() {
	cout << "1. Exploit buffer overflow" << endl;
	cout << "2. Exploit integer overflow " << endl;
	cout << "3. Exploit write what where" << endl;
	cout << "4. Exploit null pointer dereference" << endl;
	cout << "5. Exploit use after free in non paged pool" << endl;
	cout << "6. Exploit non paged pool overflow" << endl;
}

int GetUserChoice() {
	int choice = 0;
	cin >> choice;
	return choice;
}