#include <stdio.h>
#include <stdlib.h>

int main() {

	volatile unsigned int 	number1 = 1337;
	volatile long 			number2 = 6667;
	volatile int 			number3 = 2345;
	volatile double 		number4 = 1234; 
	volatile char char1 = 'A';
	volatile char *s1 = "Hello world!";
	volatile char s2[7] = "ABCDEFG";

	char buffer1[64] = "Hello world!";
	char buffer2[64] = "Hello world!";
	char buffer3[64] = "Hello world!";
	char buffer4[65] = "Hello world!";
	char buffer5[64] = "Hello world!";
	char buffer6[64] = "Hello world!";
	char buffer7[64] = "Hello world!";
	char buffer8[64] = "Hello world!";
	char buffer9[64] = "Hello world!";
	char buffer10[64] = "Hello world!";
	char buffer11[64] = "Hello world!";
	char buffer12[64] = "Hello world!";
	char buffer13[64] = "Hello world!";
	char buffer14[64] = "Hello world!";
	char buffer15[64] = "Hello world!";
	char buffer16[64] = "Hello world!";
	
	// Vulnerable gets
	gets(buffer1);

	// Not vulnerable strcpy
	strcpy(buffer2, "Hello world! Ha Ha Ha Ha");

	// Vulnerable strcpy
	strcpy(buffer3, buffer4);

	// Not vulnerable strncpy
	strncpy(buffer5, buffer6, 64);

	// Not vulnerable strncpy
	strncpy(buffer7, "Hello world!", 64);

	// Vulnerable strncpy
	strncpy(buffer8, buffer9, 1128);

	// Not vulnerable printf
	printf("%s\n", buffer2);

	// Vulnerable printf
	printf(buffer11);

	// Not vulnerable memcpy
	memcpy(buffer12, buffer13, 64);

	// Vulnerable memcpy
	memcpy(buffer14, buffer15, 128);

}