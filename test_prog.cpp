#include <stdio.h>

int arr[10000];

int main()
{
	int i;
	for (i = 0; i < 10000; i++){
		arr[i] = i;
	}
	printf("%p\n",arr);
	for (i = 0; i < 10000; i++){
		if (arr[i]%(i+51)==((i > 100) ? i/2 : 1001)){
			printf("%d\n",arr[i]);	
		}
	}
	return 0;
}
