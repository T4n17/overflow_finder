#include <stdio.h>
#include <stdlib.h>

void hidden()
{
    puts("Overflow!\n");
}
void func()
{
    puts("Nothing happened!\n");
    exit(0);
}
int main(int argc, const char *argv[])
{	
    void (*func_pointer)(); 
    func_pointer = &func;
    char buffer[64];
    scanf("%s", &buffer);
    func_pointer();
    return 0;
}
