#include <stdio.h>
#include <unistd.h>

int add(int a, int b)
{
  migrate(1, NULL, NULL);
  return a + b;
}

int main(int argc, char **argv)
{
  int a = 10;
  int b = 25;
  int c = add(a, b);
  printf("%d + %d = %d\n", a, b, c);
  return 0;
}
