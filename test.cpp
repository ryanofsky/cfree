#include <iostream>

using namespace::std;

#define EXPR(x)  cout << #x << " = " << (x) << endl

int main(int, char *[])
{
  EXPR(2342 >> 2 && 2);
  EXPR((2342 >> 2) && 2);
  EXPR(2342 >> (2 && 2));
}
