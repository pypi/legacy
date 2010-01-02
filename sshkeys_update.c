#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>

int main(int argc, char*argv[])
{
  char pyfile[PATH_MAX];
  sprintf(pyfile, "%s.py", argv[0]);
  execl(pyfile, pyfile, NULL);
}
