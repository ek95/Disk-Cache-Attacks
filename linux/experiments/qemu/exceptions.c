#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

jmp_buf fault_jmp;

void signal_handler(int signum)
{
  switch (signum)
  {
  case SIGFPE:
    fprintf(stdout, "Caught SIGFPE\n");
    break;
  case SIGSEGV:
    fprintf(stdout, "Caught SIGSEV\n");
    break;
  default:
    fprintf(stdout, "default handler\n");
  }

  longjmp(fault_jmp, 1);
}

int main(void)
{
  struct sigaction sa;
  volatile unsigned char tmp = 0;
  int b = 1;
  char choice[255];

  sa.sa_flags = SA_NODEFER;
  sa.sa_handler = signal_handler;
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGFPE, &sa, NULL);

  while (1)
  {
    printf("Which fault should be triggered:\n");
    printf("z -> divide by zero, SIGFPE\n");
    printf("s -> access to memory location *0x0, SIGSEGV\n");
    printf("k -> access to a kernel memory location *0xffff800000000000, SIGSEGV\n");
    printf("> ");
    fgets(choice, 255, stdin);

    if (setjmp(fault_jmp) == 0)
    {
      switch (choice[0])
      {
      case 'z':
        b /= 0x0;
        break;
      case 's':
        tmp = *((unsigned char *)0x0);
        break;
      case 'k':
        tmp = *((unsigned char*)  0xffff800000000000);
        break;
      }
    }
  }

  return b;
}