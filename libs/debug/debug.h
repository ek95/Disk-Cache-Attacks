#ifndef _DEBUG_H_
#define _DEBUG_H_

#define DEBUG "\x1b[35;1m[DEBUG]\x1b[0m "

#ifdef _DEBUG_
#define DEBUG_PRINT(x) printf x
#else
#define DEBUG_PRINT(x) \
    do                 \
    {                  \
    } while (0)
#endif

#endif