#ifndef _CMD_LINE_H_
#define _CMD_LINE_H_

#include <stdint.h>
#include <stdlib.h>

typedef struct {
    const size_t mandatory_args_count_;
    const size_t switches_count_;
    const char **switches_;
    const size_t *switches_arg_count_;
}CmdLineConf;

typedef struct {
    char **mandatory_args_;
    uint8_t *switch_states_;
    char ***switch_args_; 
}CmdLineParsed;


int parseCmdArgs(char *argv[], size_t argc, CmdLineConf *conf, CmdLineParsed *parsed);
void freeCmdLineParsed(CmdLineConf *conf, CmdLineParsed *parsed); 

#endif