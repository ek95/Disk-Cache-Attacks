#include <stdio.h>
#include <string.h>
#include "cmdline.h"


#define TEST_START(x) printf("Running %d. test...\n", (x))
#define TEST_END(x) printf("%d. test completed successfully.\n", (x))


int main(int argc, char *argv[])
{
    TEST_START(1);
    {
        char *argv[] = {"test"};
        CmdLineConf cmd_line_conf =
        {
          .mandatory_args_count_ = 0,
          .switches_count_ = 0,
          .switches_ = NULL,
          .switches_arg_count_ = 0
        };
        CmdLineParsed parsed_cmd_line;

        if(parseCmdArgs(&argv[1], sizeof(argv) / sizeof(char *) - 1, &cmd_line_conf, &parsed_cmd_line) != 0)
            return -1;

        freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);
    }
    TEST_END(1);


    TEST_START(2);
    {
        char *argv[] = {"test", "mandatory_arg"};
        CmdLineConf cmd_line_conf =
        {
          .mandatory_args_count_ = 1,
          .switches_count_ = 0,
          .switches_ = NULL,
          .switches_arg_count_ = 0
        };
        CmdLineParsed parsed_cmd_line;

        if(parseCmdArgs(&argv[1], sizeof(argv) / sizeof(char *) - 1, &cmd_line_conf, &parsed_cmd_line) != 0)
            return -1;
        if(strcmp(parsed_cmd_line.mandatory_args_[0], argv[1]) != 0)
            return -1;

        freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);
    }
    TEST_END(2);


    TEST_START(3);
    {
        char *argv[] = {"test", "mandatory_arg"};
        CmdLineConf cmd_line_conf =
        {
          .mandatory_args_count_ = 2,
          .switches_count_ = 0,
          .switches_ = NULL,
          .switches_arg_count_ = 0
        };
        CmdLineParsed parsed_cmd_line;

        if(parseCmdArgs(&argv[1], sizeof(argv) / sizeof(char *) - 1, &cmd_line_conf, &parsed_cmd_line) == 0)
            return -1;

        freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);
    }
    TEST_END(3);


    TEST_START(4);
    {
        char *argv[] = {"test", "mandatory_arg", "mandatory_arg2", "mandatory_arg3"};
        CmdLineConf cmd_line_conf =
        {
          .mandatory_args_count_ = 2,
          .switches_count_ = 0,
          .switches_ = NULL,
          .switches_arg_count_ = 0
        };
        CmdLineParsed parsed_cmd_line;

        if(parseCmdArgs(&argv[1], sizeof(argv) / sizeof(char *) - 1, &cmd_line_conf, &parsed_cmd_line) == 0)
            return -1;

        freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);
    }
    TEST_END(4);


    TEST_START(5);
    {
        char *argv[] = {"test", "mandatory_arg", "mandatory_arg2"};
        const char *switches[] = {"--verbose", "-n", "-t"};
        const size_t switches_arg_count[] = {0, 1, 2};
        CmdLineConf cmd_line_conf =
        {
          .mandatory_args_count_ = 2,
          .switches_count_ = 3,
          .switches_ = switches,
          .switches_arg_count_ = switches_arg_count
        };
        CmdLineParsed parsed_cmd_line;

        if(parseCmdArgs(&argv[1], sizeof(argv) / sizeof(char *) - 1, &cmd_line_conf, &parsed_cmd_line) != 0)
            return -1;
        if(strcmp(parsed_cmd_line.mandatory_args_[0], argv[1]) != 0)
            return -1;
        if(strcmp(parsed_cmd_line.mandatory_args_[1], argv[2]) != 0)
            return -1;

        freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);
    }
    TEST_END(5);


    TEST_START(6);
    {
        char *argv[] = {"test", "mandatory_arg", "mandatory_arg2", "--verbose"};
        const char *switches[] = {"--verbose", "-n", "-t"};
        const size_t switches_arg_count[] = {0, 1, 2};
        CmdLineConf cmd_line_conf =
        {
          .mandatory_args_count_ = 2,
          .switches_count_ = 3,
          .switches_ = switches,
          .switches_arg_count_ = switches_arg_count
        };
        CmdLineParsed parsed_cmd_line;

        if(parseCmdArgs(&argv[1], sizeof(argv) / sizeof(char *) - 1, &cmd_line_conf, &parsed_cmd_line) != 0)
            return -1;
        if(strcmp(parsed_cmd_line.mandatory_args_[0], argv[1]) != 0)
            return -1;
        if(strcmp(parsed_cmd_line.mandatory_args_[1], argv[2]) != 0)
            return -1;
        if(parsed_cmd_line.switch_states_[0] == 0)
            return -1;

        freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);
    }
    TEST_END(6);


    TEST_START(7);
    {
        char *argv[] = {"test", "mandatory_arg", "mandatory_arg2", "-t", "0", "1", "--verbose", "-n", "100"};
        const char *switches[] = {"--verbose", "-n", "-t"};
        const size_t switches_arg_count[] = {0, 1, 2};
        CmdLineConf cmd_line_conf =
        {
          .mandatory_args_count_ = 2,
          .switches_count_ = 3,
          .switches_ = switches,
          .switches_arg_count_ = switches_arg_count
        };
        CmdLineParsed parsed_cmd_line;

        if(parseCmdArgs(&argv[1], sizeof(argv) / sizeof(char *) - 1, &cmd_line_conf, &parsed_cmd_line) != 0)
            return -1;
        if(strcmp(parsed_cmd_line.mandatory_args_[0], argv[1]) != 0)
            return -1;
        if(strcmp(parsed_cmd_line.mandatory_args_[1], argv[2]) != 0)
            return -1;
        if(parsed_cmd_line.switch_states_[0] == 0 ||
           parsed_cmd_line.switch_states_[1] == 0 ||
           parsed_cmd_line.switch_states_[2] == 0)
            return -1;
        if(strcmp(parsed_cmd_line.switch_args_[1][0], argv[8]) != 0 ||
           strcmp(parsed_cmd_line.switch_args_[2][0], argv[4]) != 0 ||
           strcmp(parsed_cmd_line.switch_args_[2][1], argv[5]) != 0)
            return -1;

        freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);
    }
    TEST_END(7);


    TEST_START(8);
    {
        char *argv[] = {"test", "mandatory_arg", "mandatory_arg2", "-t", "0", "--verbose", "-n", "100"};
        const char *switches[] = {"--verbose", "-n", "-t"};
        const size_t switches_arg_count[] = {0, 1, 2};
        CmdLineConf cmd_line_conf =
        {
          .mandatory_args_count_ = 2,
          .switches_count_ = 3,
          .switches_ = switches,
          .switches_arg_count_ = switches_arg_count
        };
        CmdLineParsed parsed_cmd_line;

        if(parseCmdArgs(&argv[1], sizeof(argv) / sizeof(char *) - 1, &cmd_line_conf, &parsed_cmd_line) == 0)
            return -1;

        freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);
    }
    TEST_END(8);


    TEST_START(9);
    {
        char *argv[] = {"test", "mandatory_arg", "mandatory_arg2", "-t", "0", "1", "--verbose", "-n", "100", "101"};
        const char *switches[] = {"--verbose", "-n", "-t"};
        const size_t switches_arg_count[] = {0, 1, 2};
        CmdLineConf cmd_line_conf =
        {
          .mandatory_args_count_ = 2,
          .switches_count_ = 3,
          .switches_ = switches,
          .switches_arg_count_ = switches_arg_count
        };
        CmdLineParsed parsed_cmd_line;

        if(parseCmdArgs(&argv[1], sizeof(argv) / sizeof(char *) - 1, &cmd_line_conf, &parsed_cmd_line) == 0)
            return -1;

        freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);
    }
    TEST_END(9);


    return 0;
}
