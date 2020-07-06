#include "cmdline.h"
#include <string.h>


static int isSwitch(char *str, size_t *sw, CmdLineConf *conf) 
{
    for(size_t i = 0; i < conf->switches_count_; i++) 
    {
        if(strcmp(str, conf->switches_[i]) == 0) 
        {
            *sw = i;
            return 1;
        }
    }
    
    return 0;
}


int parseCmdArgs(char *argv[], size_t argc, CmdLineConf *conf, CmdLineParsed *parsed) 
{
    size_t mandatory_arg_i = 0;
    size_t sw = 0;
    size_t last_sw = 0;
    int parse_switch = 0;
    size_t switch_arg_i = 0;

    // init return struct
    memset(parsed, 0, sizeof(CmdLineParsed));
    // reserve space for string arrays
    parsed->mandatory_args_ = calloc(conf->mandatory_args_count_, sizeof(char *));
    if(parsed->mandatory_args_ == NULL) 
    {
        return -1;
    }
    parsed->switch_states_ = calloc(conf->switches_count_, sizeof(uint8_t));
    if(parsed->switch_states_ == NULL) 
    {
        return -1;
    }
    
    parsed->switch_args_ = calloc(conf->switches_count_, sizeof(char **));
    if(parsed->switch_args_ == NULL) 
    {
        return -1;
    }
    for(sw = 0; sw < conf->switches_count_; sw++) 
    {
        parsed->switch_args_[sw] = calloc(conf->switches_arg_count_[sw], sizeof(char *));
        if(parsed->switch_args_[sw] == NULL) 
        {
            return -1;
        }
    }
    
    
    // parse arg vector
    for(size_t arg_i = 0; arg_i < argc; arg_i++)
    {
        // check if argument is switch
        if(isSwitch(argv[arg_i], &sw, conf)) 
        {
            // before the switches the mandatory arguments have to be
            // after a switch with unparsed arguments no switch should follow
            if(mandatory_arg_i != conf->mandatory_args_count_ ||
               (parse_switch && conf->switches_arg_count_[last_sw] != switch_arg_i)) 
            {
                return -1;
            }
            else 
            {
                parsed->switch_states_[sw] = 1;
                last_sw = sw;
                switch_arg_i = 0;
                parse_switch = 1;
            }
        }
        // argument is a normal string
        else 
        {
            if(parse_switch) 
            {
                // too much switch arguments
                if(switch_arg_i == conf->switches_arg_count_[last_sw]) 
                {
                    return -1;
                }
                
                parsed->switch_args_[last_sw][switch_arg_i] = strdup(argv[arg_i]);
                // oom
                if(parsed->switch_args_[last_sw][switch_arg_i] == NULL) 
                {
                    return -1;
                }
                switch_arg_i++;
            }
            else 
            {
                // too much arguments
                if(mandatory_arg_i == conf->mandatory_args_count_) 
                {
                    return -1;
                }
                
                parsed->mandatory_args_[mandatory_arg_i] = strdup(argv[arg_i]);
                // oom
                if(parsed->mandatory_args_[mandatory_arg_i] == NULL) 
                {
                    return -1;
                }
                mandatory_arg_i++;
            }
        }
    }
    
    // too less mandatory strings
    // too less strings for a switch
    if(mandatory_arg_i < conf->mandatory_args_count_ || 
       (parse_switch && switch_arg_i < conf->switches_arg_count_[last_sw]))
    {
        return -1;
    }
        
    return 0;
}


void freeCmdLineParsed(CmdLineConf *conf, CmdLineParsed *parsed) 
{
    if(parsed->switch_args_ != NULL) 
    {
        for(size_t sw = 0; sw < conf->switches_count_; sw++) 
        {
            if(parsed->switch_args_[sw] != NULL) 
            {
                for(size_t i = 0; i < conf->switches_arg_count_[sw]; i++) 
                {
                    free(parsed->switch_args_[sw][i]);
                }
                
                free(parsed->switch_args_[sw]);
            }
        }
        
        free(parsed->switch_args_);
    }

    free(parsed->switch_states_); 
    
    if(parsed->mandatory_args_ != NULL) 
    {
        for(size_t i = 0; i < conf->mandatory_args_count_; i++) 
        {
            free(parsed->mandatory_args_[i]);
        }
        
        
        free(parsed->mandatory_args_);
    }
}