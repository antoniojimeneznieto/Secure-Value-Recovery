/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"
#include "ckvs_client.h"
#include "ckvs_httpd.h"

typedef int (*ckvs_command)(const char *filename, int optargc, char* optargv[]);

typedef struct {
    const char* name;
    const char* description;
    ckvs_command local_fonction;
    ckvs_command client_fonction;
} ckvs_command_mapping;

ckvs_command_mapping commands[] = {
        {"stats", " -cryptkvs [<database>|<URL>] stats", (ckvs_command) (int (**)(const char *, int, char **)) ckvs_local_stats, (ckvs_command) (int (**)(const char *, int, char **)) ckvs_client_stats},
        {"get", " -cryptkvs [<database>|<URL>] get <key> <password>",   (ckvs_command) (int (**)(const char *, int, char **)) ckvs_local_get, (ckvs_command) (int (**)(const char *, int, char **)) ckvs_client_get},
        {"set", " -cryptkvs [<database>|<URL>] set <key> <password> <filename>",   (ckvs_command) (int (**)(const char *, int, char **)) &ckvs_local_set, (ckvs_command) (int (**)(const char *, int, char **)) ckvs_client_set},
        {"new", " -cryptkvs [<database>|<URL>] new <key> <password>", (ckvs_command) (int (**)(const char *, int, char **)) ckvs_local_new, NULL},
        {"httpd", " -cryptkvs [<database>|<URL>] httpd <url>", ckvs_httpd_mainloop, NULL}
};


static void usage(const char *execname, int err)
{
    if (err == ERR_INVALID_COMMAND) {
        size_t size = sizeof(commands);
        size_t nb_elem = size / sizeof(ckvs_command_mapping);

        pps_printf("Available commands:\n");
        for(size_t i = 0; i < nb_elem; ++i) {
            pps_printf("Command: %s, Description: %s\n", commands[i].name, commands[i].description);
        }
    } else if (err >= 0 && err < ERR_NB_ERR) {
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}

/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[]) {

    if (argc < 3) return ERR_INVALID_COMMAND;

    const char *db_filename = argv[1];
    const char *cmd = argv[2];

    int optargc = argc - 3;
    char **optargv = argv + 3;

    size_t size = sizeof(commands);
    size_t nb_elem = size / sizeof(ckvs_command_mapping);

    for (size_t i = 0; i < nb_elem; ++i) {
        if (strcmp(cmd, commands[i].name) == 0) {
            // If the command is "httpd" then we only consider a local database
             if(strncmp(db_filename, "http", 4) == 0 && strcmp(cmd, "httpd") != 0) return commands[i].client_fonction(db_filename, optargc, optargv);
            return commands[i].local_fonction(db_filename, optargc, optargv);
        }
    }
    int err = ERR_INVALID_COMMAND;
    usage(argv[0], err);
    return err;
}

#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 */
int main(int argc, char *argv[])
{
    int ret = ckvs_do_one_cmd(argc, argv);
    if (ret != ERR_NONE) {
        usage(argv[0], ret);
    }
    return ret;
}
#endif
