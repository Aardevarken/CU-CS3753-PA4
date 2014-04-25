#ifndef _PARAMS_H_
#define _PARAMS_H_

#define ENCRYPT 1
#define DECRYPT 0
#define PASS -1

// maintain encfs state in here
#include <limits.h>
#include <stdio.h>
struct encfs_state 
{
	char *rootdir;
	char *passphrase;
};
#define ENCFS_DATA ((struct encfs_state *) fuse_get_context()->private_data)

#endif