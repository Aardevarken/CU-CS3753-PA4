#ifndef _PARAMS_H_
#define _PARAMS_H_


// maintain xmpfs state in here
#include <limits.h>
#include <stdio.h>
struct xmp_state 
{
	char *rootdir;
	char *passphrase;
};
#define XMP_DATA ((struct xmp_state *) fuse_get_context()->private_data)

#endif