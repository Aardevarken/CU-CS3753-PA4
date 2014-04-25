/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR
static const char ENCATTRNAME[] = "user.pa4-encfs.encrypted";

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
/* For open_memstream() */
#define _POSIX_C_SOURCE 200809L
/* Linux is missing ENOATTR error, using ENODATA instead */
#define ENOATTR ENODATA
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h> 	
#include <linux/limits.h>
#include "params.h"
#include "aes-crypt.h"
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif




static int is_encrypted(const char *path){
	ssize_t valsize;
	char *tmpval;
	valsize = getxattr(path, ENCATTRNAME, NULL, 0);
	if(valsize < 0){
	    if(errno == ENOATTR){
		fprintf(stderr, "No %s attribute set on %s\n", ENCATTRNAME, path);
		return 0;
	    }
	    else{
		perror("getxattr error");
		fprintf(stderr, "path  = %s\n", path);
		fprintf(stderr, "name  = %s\n", ENCATTRNAME);
		fprintf(stderr, "value = %s\n", "NULL");
		fprintf(stderr, "size  = %zd\n", valsize);
		return -errno;
	    }
	}
	/* Malloc Value Space */
	tmpval = malloc(sizeof(*tmpval)*(valsize+1));
	if(!tmpval){
	    perror("malloc of 'tmpval' error");
	    return -errno;
	}
	/* Get attribute value */
	valsize = getxattr(path, ENCATTRNAME, tmpval, valsize);
	if(valsize < 0){
	    if(errno == ENOATTR){
		fprintf(stdout, "No %s attribute set on %s\n", ENCATTRNAME, path);
		return 0;
	    }
	    else{
		perror("getxattr error");
		fprintf(stderr, "path  = %s\n", path);
		fprintf(stderr, "name  = %s\n", ENCATTRNAME);
		fprintf(stderr, "value = %s\n", tmpval);
		fprintf(stderr, "size  = %zd\n", valsize);
		return -errno;
	    }
	}

	tmpval[valsize] = '\0';
	fprintf(stderr, "%s = %s\n\n", ENCATTRNAME, tmpval);

	if(!strcmp(tmpval, "true")){
		return 1;
	}
	else
		return 0;
}

static void xmp_fullpath(char fpath[PATH_MAX], const char *path)
{
	strcpy(fpath, XMP_DATA->rootdir);
	strncat(fpath, path, PATH_MAX);
}

static long xmp_encgetsize(char *path){
	FILE *fp, *tmpfp;
	long size;

	fp = fopen(path, "r");

	if(is_encrypted(path)){
		tmpfp = tmpfile();
		if (tmpfp == NULL)
			return -errno;
		if (fp == NULL)
			return -errno;
		do_crypt(fp, tmpfp, DECRYPT, XMP_DATA->passphrase);
		fseek(tmpfp, 0, SEEK_END);
		size = ftell(tmpfp);
		fclose(fp);
	}
	else{
		fprintf(stderr, "encgetsize: file was not encrypted\n");
		return -errno;
	}
	
	return size;
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	long unecrsize;

	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;
	/* if the file is encrypted, we'll need to replace the size,
	since size(unecrypted) != size(encrypted), which is important
	for some text editors */
	if(S_ISREG(stbuf->st_mode)){
		if(is_encrypted(fpath)){
			unecrsize = xmp_encgetsize(fpath);
			stbuf->st_size = unecrsize;
		}
	}

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	(void) offset;
	(void) fi;

	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	FILE *fp, *memfp;
	char *memdata;
	size_t memsize;
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);


	if(is_encrypted(fpath)){
	(void) fi;
	fp = fopen(fpath, "r");
	if (fp == NULL)
		return -errno;

	memfp = open_memstream(&memdata, &memsize);
	if (memfp == NULL)
		return -errno;

	do_crypt(fp, memfp, DECRYPT, XMP_DATA->passphrase);
	fclose(fp);

	fflush(memfp);
	fseek(memfp, offset, SEEK_SET);

	res = fread(buf, 1, size, memfp);
	if (res == -1)
		res = -errno;

	fclose(memfp);
	}
	else{
	int fd;

	fd = open(fpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	}

	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	FILE *fp, *memfp;
	int res;
	char *memdata;
	size_t memsize;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	(void) fi;

	if(is_encrypted(fpath)){
	fp = fopen(fpath, "r");
	if (fp == NULL)
		return -errno;

	memfp = open_memstream(&memdata, &memsize);
	if (memfp == NULL)
		return -errno;

	do_crypt(fp, memfp, DECRYPT, XMP_DATA->passphrase);
	fclose(fp);

	fseek(memfp, offset, SEEK_SET);
	res = fwrite(buf, 1, size, memfp);
	if (res == -1)
		res = -errno;
	fflush(memfp);

	fp = fopen(fpath, "w");
	fseek(memfp, 0, SEEK_SET);
	do_crypt(memfp, fp, ENCRYPT, XMP_DATA->passphrase);

	fclose(memfp);
	fclose(fp);
	}
	else{
	int fd;

	fd = open(fpath, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	}

	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) 
{
    (void) fi;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	FILE *fp;
    int res;
    int attr;

    res = creat(fpath, mode);
    if(res == -1)
	return -errno;
	
	fp = fdopen(res, "w");
	close(res);
	
	do_crypt(fp, fp, ENCRYPT, XMP_DATA->passphrase);

	fclose(fp);
    
	/* set file attribute */
	attr = setxattr(fpath, ENCATTRNAME, "true", 4, 0);
	if(attr == -1)
		return -errno;

    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

void *xmp_init()
{
    return XMP_DATA;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	if(is_encrypted(fpath)){
		size = xmp_encgetsize(fpath);
	}

	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
	.init       = xmp_init,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

void xmp_usage()
{
    fprintf(stderr, "usage: ./pa4-encfs [FUSE and mount options] passphrase rootDir mountPoint\n");
    exit(1);
}

int main(int argc, char *argv[])
{
	struct xmp_state *xmp_data;

	// Perform some sanity checking on the command line:  make sure
    // there are enough arguments, and that neither of the last two
    // start with a hyphen (this will break if you actually have a
    // rootpoint or mountpoint whose name starts with a hyphen, but so
    // will a zillion other programs)
    if ((argc < 4) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-')) {
		xmp_usage();
	}
	
	xmp_data = malloc(sizeof(struct xmp_state));
	    if (xmp_data == NULL) {
			perror("main calloc");
			abort();
    }

	xmp_data->rootdir = realpath(argv[argc-2], NULL);
	xmp_data->passphrase = argv[argc-3];
    argv[argc-3] = argv[argc-1];
    argv[argc-2] = NULL;
    argv[argc-1] = NULL;
    argc -= 2;

    umask(0);
	return fuse_main(argc, argv, &xmp_oper, xmp_data);
}
