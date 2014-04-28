/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>
  Further modified to create an encrypted file system by Morgan Garske 04/25/2014

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fuseencfs.c -o fuseencfs `pkg-config fuse --libs`

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
/* name for encryption attribute */
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



/* given a file path, will return a 0 if unencrypted, and 1 if encrypted.
   This code has been lightly modified from that which appears in xattr-util.c */
static int encfs_isencrypted(const char *path){
	ssize_t valsize;
	char *tmpval;

	/* get the size of the value */
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

	/* place NULL terminator at valsize for comparison */
	tmpval[valsize] = '\0';

	/* if value is "true", it is encrypted. Otherwise, consider it unencrypted */
	if(!strcmp(tmpval, "true")){
		return 1;
	}
	else
		return 0;
}

/* replaces the root path with the full path for mirroring the specified directory */
static void encfs_fullpath(char fpath[PATH_MAX], const char *path)
{
	strcpy(fpath, ENCFS_DATA->rootdir);
	strncat(fpath, path, PATH_MAX);
}

/* gets the size of an encrypted file, which will appear different
   if the size is determined before the file has been unecrypted */
static long encfs_encgetsize(char *path){
	FILE *fp, *tmpfp;
	long size;

	fp = fopen(path, "r");
	if (fp == NULL)
			return -errno;

	/* double check that the path is for an encrypted file */
	if(encfs_isencrypted(path)){
		/* create temp file and encrypt into it. */
		tmpfp = tmpfile();
		if (tmpfp == NULL)
			return -errno;
		do_crypt(fp, tmpfp, DECRYPT, ENCFS_DATA->passphrase);
		/* go back to the beginning of the file then get the size */
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

static int encfs_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	long unecrsize;

	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;
	/* if the file is encrypted, we'll need to replace the size,
	since size(unecrypted) != size(encrypted), which is important
	for some text editors */
	if(S_ISREG(stbuf->st_mode)){
		if(encfs_isencrypted(fpath)){
			unecrsize = encfs_encgetsize(fpath);
			stbuf->st_size = unecrsize;
		}
	}

	return 0;
}

static int encfs_access(const char *path, int mask)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

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

static int encfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

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

static int encfs_mkdir(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_unlink(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rmdir(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chmod(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_truncate(const char *path, off_t size)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	/* if encrypted, get the correct size */
	if(encfs_isencrypted(fpath)){
		size = encfs_encgetsize(fpath);
	}

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int encfs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	FILE *fp, *tmpfp;
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	(void) fi;

	/* if the file is encrypted, we need to decrypt before reading */
	if(encfs_isencrypted(fpath)){

		fp = fopen(fpath, "r");
		if (fp == NULL)
			return -errno;
		/*create the temp file to decrypt into */
		tmpfp = tmpfile();
		if (tmpfp == NULL)
			return -errno;
		/* decrypt the file into the tempfile */
		do_crypt(fp, tmpfp, DECRYPT, ENCFS_DATA->passphrase);
		fclose(fp);
		/*seek to the position we want to read, then read */
		fseek(tmpfp, offset, SEEK_SET);
		res = fread(buf, 1, size, tmpfp);
		if (res == -1)
			res = -errno;
		fclose(tmpfp);
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

static int encfs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	FILE *fp, *tmpfp;
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	(void) fi;

	/* if the file is encrypted, then we'll have to unencrypt, write, then decrypt.*/
	if(encfs_isencrypted(fpath)){

		fp = fopen(fpath, "r");
		if (fp == NULL)
			return -errno;
		/* create and open a temp file */
		tmpfp = tmpfile();
		if (tmpfp == NULL)
			return -errno;
		/* decrypt the file into the temp file */
		do_crypt(fp, tmpfp, DECRYPT, ENCFS_DATA->passphrase);
		fclose(fp);

		/*seek to the position we need to write at then write */
		fseek(tmpfp, offset, SEEK_SET);
		res = fwrite(buf, 1, size, tmpfp);
		if (res == -1)
			res = -errno;
		/* open the original file to write encrypted data */
		fp = fopen(fpath, "w");
		/* go to beginning of temp file and then encrypt */
		fseek(tmpfp, 0, SEEK_SET);
		do_crypt(tmpfp, fp, ENCRYPT, ENCFS_DATA->passphrase);

		fclose(tmpfp);
		fclose(fp);
	}

	/*if it is not encrypted, we just use the logic from fuseencfs.c */
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

static int encfs_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) 
{
    (void) fi;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	FILE *fp;
    int res;
    int attr;

    res = creat(fpath, mode);
    if(res == -1)
	return -errno;
	
	fp = fdopen(res, "w");
	close(res);
	
	do_crypt(fp, fp, ENCRYPT, ENCFS_DATA->passphrase);

	fclose(fp);
    
	/* set file attribute */
	attr = setxattr(fpath, ENCATTRNAME, "true", 4, 0);
	if(attr == -1)
		return -errno;

    return 0;
}


static int encfs_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int encfs_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

void *encfs_init()
{
    return ENCFS_DATA;
}

#ifdef HAVE_SETXATTR
static int encfs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int encfs_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations encfs_oper = {
	.getattr	= encfs_getattr,
	.access		= encfs_access,
	.readlink	= encfs_readlink,
	.readdir	= encfs_readdir,
	.mknod		= encfs_mknod,
	.mkdir		= encfs_mkdir,
	.symlink	= encfs_symlink,
	.unlink		= encfs_unlink,
	.rmdir		= encfs_rmdir,
	.rename		= encfs_rename,
	.link		= encfs_link,
	.chmod		= encfs_chmod,
	.chown		= encfs_chown,
	.truncate	= encfs_truncate,
	.utimens	= encfs_utimens,
	.open		= encfs_open,
	.read		= encfs_read,
	.write		= encfs_write,
	.statfs		= encfs_statfs,
	.create         = encfs_create,
	.release	= encfs_release,
	.fsync		= encfs_fsync,
	.init       = encfs_init,
#ifdef HAVE_SETXATTR
	.setxattr	= encfs_setxattr,
	.getxattr	= encfs_getxattr,
	.listxattr	= encfs_listxattr,
	.removexattr	= encfs_removexattr,
#endif
};

void encfs_usage()
{
    fprintf(stderr, "usage: ./pa4-encfs [FUSE and mount options] passphrase rootDir mountPoint\n");
    fprintf(stderr, "passphrase cannot start with a hyphen (-)\n");
    exit(1);
}

int main(int argc, char *argv[])
{
	struct encfs_state *encfs_data;

	// Perform some sanity checking on the command line:  make sure
    // there are enough arguments, and that neither of the last two
    // start with a hyphen (this will break if you actually have a
    // rootpoint or mountpoint whose name starts with a hyphen, but so
    // will a zillion other programs) Will also not allow a passphrase
    // with a hyphen before.
    if ((argc < 4) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-') || (argv[argc-3][0] == '-')) {
		encfs_usage();
	}
	
	encfs_data = malloc(sizeof(struct encfs_state));
	    if (encfs_data == NULL) {
			perror("main calloc");
			abort();
    }

	encfs_data->rootdir = realpath(argv[argc-2], NULL);
	encfs_data->passphrase = argv[argc-3];
    argv[argc-3] = argv[argc-1];
    argv[argc-2] = NULL;
    argv[argc-1] = NULL;
    argc -= 2;

    umask(0);
	return fuse_main(argc, argv, &encfs_oper, encfs_data);
}
