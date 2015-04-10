/*
iostream functions for twopence

Copyright (C) 2014-2015 SUSE

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "twopence.h"
#include "utils.h"


typedef struct twopence_io_ops twopence_io_ops_t;
struct twopence_io_ops {
	void			(*close)(twopence_substream_t *);
	int			(*write)(twopence_substream_t *, const void *, size_t);
	int			(*read)(twopence_substream_t *, void *, size_t);
	int			(*set_blocking)(twopence_substream_t *, bool);
	int			(*getfd)(twopence_substream_t *);
	long			(*filesize)(twopence_substream_t *);
};

struct twopence_substream {
	const twopence_io_ops_t *ops;
	union {
	    struct {
	        twopence_buf_t *buffer;
		bool		resizable;
	    };
	    struct {
	        int		fd;
		bool		close;
	    };
	};
};

/*
 * Manipulation of iostreams
 */
twopence_iostream_t *
twopence_iostream_new(void)
{
  twopence_iostream_t *stream;

  stream = twopence_calloc(1, sizeof(*stream));
  return stream;
}

void
twopence_iostream_free(twopence_iostream_t *stream)
{
  twopence_iostream_destroy(stream);
  free(stream);
}

static int
__twopence_iostream_open_file(const char *filename, int mode, unsigned int permissions, twopence_iostream_t **ret)
{
  int fd;

  fd = open(filename, mode, permissions);
  if (fd == -1)
    return errno == ENAMETOOLONG?  TWOPENCE_PARAMETER_ERROR: TWOPENCE_LOCAL_FILE_ERROR;

  *ret = twopence_iostream_new();
  twopence_iostream_add_substream(*ret, twopence_substream_new_fd(fd, true));

  return 0;
}

int
twopence_iostream_open_file(const char *filename, twopence_iostream_t **ret)
{
	return __twopence_iostream_open_file(filename, O_RDONLY, 0, ret);
}

int
twopence_iostream_create_file(const char *filename, unsigned int permissions, twopence_iostream_t **ret)
{
	return __twopence_iostream_open_file(filename, O_CREAT|O_TRUNC|O_WRONLY, permissions, ret);
}

int
twopence_iostream_wrap_fd(int fd, bool closeit, twopence_iostream_t **ret)
{
  *ret = twopence_iostream_new();
  twopence_iostream_add_substream(*ret, twopence_substream_new_fd(fd, closeit));
  return 0;
}

int
twopence_iostream_wrap_buffer(twopence_buf_t *bp, bool resizable, twopence_iostream_t **ret)
{
  *ret = twopence_iostream_new();
  twopence_iostream_add_substream(*ret, twopence_substream_new_buffer(bp, resizable));
  return 0;
}

void
twopence_iostream_add_substream(twopence_iostream_t *stream, twopence_substream_t *substream)
{
  if (stream->count >= TWOPENCE_IOSTREAM_MAX_SUBSTREAMS) {
    twopence_substream_close(substream);
    free(substream);
    return;
  }

  stream->substream[stream->count++] = substream;
}

void
twopence_iostream_destroy(twopence_iostream_t *stream)
{
  unsigned int i;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];

    twopence_substream_close(substream);
    free(substream);
  }
  memset(stream, 0, sizeof(*stream));
}

long
twopence_iostream_filesize(twopence_iostream_t *stream)
{
  twopence_substream_t *substream;

  if (stream->count != 1)
    return TWOPENCE_LOCAL_FILE_ERROR;

  substream = stream->substream[0];
  if (substream->ops->filesize == NULL)
    return TWOPENCE_LOCAL_FILE_ERROR;

  return substream->ops->filesize(substream);
}

/*
 * Buffering functions
 */
static unsigned int
__twopence_buffer_put(twopence_buf_t *bp, const void *data, size_t len)
{
  size_t tailroom;

  tailroom = twopence_buf_tailroom(bp);
  if (len > tailroom)
    len = tailroom;

  twopence_buf_append(bp, data, len);
  return len;
}

/*
 * Check if iostream is at EOF
 */
bool
twopence_iostream_eof(const twopence_iostream_t *stream)
{
  return stream->eof;
}

/*
 * Tune blocking behavior of iostream
 */
int
twopence_iostream_set_blocking(twopence_iostream_t *stream, bool blocking)
{
  int was_blocking = 0;
  unsigned int i;

  if (stream->eof || stream->count == 0)
    return false;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];

    if (substream->ops == NULL)
       continue;
    if (substream->ops->set_blocking == NULL)
      return -1;

    was_blocking = substream->ops->set_blocking(substream, blocking);
  }

  return was_blocking;
}

/*
 * Fill a pollfd struct
 * Returns one of:
 *   0 (EOF condition, pfd struct not filled in)
 *   1 (pfd struct valid)
 *  <0 (error)
 */
int
twopence_iostream_poll(twopence_iostream_t *stream, struct pollfd *pfd, int mask)
{
  unsigned int i;

  if (stream == NULL)
    return -1;

  if (stream->eof || stream->count == 0)
    return 0;

  /* We can only do POLLIN for now */
  if (mask & POLLOUT)
    return -1;
  pfd->events = mask;

  /* Find the first non-EOF substream and fill in the pollfd */
  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];

    if (substream->ops == NULL)
      continue;

    if (substream->ops->getfd == NULL)
      return 0;

    pfd->fd = substream->ops->getfd(substream);
    if (pfd->fd >= 0)
      return 1;

    return -1;
  }

  /* All substreams are EOF, so no polling */
  return 0;
}

int
twopence_iostream_getfd(twopence_iostream_t *stream)
{
  twopence_substream_t *substream;

  if (stream == NULL || stream->eof || stream->count != 1)
    return -1;

  substream = stream->substream[0];
  if (substream
   && substream->ops != NULL
   && substream->ops->getfd != NULL)
    return substream->ops->getfd(substream);

  return -1;
}

/*
 * Read from an iostream
 */
int
twopence_iostream_getc(twopence_iostream_t *stream)
{
  unsigned int i;

  if (stream->eof || stream->count == 0)
    return EOF;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];
    unsigned char c;
    int n;

    if (substream->ops == NULL || substream->ops->read == NULL)
      continue;
    n = substream->ops->read(substream, &c, 1);
    if (n == 1)
      return c;

    // This substream is at its EOF
    twopence_substream_close(substream);
  }

  stream->eof = true;
  return 0;
}

int
twopence_iostream_read(twopence_iostream_t *stream, char *data, size_t len)
{
  unsigned int i;

  if (stream->eof || stream->count == 0)
    return 0;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];
    int n;

    if (substream->ops == NULL || substream->ops->read == NULL)
      continue;

    n = substream->ops->read(substream, data, len);
    if (n > 0)
      return n;

    if (n < 0)
      return n;

    // This substream is at its EOF
    twopence_substream_close(substream);
  }

  stream->eof = true;
  return 0;
}

twopence_buf_t *
twopence_iostream_read_all(twopence_iostream_t *stream)
{
  twopence_buf_t *bp;
  char buffer[8192];
  long size;
  int len;

  if ((size = twopence_iostream_filesize(stream)) < 0)
	  size = 0;

  bp = twopence_buf_new(size);
  while (true) {
    len = twopence_iostream_read(stream, buffer, sizeof(buffer));
    if (len < 0) {
      twopence_buf_free(bp);
      return NULL;
    }
    if (len == 0)
      break;

    twopence_buf_ensure_tailroom(bp, len);
    twopence_buf_append(bp, buffer, len);
  }

  return bp;
}

/*
 * Write to a sink object
 */
int
twopence_iostream_putc(twopence_iostream_t *stream, char c)
{
  unsigned int i;

  if (stream->count == 0)
    return 0;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];

    if (substream->ops == NULL || substream->ops->write == NULL)
      return -1;
    substream->ops->write(substream, &c, 1);
  }

  return 1;
}

int
twopence_iostream_write(twopence_iostream_t *stream, const char *data, size_t len)
{
  unsigned int i;

  if (stream->count == 0)
    return 0;

  for (i = 0; i < stream->count; ++i) {
    twopence_substream_t *substream = stream->substream[i];

    if (substream->ops == NULL || substream->ops->write == NULL)
      return -1;
    substream->ops->write(substream, data, len);
  }

  return len;
}

/*
 * Create a new substream object
 */
static twopence_substream_t *
__twopence_substream_new(const twopence_io_ops_t *ops)
{
  twopence_substream_t *substream;

  substream = twopence_calloc(1, sizeof(*substream));
  substream->ops = ops;

  return substream;
}

void
twopence_substream_close(twopence_substream_t *substream)
{
  if (substream->ops == NULL)
    return;

  if (substream->ops->close)
    substream->ops->close(substream);
  substream->ops = NULL;
}

/*
 * Handle a buffered substream.
 * In the write case, the buffer size is limited, ie we do not grow the buffer
 * dynamically in order  to accomodate arbitrary amounts of data.
 */
static int
twopence_substream_buffer_write(twopence_substream_t *sink, const void *data, size_t len)
{
  twopence_buf_t *bp = sink->buffer;

  if (sink->resizable)
    twopence_buf_ensure_tailroom(bp, len);

  __twopence_buffer_put(bp, data, len);
  return len;
}

static int
twopence_substream_buffer_read(twopence_substream_t *src, void *data, size_t len)
{
  twopence_buf_t *bp = src->buffer;
  unsigned int avail;

  if (bp == NULL)
    return -1;

  avail = twopence_buf_count(bp);
  if (len > avail)
    len = avail;

  memcpy(data, twopence_buf_head(bp), len);
  twopence_buf_advance_head(bp, len);
  return len;
}

static long
twopence_substream_buffer_size(twopence_substream_t *src)
{
  twopence_buf_t *bp = src->buffer;

  if (bp == NULL)
    return -1;

  return twopence_buf_count(bp);
}

int
twopence_substream_buffer_set_blocking(twopence_substream_t *src, bool blocking)
{
  /* always succeeds */
  return 0;
}

static twopence_io_ops_t twopence_buffer_io = {
	.read		= twopence_substream_buffer_read,
	.write		= twopence_substream_buffer_write,
	.set_blocking	= twopence_substream_buffer_set_blocking,
	.filesize	= twopence_substream_buffer_size,
};

twopence_substream_t *
twopence_substream_new_buffer(twopence_buf_t *bp, bool resizable)
{
  twopence_substream_t *io;

  io = __twopence_substream_new(&twopence_buffer_io);
  io->buffer = bp;
  io->resizable = resizable;
  return io;
}

/*
 * fd based substreams
 */
static void
twopence_substream_file_close(twopence_substream_t *substream)
{
  if (substream->fd >= 0 && substream->close) {
    close(substream->fd);
    substream->fd = -1;
  }
}

static int
twopence_substream_file_write(twopence_substream_t *sink, const void *data, size_t len)
{
  int fd = sink->fd;

  if (fd < 0)
    return -1;

  return write(fd, data, len);
}

static int
twopence_substream_file_read(twopence_substream_t *src, void *data, size_t len)
{
  int fd = src->fd;

  if (fd < 0)
    return -1;

  return read(fd, data, len);
}

static long
twopence_substream_file_size(twopence_substream_t *src)
{
  int fd = src->fd;
  struct stat stb;

  if (fd < 0)
    return -1;

  if (fstat(fd, &stb) < 0 || !S_ISREG(stb.st_mode))
    return -1;

  return stb.st_size;
}

int
twopence_substream_file_set_blocking(twopence_substream_t *src, bool blocking)
{
  int oflags, nflags;

  if (src->fd < 0)
    return 0;

  oflags = fcntl(src->fd, F_GETFL);        // Get old flags
  if (oflags == -1)
    return -1;

  nflags = oflags & ~O_NONBLOCK;
  if (!blocking)
    nflags |= O_NONBLOCK;

  if (fcntl(src->fd, F_SETFL, nflags) < 0)
    return -1;

  /* Return old settings (true means it was using blocking mode before the change) */
  return !(oflags & O_NONBLOCK);
}

int
twopence_substream_file_getfd(twopence_substream_t *src)
{
  return src->fd;
}

static twopence_io_ops_t twopence_file_io = {
	.close	= twopence_substream_file_close,
	.read	= twopence_substream_file_read,
	.write	= twopence_substream_file_write,
	.set_blocking = twopence_substream_file_set_blocking,
	.getfd	= twopence_substream_file_getfd,
	.filesize = twopence_substream_file_size,
};

twopence_substream_t *
twopence_substream_new_fd(int fd, bool closeit)
{
  twopence_substream_t *io;

  io = __twopence_substream_new(&twopence_file_io);
  io->fd = fd;
  io->close = closeit;
  return io;
}

twopence_substream_t *
twopence_iostream_stdout(void)
{
  return twopence_substream_new_fd(1, false);
}

twopence_substream_t *
twopence_iostream_stderr(void)
{
  return twopence_substream_new_fd(2, false);
}
