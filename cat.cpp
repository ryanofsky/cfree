#include <aio.h>
#include <errno.h>
#include <iostream>

/* Test program to start building an asynchronous i/o 
 * framework. Things that gots to be done
 *
 * 1) Wait function is ridiculously simplistic, needs to be
 *    generalized to wait on any number of events and to be able
 *    to return error and status information.
 *    
 * 2) AsynchOp classes need to be rearranged and filled out. A first step is
 *    to generalize the interface enough to support multiple implementations,
 *    such as a select() based implementation or asynchronous read and writes
 *    for nonblocking descriptors.
 *
 * 3) Then the ultimate goal is to be able to figure out a nice way to 
 *    implement complex asynchronous operations on top of primitive ones (i.e.
 *    readline on top of read). I have some ideas for using cooperative
 *    threads (fibers) for this. It'll require another overhaul of wait().
 */

struct AsynchOp
{
};

struct AioOp : public AsynchOp, public aiocb
{
  void init(int filedes, off_t offset, char * buffer, size_t len)
  {
    this->aio_fildes = filedes;
    this->aio_offset = offset;
    this->aio_buf= buffer;
    this->aio_nbytes = len;
    this->aio_sigevent.sigev_notify = SIGEV_NONE;
  }
};

struct IOError
{
  IOError(int error_, char const * file_, int line_)
    : error(error_), file(file_), line(line_)
  {}

  int error;
  char const * file;
  int line;
};

#define EARGS , __FILE__, __LINE__

struct WriteOp : public AioOp
{
  void init(int filedes, off_t offset, char const * buffer, size_t len)
  {
    AioOp::init(filedes, offset, const_cast<char *>(buffer), len);
    if (aio_write(this))
      throw IOError(errno EARGS);
  }
};

struct ReadOp : public AioOp
{
  void init(int filedes, off_t offset, char * buffer, size_t len)
  {
    AioOp::init(filedes, offset, buffer, len);
    if (aio_read(this))
      throw IOError(errno EARGS);
  }
};

#define DIM(x) (sizeof((x))/sizeof((x)[0]))

void wait(AioOp & a, AioOp & b)
{
  const struct aiocb * list[] = {&a, &b};
  bool inProgress;

  do
  {
    if (aio_suspend(list, DIM(list), NULL))
      throw IOError(errno EARGS);

    inProgress = false;
    for (unsigned i=0; i<DIM(list); ++i)
    {
      if (list[i])
      {
        int error = aio_error(list[i]);
        if (error == EINPROGRESS)
         inProgress = true;
        else if (error == 0)
          list[i] = NULL;
        else
          throw IOError(error EARGS);
      }
    }
  }
  while (inProgress);
}

int main(int, const char *[])
{
  try
  {
    const int BUFFER_SIZE = 4096;
    char readBuffer[BUFFER_SIZE], *readPtr(readBuffer);
    char writeBuffer[BUFFER_SIZE], *writePtr(writeBuffer);
    
    ReadOp readOp;
    WriteOp writeOp;
    
    off_t offset = 0;
    readOp.init(STDIN_FILENO, offset, readPtr, BUFFER_SIZE);

    for (;;)
    {
      wait(readOp, writeOp);

      ssize_t readLen = aio_return(&readOp);
      if (readLen == 0)
        break;

      std::swap(readPtr, writePtr);

      writeOp.init(STDOUT_FILENO, offset, writePtr, readLen);
      readOp.init(STDIN_FILENO, offset += readLen, readPtr, BUFFER_SIZE);
    }
  }
  catch (IOError e)
  {
    std::cerr << "IO Error at " << e.file << ":" << e.line << std::endl;
    std::cerr << strerror(e.error) << std::endl;
  }
}
