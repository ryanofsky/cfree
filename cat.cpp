#include <aio.h>
#include <errno.h>
#include <iostream>
#include <vector>

/* Test program to start building an asynchronous i/o 
 * framework. Things that gots to be done
 *
 * 1) Wait function is too simplistic, needs to be generalized to be able
 *    to return error and status information.
 *    
 * 2) AsynchOp classes need to be rearranged and filled out. A first step is
 *    to generalize the interface enough to support multiple implementations,
 *    such as a select() based implementation of asynchronous read and writes
 *    for nonblocking descriptors.
 *
 * 3) Then the ultimate goal is to be able to figure out a nice way to 
 *    implement complex asynchronous operations on top of primitive ones (i.e.
 *    readline on top of read). I have some ideas for using cooperative
 *    threads (fibers) for this. It'll require another overhaul of wait().
 */

//! Expression template for holding && operands in wait expressions
template<typename LEFT, typename RIGHT>
struct AndNode
{
  typedef LEFT Left;
  typedef RIGHT Right;
  typedef AndNode<Left, Right> This;

  //! Template metafunction to figure out member types from operands
  template<typename OPERAND, int EXPR_LEAF=OPERAND::EXPR_LEAF>
  struct Operand2Member
  {
    // If Operand is an leaf (i.e. an AsynchOp object) just hold a pointer
    typedef OPERAND const * type;
    static void assign(type &member, OPERAND const &operand)
    {
      member = &operand;
    }
  };

  template<typename OPERAND>
  struct Operand2Member<OPERAND, false>
  {
    // If Operand is an AndNode, contain and copy the whole object
    typedef OPERAND type;
    static void assign(type &member, OPERAND const &operand)
    {
      member = operand;
    }
  };

  typedef typename Operand2Member<Left>::type LeftMember;
  typedef typename Operand2Member<Right>::type RightMember;  
  LeftMember left;
  RightMember right;
  
  enum {EXPR_LEAF=false};

  AndNode(LEFT const & left_, RIGHT const & right_)
  {
    Operand2Member<Left>::assign(left, left_);
    Operand2Member<Right>::assign(right, right_);
  }

  AndNode()
  {
  }

  template<typename R>
  AndNode<This, R> operator&&(R const & r) const
  {
    AndNode<This, R> a(*this, r);
    return a;
  }
};

//! Asynchronous Operation Base Class
struct AsynchOp
{
  enum {EXPR_LEAF=true};
};

//! Posix Asynchronous Operation
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

  template<typename R>
  AndNode<AioOp, R> operator&&(R const & r) const
  {
    AndNode<AioOp, R> a(*this, r);
    return a;
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

void wait(const aiocb * list[], size_t len)
{
  bool inProgress;
  do
  {
    if (aio_suspend(list, len, NULL))
      throw IOError(errno EARGS);

    inProgress = false;
    for (unsigned i=0; i<len; ++i)
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

typedef std::vector<const aiocb*> WaitList;
        
template<typename WAIT_EXPR>
void wait(WAIT_EXPR expr)
{
  // Since the list values are known at compile-time, it'd wouldn't be
  // impossible to put them in a recursive struct, which could be cast
  // as an array and passed to aio_suspend. It's not really worth the
  // trouble though since if I ever implement the cooperating threading
  // scheme the list'll need to be built dynamically.
  WaitList waitList;
  buildList(waitList, expr);
  wait(&*waitList.begin(), waitList.size());
}
        
template<typename LEFT, typename RIGHT>
static inline void buildList(WaitList & waitList, AndNode<LEFT, RIGHT> const & node)
{
  buildList(waitList, node.left);
  buildList(waitList, node.right);
}

static inline void buildList(WaitList & waitList, aiocb const * value)
{
  waitList.push_back(value);
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
      wait(readOp && writeOp);

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
