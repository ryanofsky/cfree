#include <aio.h>
#include <errno.h>
#include <iostream>
#include <vector>

/* Test program to start building an asynchronous i/o 
 * framework. Things that gots to be done
 *
 * 1) Wait function needs to return error information.
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

struct NullType;

// Forward declaration
template <typename OPERATION, typename RESULT>
struct ResultNode;

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
    typedef ResultNode<OPERAND, NullType> type;
    static void assign(type &member, OPERAND &operand)
    {
      member.operation = &operand;
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

  // Why the multiple declarations? The constructors must accept non-const
  // reference arguments because we store non-const pointers to AsynchOp
  // objects so they can be modified by wait(). But since we must accept 
  // rvalues to support nested expressions, and the current C++ standard
  // doesn't allow non-const references to rvalues, we have to accept const
  // references as well. The ideal solution would be to accept rvalue 
  // references, which have been proposed for a future version of C++, and
  // would match both types of arguments. In the meantime, just catch
  // both types of arguments by exhausting the combinations.
  AndNode(LEFT & left_, RIGHT & right_)
  {
    Operand2Member<Left>::assign(left, left_);
    Operand2Member<Right>::assign(right, right_);
  }

  AndNode(LEFT const & left_, RIGHT & right_)
  {
    Operand2Member<Left>::assign(left, left_);
    Operand2Member<Right>::assign(right, right_);
  }

  AndNode(LEFT & left_, RIGHT const & right_)
  {
    Operand2Member<Left>::assign(left, left_);
    Operand2Member<Right>::assign(right, right_);
  }

  AndNode(LEFT const & left_, RIGHT const & right_)
  {
    Operand2Member<Left>::assign(left, left_);
    Operand2Member<Right>::assign(right, right_);
  }

  AndNode()
  {
  }

  // accept non-const refs and rvalues (see "multiple declarations" above)
  template<typename R>
  AndNode<This, R> operator&&(R & r) const
  {
    AndNode<This, R> a(*this, r);
    return a;
  }

  template<typename R>
  AndNode<This, R> operator&&(R const & r) const
  {
    AndNode<This, R> a(*this, r);
    return a;
  }  
};

//! Expression template for holding >> operands in wait expressions
template <typename OPERATION, typename RESULT>
struct ResultNode
{
  typedef ResultNode<OPERATION, RESULT> This;

  enum {EXPR_LEAF=false};

  ResultNode(OPERATION & operation_, RESULT & result_)
  : operation(&operation_), result(&result_)
  {}

  ResultNode()
  : operation(NULL), result(NULL)
  {}

  // accept non-const refs and rvalues (see "multiple declarations" above)
  template<typename R>
  AndNode<This, R> operator&&(R & r) const
  {
    AndNode<This, R> a(*this, r);
    return a;
  }

  template<typename R>
  AndNode<This, R> operator&&(R const & r) const
  {
    AndNode<This, R> a(*this, r);
    return a;
  }
  
  OPERATION * operation;
  RESULT * result;
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
  AndNode<AioOp, R> operator&&(R & r)
  {
    AndNode<AioOp, R> n(*this, r);
    return n;
  }

  template<typename R>
  ResultNode<AioOp, R> operator>>(R & r)
  {
    ResultNode<AioOp, R> n(*this, r);
    return n;
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

  struct Result
  {
    aiocb * cb;

    int bytesRead()
    {
      return aio_return(cb);
    }
  };
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

template<typename OPERATION>
static inline void 
buildList(WaitList & waitList, ResultNode<OPERATION, NullType> const & node)
{
  waitList.push_back(node.operation);
}

template<typename OPERATION, typename RESULT>
static inline void 
buildList(WaitList & waitList, ResultNode<OPERATION, RESULT> const & node)
{
  waitList.push_back(node.operation);
  node.result->cb = node.operation;
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
      ReadOp::Result readResult;
      wait(readOp >> readResult && writeOp);

      ssize_t readLen = readResult.bytesRead();
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
