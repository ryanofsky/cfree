#include <stdexcept>
#include <iostream>
#include <sstream>

#include "ace/Asynch_IO.h"
#include "ace/Asynch_Acceptor.h"
#include "ace/Asynch_Connector.h"
#include "ace/Basic_Types.h"
#include "ace/Message_Block.h"
#include "ace/OS_main.h"
#include "ace/Proactor.h"

const int RECV_BUFFER_SIZE = 32;

struct MyClient : public ACE_Service_Handler
{
  virtual void addresses(const ACE_INET_Addr &remote_address,
                         const ACE_INET_Addr &local_address)
  {
    ACE_DEBUG((LM_DEBUG,
               ACE_TEXT("[%D] Connection initiated from %s:%i to %s:%i\n"),
               local_address.get_host_addr(),
               (int)local_address.get_port_number(),
               remote_address.get_host_addr(),
               (int)remote_address.get_port_number()));
  }

  virtual void open(ACE_HANDLE handle, ACE_Message_Block &)
  {
    ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D] Writing message \"%.*s\"\n"),
               this->message.length(), this->message.base()));

    this->handle(handle);

    if (this->writer.open(*this) != 0)
      throw std::runtime_error("Could not open writer");

    if (this->writer.write(message, message.length()))
      throw std::runtime_error("Could not initiate write");
  }

  virtual void
  handle_write_stream(const ACE_Asynch_Write_Stream::Result &result)
  {
    if (result.success())
      ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D] Wrote %i bytes\n"),
                 result.bytes_transferred()));
    else
      ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D] Write error %u: %s\n"),
                 result.error(), ACE_OS::strerror(result.error())));

    if (ACE_OS::shutdown(this->handle(), ACE_SHUTDOWN_WRITE))
      throw std::runtime_error("shutdown failed");
    ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D] Shut down socket\n")));

    delete this;
  }

  virtual ~MyClient()
  {
    if (this->handle() != ACE_INVALID_HANDLE)
    {
      if (ACE_OS::closesocket(this->handle()))
        ACE_DEBUG((LM_ERROR, ACE_TEXT("[%D] Error: closesocket failed")));
      ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D] Closed socket\n")));

      this->proactor()->proactor_end_event_loop();
      ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D] Shut down proactor\n")));
    }
  }

  ACE_Message_Block message;
  ACE_Asynch_Write_Stream writer;
};

struct MyConnector : public ACE_Asynch_Connector<MyClient>
{
  MyConnector(ACE_TCHAR const *message_) 
  : message(ACE_TEXT_ALWAYS_CHAR(message_)) {}

  MyClient *make_handler()
  {
    MyClient *handler = ACE_Asynch_Connector<MyClient>::make_handler();
    if (handler)
    {
      handler->message.init(this->message, strlen(this->message));
      handler->message.wr_ptr(handler->message.end());
    }
    return handler;
  }

  const char *message;
};

struct MyServer : public ACE_Service_Handler
{
  MyServer() : buffer(RECV_BUFFER_SIZE), connection(++connections) {}

  virtual void addresses(const ACE_INET_Addr &remote_address,
                         const ACE_INET_Addr &local_address)
  {
    ACE_DEBUG((LM_DEBUG,
               ACE_TEXT("[%D, %i] Connection recieved from %s:%i on %s:%i\n"),
               this->connection,
               remote_address.get_host_addr(),
               (int)remote_address.get_port_number(),
               local_address.get_host_addr(),
               (int)local_address.get_port_number()));
  }

  virtual void open(ACE_HANDLE handle, ACE_Message_Block &)
  {
    this->handle(handle);
    this->read();
  }

  void read()
  {
    ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D, %i] Reading message\n"),
               this->connection));

    this->buffer.wr_ptr(this->buffer.base());

    if (this->reader.open(*this) != 0)
      throw std::runtime_error("Could not open reader");

    if (this->reader.read(buffer, buffer.space()))
      throw std::runtime_error("Could not initiate read");
  }

  virtual void handle_read_stream(const ACE_Asynch_Read_Stream::Result &result)
  {
    if (result.success())
      ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D, %i] Received message \"%.*s\"\n"),
                 this->connection, this->buffer.length(),
                 this->buffer.rd_ptr()));
    else
      ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D, %i] Write error %u: %s\n"),
                 this->connection, result.error(),
                 ACE_OS::strerror(result.error())));


    if (result.bytes_transferred())
      this->read();
    else
    {
      ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D, %i] Shutting down socket\n"),
                 this->connection));

      if (ACE_OS::shutdown(this->handle(), ACE_SHUTDOWN_WRITE))
        throw std::runtime_error("shutdown failed");

      ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D, %i] Shut down socket\n"),
                 this->connection));

      delete this;
    }
  }

  virtual ~MyServer()
  {
    if (this->handle() != ACE_INVALID_HANDLE)
    {
      if (ACE_OS::closesocket(this->handle()))
        ACE_DEBUG((LM_ERROR,
                   ACE_TEXT("[%D, %i] Error: closesocket failed"),
                   this->connection));

          ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D, %i] Closed socket\n"),
                     this->connection));
    }
  }

  ACE_Message_Block buffer;
  ACE_Asynch_Read_Stream reader;
  int connection;
  static int connections;
};

int MyServer::connections = 0;

typedef ACE_Asynch_Acceptor<MyServer> MyAcceptor;

static bool parseArgs(int argc, ACE_TCHAR **argv, const ACE_TCHAR *& message,
                      ACE_UINT16 &port)
{
  typedef std::basic_istringstream<ACE_TCHAR> istringstream;
  if (argc > 1 && istringstream(argv[1]) >> port)
  {
    if (argc == 2)
    {
      message = NULL;
      return true;
    }
    else if (argc == 3)
    {
      message = argv[2];
      return true;
    }
  }
  return false;
}

int ACE_TMAIN(int argc, ACE_TCHAR *argv[])
{
  // read ar  guments
  ACE_UINT16 port;
  ACE_TCHAR const *message;

  if (!parseArgs(argc, argv, message, port))
  {
    ACE_DEBUG((LM_DEBUG, ACE_TEXT("Usage: %s port [message]\n\n"),
               argv[0]));
    ACE_DEBUG((LM_DEBUG,
               ACE_TEXT("If message is specified, connects to ")
               ACE_TEXT("port and sends message, otherwise ")
               ACE_TEXT("listens on port for messages.\n")));
    return 1;
  }

  try
  {
    if (message)
    {
      MyConnector * connector = new MyConnector(message);

      if (connector->open(1, ACE_Proactor::instance()) == -1)
        ACE_ERROR_RETURN((LM_ERROR, ACE_TEXT("%p open failed, errno = %d.\n"),
                          errno), 1);

      ACE_INET_Addr address(port, ACE_LOCALHOST);
      if (connector->connect(address) == -1)
        ACE_ERROR_RETURN((LM_ERROR, 
                          ACE_TEXT("%p connect failed, errno = %d.\n"),
                          errno), 1);

      ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D] Connecting to port %i\n"), 
                 (int)port));
    }
    else
    {
      MyAcceptor * acceptor = new MyAcceptor;

      ACE_INET_Addr address(port, ACE_LOCALHOST);
      if (acceptor->open(port, 0, 1, ACE_DEFAULT_BACKLOG, 1,
                         ACE_Proactor::instance()) == -1)
        ACE_ERROR_RETURN((LM_ERROR, ACE_TEXT("%p open failed, errno = %d.\n"),
                          errno), 1);

      if (acceptor->accept() == -1)
        ACE_ERROR_RETURN((LM_ERROR,
                          ACE_TEXT("%p accept failed, errno = %d.\n"), errno),
                         1);

      ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D] Accepting connections on port %i\n"),
                 (int)port));
   }

    ACE_Proactor::instance()->proactor_run_event_loop();
  }
  catch (std::exception & e)
  {
    ACE_DEBUG((LM_DEBUG, ACE_TEXT("[%D] Caught std::exception \"%s\"\n"),
               e.what()));
  }
  return 0;
}
