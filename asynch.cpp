#include <stdexcept>
#include <iostream>
#include <sstream>

#include "ace/Asynch_IO.h"
#include "ace/Asynch_Connector.h"
#include "ace/Basic_Types.h"
#include "ace/Message_Block.h"
#include "ace/OS_main.h"
#include "ace/Proactor.h"

struct MyClient : public ACE_Service_Handler
{
  virtual void addresses(const ACE_INET_Addr &remote_address,
                         const ACE_INET_Addr &local_address)
  {
    ACE_DEBUG((LM_DEBUG,
               ACE_TEXT ("[%D] Connection initiated from %s:%i to %s:%i\n"),
               local_address.get_host_addr(),
               (int)local_address.get_port_number(),
               remote_address.get_host_addr(),
               (int)remote_address.get_port_number()));
  }

  virtual void open(ACE_HANDLE handle, ACE_Message_Block&)
  {
    ACE_DEBUG((LM_DEBUG, ACE_TEXT ("[%D] Writing message \"%s\"\n"),
               this->message.base(),
               this->message.data_block()->size()));

    this->handle(handle);

    if (this->writer.open (*this) != 0)
      throw std::runtime_error("Could not open writer");

    if (this->writer.write(message, message.length()))
      throw std::runtime_error("Could not initiate write");
  }

  virtual void handle_write_stream(const ACE_Asynch_Write_Stream::Result &result)
  {
    ACE_DEBUG((LM_DEBUG, ACE_TEXT ("[%D] Write completed\n")));

    if (ACE_OS::shutdown (this->handle(), ACE_SHUTDOWN_WRITE))
      throw std::runtime_error("shutdown failed");

        ACE_DEBUG((LM_DEBUG, ACE_TEXT ("[%D] Shut down socket\n")));

    delete this;
  }

  virtual ~MyClient()
  {
    if (this->handle() != ACE_INVALID_HANDLE)
    {
      if (ACE_OS::closesocket(this->handle()))
        ACE_DEBUG((LM_ERROR,
                   ACE_TEXT ("[%D] Error: closesocket failed")));

          ACE_DEBUG((LM_DEBUG, ACE_TEXT ("[%D] Closed socket\n")));

      this->proactor()->proactor_end_event_loop();
      ACE_DEBUG((LM_DEBUG, ACE_TEXT ("[%D] Shut down proactor\n")));
    }
  }

  ACE_Message_Block message;
  ACE_Asynch_Write_Stream writer;
};

struct MyConnector : public ACE_Asynch_Connector<MyClient>
{
  MyConnector(const char * message_) : message(message_) {}

  MyClient * make_handler()
  {
    MyClient * handler = ACE_Asynch_Connector<MyClient>::make_handler();
    if (handler)
    {
          handler->message.init(this->message, strlen(this->message));
      handler->message.wr_ptr(handler->message.end());
    }
    return handler;
  }

  const char * message;
};

static bool parseArgs(int argc, char **argv, const char *& message,
                      ACE_UINT16 &port)
{
  if (argc > 1 && std::istringstream(argv[1]) >> port)
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

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  // read arguments
  ACE_UINT16 port;
  const char * message;

  if (!parseArgs(argc, argv, message, port))
  {
    ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("Usage: %s port [message]\n\n"),
                argv[0]));
    ACE_DEBUG ((LM_DEBUG,
                ACE_TEXT ("If message is specified, connects to ")
                ACE_TEXT ("port and sends message, otherwise ")
                ACE_TEXT ("listens on port for messages.\n")));
    return 1;
  }

  try
  {
    if (message)
    {
      MyConnector * connector = new MyConnector(message);

      if (connector->open(1, ACE_Proactor::instance()) == -1)
        ACE_ERROR_RETURN ((LM_ERROR, "%p open failed, errno = %d.\n",
                           errno), 1);

      ACE_INET_Addr address (port, ACE_LOCALHOST);
      if (connector->connect(address) == -1)
        ACE_ERROR_RETURN ((LM_ERROR, "%p connect failed, errno = %d.\n",
                           errno), 1);

      ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("[%D] Connecting to port %i\n"), (int)port));
    }
    else
    {
      //ACE_Asynch_Acceptor<> acceptor;
    }

    ACE_Proactor::instance()->proactor_run_event_loop ();
  }
  catch (std::exception & e)
  {
    ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("[%D] Caught std::exception \"%s\"\n"),
               e.what()));
  }

  return 0;
}
