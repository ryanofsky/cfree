#include "crypto++/socketft.h"
#include "crypto++/misc.h"
#include "crypto++/integer.h"
#include "crypto++/dh.h"
#include "crypto++/rijndael.h"
#include "crypto++/osrng.h"
#include "crypto++/des.h"
#include "crypto++/modes.h"
#include "crypto++/hex.h"
#include "crypto++/files.h"
#include <stdexcept>
#include <iostream>
#include <sstream>

using namespace CryptoPP;
using std::cout;
using std::endl;


/*- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -
  Crypto Parameters
- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -*/

byte DHgroup_Modulus[128] =
{
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
  0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
  0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
  0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
  0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
  0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

byte DHgroup_Generator[1] = { 0x2 };

byte DSAgroupC_Modulus[128] =
{
  0xcb, 0x0a, 0x78, 0x2c, 0x7a, 0xbf, 0xf4, 0x92,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x02, 0x3d, 0x66, 0x28,
  0x54, 0xa1, 0x0e, 0x52, 0xde, 0x49, 0xda, 0x38,
  0x3d, 0x9e, 0xe2, 0x1d, 0x7a, 0x33, 0x72, 0x13,
  0xd2, 0x4e, 0xd0, 0x96, 0xf9, 0x5a, 0x5d, 0x37,
  0xb8, 0x53, 0x7b, 0xba, 0xa5, 0x8a, 0x2a, 0x6b,
  0x26, 0xbd, 0x32, 0x8f, 0x6a, 0x32, 0xce, 0xc7,
  0x71, 0x80, 0xf7, 0x8d, 0x5b, 0xe4, 0x3d, 0x80,
  0xe8, 0x13, 0xe4, 0x01, 0x8d, 0x09, 0xda, 0x38,
  0xbd, 0x58, 0xfd, 0x61, 0x5c, 0x01, 0xfb, 0xab,
  0x49, 0x2e, 0xc2, 0x03, 0xc6, 0x9e, 0x3d, 0xa9,
  0xfd, 0x68, 0x2c, 0xe8, 0xaa, 0x98, 0xf1, 0x5a,
  0xd8, 0x05, 0x79, 0x70, 0xed, 0xb4, 0x4f, 0xe1,
  0xed, 0x08, 0xe0, 0x46, 0x2e, 0x5b, 0x8d, 0x97
};

byte DSAgroupC_Divisor[20] =
{
  0xef, 0x1f, 0x7a, 0x7a, 0x73, 0x36, 0x2e, 0x52,
  0x65, 0x15, 0xf3, 0x48, 0x07, 0x5a, 0xee, 0x26,
  0x5e, 0x9e, 0xff, 0x45
};

byte DSAgroupC_Generator[128] =
{
  0x93, 0x01, 0x68, 0xde, 0x21, 0xe7, 0xfb, 0x66,
  0xc0, 0x37, 0x5e, 0x08, 0xe9, 0x64, 0x25, 0x5a,
  0x0f, 0x7f, 0x0a, 0xd5, 0x45, 0x07, 0xa5, 0x18,
  0x64, 0xaf, 0xdc, 0x68, 0x6f, 0x36, 0xbe, 0x8b,
  0xb8, 0xb7, 0x86, 0x54, 0x08, 0x11, 0x60, 0x60,
  0xc5, 0xf3, 0x4f, 0x94, 0xb5, 0x14, 0x6c, 0xbe,
  0xf9, 0xe4, 0xad, 0xb7, 0x03, 0x24, 0xfb, 0xa0,
  0x1d, 0x34, 0xc1, 0xc6, 0x08, 0x17, 0xcb, 0xad,
  0xf6, 0x85, 0x4d, 0x65, 0x41, 0x76, 0xcb, 0x39,
  0x1d, 0xe0, 0xd4, 0x1e, 0x0f, 0x0f, 0xbb, 0xc8,
  0xce, 0xea, 0x55, 0x46, 0xc0, 0x9a, 0x67, 0x6b,
  0x0d, 0x9a, 0x99, 0x88, 0xc7, 0xa1, 0xce, 0x36,
  0xce, 0x31, 0x59, 0x60, 0x37, 0xa1, 0x8b, 0x4d,
  0x54, 0x03, 0x74, 0xbd, 0xf2, 0xad, 0x07, 0x1a,
  0x3f, 0x8d, 0xd1, 0x01, 0x5a, 0x9d, 0x8b, 0xa0,
  0xf0, 0xd5, 0x1c, 0xde, 0x21, 0x2d, 0xb6, 0xda
};


/*- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -
  Crypto++ Adapter Functions

  The code in this section rounds off some rough edges of the Crypto++
  library to allow the freenet code to be implemented as simply as
  possible. The code here is shoddy, but safe, and hidden behind clean
  interfaces.
- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -*/

/* Pump source until the specified number of bytes is retrievable
   This function will only work on filter chains that output the same
   number of bytes that are inputted, as they are inputted. So, for
   example, it won't work with most chains containing HexDecoders
   or block ciphers. */
static void pumpOut(Source & bt, unsigned len)
{
  unsigned avail = bt.MaxRetrievable();
  if (len <= avail)
    return;

  bt.Pump(len - avail);

  if (len != bt.MaxRetrievable())
    throw std::runtime_error("didn't pump out the right number of bytes");
}

static void read(Source & bt, byte * buf, unsigned len)
{
  pumpOut(bt, len);
  if (len != bt.Get(buf, len))
    throw std::runtime_error("did not get byte *");
}

static void read(Source & bt, byte & b)
{
  pumpOut(bt, sizeof(b));
  if (sizeof(b) != bt.Get(b))
    throw std::runtime_error("did not get byte");
}

static void readWord16(Source & bt, word16 & w)
{
  pumpOut(bt, sizeof(w));
  if (sizeof(w) != bt.GetWord16(w))
    throw std::runtime_error("did not get word16");
}

static void write(BufferedTransformation & bt, byte const * buf, unsigned len)
{
  if (0 != bt.Put(buf, len))
    throw std::runtime_error("did not put byte *");
}

static void write(BufferedTransformation & bt, byte b)
{
  if (0 != bt.Put(b))
    throw std::runtime_error("did not put byte");
}

static void writeWord16(BufferedTransformation & bt, word16 w)
{
  if (0 != bt.PutWord16(w))
    throw std::runtime_error("did not put word16");
}

static void flush(BufferedTransformation & bt)
{
  bt.Flush(true);
}

/* emulate java's BigInteger.bitLength() method
   return # of bits in 2's complement representation, minus one */
static unsigned int bitLength(Integer const & i)
{
  unsigned l = i.BitCount();
  if (i.IsNegative() && i == -Integer::Power2(l-1))
    --l;
  return l;
}

/* Construct integer from unsigned big endian byte array */
#define INTEGER(x) Integer((x), sizeof((x)))

/* these typedefs are just copies of the typedefs inside 
   "DSA::SchemeOptions" which, for some reason, is private */
typedef DL_Keys_DSA::PublicKey DSA_PublicKey;
typedef DL_Keys_DSA::PrivateKey DSA_PrivateKey;
typedef DL_Algorithm_GDSA<Integer> DSA_SignatureAlgorithm;
typedef SHA DSA_HashFunction;

typedef PK_MessageAccumulatorImpl<DSA_HashFunction>
        DSA_MessageAccumulator;

// initialize accumulator used for signing
// this is just a hack to get access to DSA::Signers's protected
// RestartMessageAccumulator() method
static void
initAccumulator(DSA_MessageAccumulator & msg,
                DSA::Signer const & sign,
                RandomNumberGenerator & rng)
{
  struct MS : public DSA::Signer
  {
    void RestartMessageAccumulator(RandomNumberGenerator &rng, PK_MessageAccumulatorBase &ma) const
    {
      this->DSA::Signer::RestartMessageAccumulator(rng, ma);
    }
  };

  MS const & ms = *static_cast<MS const *>(&sign);
  ms.RestartMessageAccumulator(rng, msg);
}

// set cipher mode key and initialization vector
static void
setKey(CipherModeBase &mode, byte const *key, unsigned len, byte const *iv)
{
  mode.SetKey(key, len, MakeParameters("IV", iv)("FeedbackSize", 0));
}

// The following cheesy implementations of SocketSource and SocketSink
// were writtten to work around a deadlock that occurs when using
// Crypto++'s socket classes. I suspect this is due to a bug in those
// implementations, but I don't understand them well enough to find it.
class MySocketSource : public Source
{
public:
  MySocketSource(Socket & sock, bool pumpAll = false, BufferedTransformation *attachment = NULL)
    : Source(attachment), m_sock(sock), m_buf(4096), m_eof(false)
  {
    assert (!pumpAll);
  }

    unsigned int Pump2(unsigned long &byteCount, bool blocking=true)
    {
      unsigned long bytesLeft = byteCount;
      while (bytesLeft)
      {
        unsigned bytes = std::min(bytesLeft, (unsigned long)m_buf.size());
        bytes = m_sock.Receive(m_buf, bytes);
        if (bytes == 0)
        {
          m_eof = true;
          break;
        }
        bytesLeft -= bytes;

        bytes = this->AttachedTransformation()->Put(m_buf, bytes);
        assert (bytes == 0);
      }
      byteCount -= bytesLeft;
      return 0;
    }

    bool SourceExhausted() const
    {
      return m_eof;
    }

  unsigned int PumpMessages2(unsigned int &messageCount, bool blocking=true)
  {
    assert (false);
    return 0;
  }

protected:
  Socket & m_sock;
  SecByteBlock m_buf;
  bool m_eof;
};

class MySocketSink : public Bufferless<Sink>
{
public:
  MySocketSink(Socket & sock) : m_sock(sock)
  {}

    unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking)
    {
      assert (blocking);
      unsigned len = m_sock.Send(begin, length);
      assert(len == length);
      return 0;
    }

  unsigned int CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end=ULONG_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const
  {
    assert (false);
    return 0;
  }

  unsigned int GetMaxWaitObjectCount() const
  {
    assert (false);
    return 0;
  }

  void GetWaitObjects(WaitObjectContainer &container)
  {
    assert (false);
  }

  unsigned int TransferTo2(BufferedTransformation &target, unsigned long &byteCount, const std::string &channel=NULL_CHANNEL, bool blocking=true)
  {
    assert (false);
    return 0;
  }

protected:
  Socket & m_sock;
};

static void disableNagle(Socket & socket)
{
#ifdef _WINDOWS
  int one = 1;
  if (::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one)))
    throw std::runtime_error("no set option sucka");
#endif
}

static void
generateKeyPair(DL_GroupParameters_IntegerBased const & params,
                RandomNumberGenerator & rng,
                Integer & priv, Integer & pub)
{
  priv.Randomize(rng, Integer::One(), params.GetMaxExponent());
  pub = params.ExponentiateBase(priv);
}


/*- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -
  Freenet MPI Code

  Functions for reading and writing freenet multi-precision integers.
- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -*/

static void readMPI(Source & bt, Integer & i)
{
  word16 bits;
  readWord16(bt, bits);
  unsigned len = BitsToBytes(bits+1);
  pumpOut(bt, len);
  i.Decode(bt, len, Integer::SIGNED);
}

static void writeMPI(BufferedTransformation & bt, Integer const & i)
{
  unsigned bits = bitLength(i);
  writeWord16(bt, bits);
  unsigned len = BitsToBytes(bits+1);
  i.Encode(bt, len, Integer::SIGNED);
}

/* interpret value in buf as a nonnegative big endian integer and send as
   a freenet mpi */
static void writeMPI(BufferedTransformation & bt, const byte * buf, unsigned len)
{
  // skip leading null bytes
  while(*buf == 0 && len > 0)
  {
    ++buf;
    --len;
  }

  // special case for sending 0
  if (len == 0)
  {
    writeWord16(bt, 0);
    write(bt, '\0');
    return;
  }

  // find magnitude of high byte
  unsigned bitCount = BitPrecision(*buf);

  // send ceil(log2(number + 1))
  writeWord16(bt, (len-1) * 8 + bitCount);

  // pad with extra byte if neccessary to make rightmost bit zero
  if (bitCount == 8)
    write(bt, '\0');

  // send number
  write(bt, buf, len);
}

static void readMPI(Source &bt, byte * buf, unsigned len)
{
  // read length of number's minimal representation in bits (assuming not < 0)
  word16 bits;
  readWord16(bt, bits);

  // convert to bytes
  unsigned bytes = BitsToBytes(bits);
  if (len < bytes)
    throw std::runtime_error("too beeg");

  // pad output with zeros if neccessary
  memset(buf, 0, len - bytes);

  // bits = BitPrecision(high byte) mod 8
  bits %= 8;

  // check sign bits when they reside in their own byte
  if (bits == 0)
  {
    byte b;
    read(bt, b);
    // barf if nonzero
    if (b != 0)
      if (b == 0xFF)
        throw std::runtime_error("too negative");
      else
        throw std::runtime_error("too malformed");
  }

  // read number
  read(bt, buf + len - bytes, bytes);

  // check sign bits when they are in the high byte
  if (bits != 0)
  {
    byte b = *buf >> bits;
    if (b != 0)
      if (b == (0xFF >> bits))
        throw std::runtime_error("too negative");
      else
        throw std::runtime_error("too malformed");
  }
}


/*- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -
  Connection Negotiation
- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -*/

const byte SILENT_BOB_BYTE = 0xfb;
const word16 DESIGNATOR = 1;
const byte AUTH_LAYER_VERSION = 0x01;
const byte VER_BIT_LENGTH = 5;
const byte AUTHENTICATE = 0x00;
const byte NEGOTIATION_MODE_MASK = 0x03;
const byte VER_BIT_MASK = 0x1f;

// encrypt buf, writing to bt
static void dlesEncrypt(BufferedTransformation & bt,
                        byte const * buf, unsigned len,
                        DSA_PublicKey const & publicKey,
                        RandomNumberGenerator & rng)
{
  // initialize parameters
  DH::GroupParameters grp;
  grp.Initialize(publicKey.GetGroupParameters());
  DH dh(grp);

  // generate ephermal keypair and send public key
  SecByteBlock ephermalPublic(dh.PublicKeyLength());
  SecByteBlock ephermalPrivate(dh.PrivateKeyLength());
  dh.GenerateKeyPair(rng, ephermalPrivate, ephermalPublic);
  writeMPI(bt, ephermalPublic, ephermalPublic.size());

  // encode public key so we can pass it to agreement interface
  SecByteBlock publicKeyVal(dh.PublicKeyLength());
  publicKey.GetPublicElement().Encode(publicKeyVal, publicKeyVal.size());

  // compute secret value
  SecByteBlock agreedValue(dh.AgreedValueLength());
  dh.Agree(agreedValue, ephermalPrivate, publicKeyVal);

  // hash secret value and public key
  SHA256 sha256;
  SecByteBlock hash(sha256.DigestSize());
  HashFilter hashbt(sha256, new ArraySink(hash, hash.size()));
  writeMPI(hashbt, ephermalPublic, ephermalPublic.size());
  writeMPI(hashbt, agreedValue, agreedValue.size());
  hashbt.MessageEnd();

  // encrypt message using first half of sha256 hash as key
  SecByteBlock encMessage(len), iv(NULL, Rijndael::BLOCKSIZE);
  CFB_Mode<Rijndael>::Encryption rijndael(&hash[0], 16, iv);
  StringSource(buf, len, true,
               new StreamTransformationFilter(rijndael,
               new ArraySink(encMessage, len)));

  // compute keyed hash of message using second half of sha256 hash as key
  HMAC<SHA1> hmac(&hash[16], 16);
  hmac.Update(encMessage, encMessage.size());
  SecByteBlock mac(hmac.DigestSize());
  hmac.Final(mac);

  // write results of keyed hash and encryption
  writeMPI(bt, mac, mac.size());
  writeMPI(bt, encMessage, encMessage.size());
}

// read from bt, decrypt and store in buf
static void dlesDecrypt(Source & bt,
                        byte * buf, unsigned len,
                        DSA_PrivateKey const & privateKey)
{
  // initialize parameters
  DH::GroupParameters grp;
  grp.Initialize(privateKey.GetGroupParameters());
  DH dh(grp);

  // read ephermal public key
  SecByteBlock ephermalPublic(dh.PublicKeyLength());
  readMPI(bt, ephermalPublic, ephermalPublic.size());

  // encode private key so we can pass it to agreement interface
  SecByteBlock privateKeyVal(dh.PrivateKeyLength());
  privateKey.GetPrivateExponent().Encode(privateKeyVal, privateKeyVal.size());

  // compute agreed value
  SecByteBlock agreedValue(dh.AgreedValueLength());
  dh.Agree(agreedValue, privateKeyVal, ephermalPublic);

  // hash to produce hmac and rijndael keys
  SHA256 sha256;
  SecByteBlock hash(sha256.DigestSize());
  HashFilter hashbt(sha256, new ArraySink(hash, hash.size()));
  writeMPI(hashbt, ephermalPublic, ephermalPublic.size());
  writeMPI(hashbt, agreedValue, agreedValue.size());
  hashbt.MessageEnd();

  // set up mac verifier
  HMAC<SHA1> hmac(&hash[16], 16);
  SecByteBlock mac(hmac.DigestSize()), encMessage(len);

  // read mac code and encrypted message
  readMPI(bt, mac, mac.size());
  readMPI(bt, encMessage, encMessage.size());

  // verify mac code
  hmac.Update(encMessage, encMessage.size());
  if (!hmac.Verify(mac))
    throw std::runtime_error("too fake");

  // decrypt message
  SecByteBlock iv(NULL, Rijndael::BLOCKSIZE);
  CFB_Mode<Rijndael>::Decryption rijndael(&hash[0], 16, iv);
  StringSource(encMessage, encMessage.size(), true,
               new StreamTransformationFilter(rijndael,
               new ArraySink(buf, len)));
}

// send a DSA signature
static void
writeSignature(BufferedTransformation & write,
               DSA::Signer & sign,
               DSA_MessageAccumulator & msg,
               RandomNumberGenerator & rng)
{
  // get information about dsa signature
  DL_GroupParameters_GFP const & params = sign.GetKey().GetGroupParameters();
  DSA_SignatureAlgorithm alg;
  unsigned rlen(alg.RLen(params)), slen(alg.SLen(params));

  // sign message
  SecByteBlock signature(rlen + slen);
  sign.SignAndRestart(rng, msg, signature, false);

  // send signature as two MPI's
  writeMPI(write, &signature[0], rlen);
  writeMPI(write, &signature[rlen], slen);
}

// receive a DSA signature and verify it
static void
readSignature(Source & bt,
              DSA::Verifier & verify,
              DSA_MessageAccumulator & msg)
{
  // get information about dsa signature
  DL_GroupParameters_GFP const & params = verify.GetKey().GetGroupParameters();
  DSA_SignatureAlgorithm alg;
  unsigned rlen(alg.RLen(params)), slen(alg.SLen(params));

  // receive signature as two MPI's
  SecByteBlock signature(rlen + slen);
  readMPI(bt, &signature[0], rlen);
  readMPI(bt, &signature[rlen], slen);

  // verify signature
  verify.InputSignature(msg, signature, signature.size());
  if (!verify.VerifyAndRestart(msg))
    throw std::runtime_error("bad signature");
}

byte zeroes[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

// generate key of specified length from entropy source. length of key must be
// 320 bytes or less. (320 = SHA::DIGESTSIZE * sizeof(zeroes))
static void
makeKey(const byte * entropy, unsigned entropyLen, byte * key, unsigned len)
{
  // more or less copied and pasted from
  // freenet.crypt.Util.makeKey(byte[], byte[], int, int)
  SHA ctx;

  int ic=0;
  while (len>0)
  {
    ic++;
    assert (ic <= sizeof(zeroes));
    ctx.Update(zeroes, ic);
    ctx.Update(entropy, entropyLen);
    int bc=ctx.DigestSize();
    if (len>bc)
    {
      ctx.Final(key);
    }
    else
    {
      bc=len;
      ctx.TruncatedFinal(key, bc);
    }
    key+=bc;
    len-=bc;
  }
}

// generate key of specified length using a key agreement algorithm
static void
makeKey(byte * key,
        unsigned len,
        SimpleKeyAgreementDomain & agree,
        byte const * privateKey,
        byte const * publicKey)
{
  // calculate secret value
  SecByteBlock agreedValue(agree.AgreedValueLength());
  agree.Agree(agreedValue, privateKey, publicKey);

  // put secret value in mpi form before we hash it
  SecByteBlock agreedValueMpi(agreedValue.size() + 3);
  ArraySink agreedValueMpiSink(agreedValueMpi, agreedValueMpi.size());
  writeMPI(agreedValueMpiSink, agreedValue, agreedValue.size());

  // do some fancy hashing of secret value to make key
  makeKey(agreedValueMpi, agreedValueMpiSink.TotalPutLength(), key, len);
}

static void
negotiateInbound(Socket & sock,
                 CFB_Mode<Rijndael>::Encryption & encryption,
                 CFB_Mode<Rijndael>::Decryption & decryption,
                 DSA::Signer & sign,
                 RandomNumberGenerator & rng,
                 SimpleKeyAgreementDomain & agree)
{
  MySocketSource sin(sock);
  MySocketSink sout(sock);

  word16 designator;
  readWord16(sin, designator);

  if (designator != DESIGNATOR)
    throw std::runtime_error("did not receive designator word");

  byte connType;
  read(sin, connType);

  if (((connType >> (8-VER_BIT_LENGTH)) & VER_BIT_MASK) != AUTH_LAYER_VERSION)
    throw std::runtime_error("wrong protocol version");

  byte negmode = connType & NEGOTIATION_MODE_MASK;

  // xxx: need to implement "RESTART" mode also
  if (negmode != AUTHENTICATE)
    throw std::runtime_error("unknown negotiation mode");

  // receive ephermal public key
  SecByteBlock yourEphermalPublic(agree.PublicKeyLength());
  readMPI(sin, yourEphermalPublic, yourEphermalPublic.size());

  // receive ephermal public key again, this time under DLES encryption
  SecByteBlock temp(yourEphermalPublic.size());
  dlesDecrypt(sin, temp, temp.size(), sign.GetKey());
  if (temp != yourEphermalPublic)
    throw std::runtime_error("connecting node sent two different keys");

  // send silent bob byte
  write(sout, SILENT_BOB_BYTE);

  // generate ephermal keypair
  SecByteBlock myEphermalPublic(agree.PublicKeyLength());
  SecByteBlock myEphermalPrivate(agree.PrivateKeyLength());
  agree.GenerateKeyPair(rng, myEphermalPrivate, myEphermalPublic);

  // send ephermal public key
  writeMPI(sout, myEphermalPublic, myEphermalPublic.size());

  // generate rijndael key using agreement algorithm and hashing
  SecByteBlock rijndaelKey(16);
  makeKey(rijndaelKey, rijndaelKey.size(), agree, myEphermalPrivate, yourEphermalPublic);

  // fill up pcfb initialization vector and send as plaintext
  SecByteBlock iv(Rijndael::BLOCKSIZE);
  rng.GenerateBlock(iv, iv.size());
  write(sout, iv, iv.size());
  flush(sout);

  // after this send everything via rijndael
  setKey(encryption, rijndaelKey, rijndaelKey.size(), iv);

  StreamTransformationFilter cwrite(encryption, new MySocketSink(sock));

  // put together a message we can proudly sign
  DSA_MessageAccumulator signMsg;
  initAccumulator(signMsg, sign, rng);
  HashFilter signbt(signMsg);
  writeMPI(signbt, yourEphermalPublic, yourEphermalPublic.size());
  writeMPI(signbt, myEphermalPublic, myEphermalPublic.size());

  // sign message and send signature
  writeSignature(cwrite, sign, signMsg, rng);
  flush(cwrite);

  // read iv and setup rijndael cfb receive transformation
  read(sin, iv, iv.size());
  setKey(decryption, rijndaelKey, rijndaelKey.size(), iv);
  MySocketSource cread(sock, false, new StreamTransformationFilter(decryption));
  sin.CopyTo(*cread.AttachedTransformation());

  // read other node's public key
  Integer yourPublic, yourModulus, yourDivisor, yourGenerator;
  readMPI(cread, yourPublic);
  readMPI(cread, yourModulus);
  readMPI(cread, yourDivisor);
  readMPI(cread, yourGenerator);
  DSA::Verifier verify(yourModulus, yourDivisor, yourGenerator, yourPublic);

  // put together the message that other node has proudly signed
  DSA_MessageAccumulator verifyMsg;
  HashFilter verifybt(verifyMsg);
  writeMPI(verifybt, yourModulus);
  writeMPI(verifybt, yourDivisor);
  writeMPI(verifybt, yourGenerator);
  writeMPI(verifybt, yourPublic);
  writeMPI(verifybt, yourEphermalPublic, yourEphermalPublic.size());
  writeMPI(verifybt, myEphermalPublic, myEphermalPublic.size());

  // read and verify signature
  readSignature(cread, verify, verifyMsg);
}

static void
negotiateOutbound(Socket & sock,
                  CFB_Mode<Rijndael>::Encryption encryption,
                  CFB_Mode<Rijndael>::Decryption decryption,
                  DSA::Verifier & verify,
                  RandomNumberGenerator & rng,
                  SimpleKeyAgreementDomain & agree,
                  DSA::Signer & sign,
                  const Integer & myPublic)
{
  MySocketSource sin(sock);
  MySocketSink sout(sock);

  // send header bytes
  writeWord16(sout, DESIGNATOR);
  write(sout, (AUTH_LAYER_VERSION << (8-VER_BIT_LENGTH)) + AUTHENTICATE);

  // generate ephermal keypair
  SecByteBlock myEphermalPublic(agree.PublicKeyLength());
  SecByteBlock myEphermalPrivate(agree.PrivateKeyLength());
  agree.GenerateKeyPair(rng, myEphermalPrivate, myEphermalPublic);

  // send ephermal public key as plaintext
  writeMPI(sout, myEphermalPublic, myEphermalPublic.size());

  // send ephermal public key again, this time encrypted with DLES
  dlesEncrypt(sout, myEphermalPublic, myEphermalPublic.size(),
              verify.GetKey(), rng);
  flush(sout);

  // retrieve silent bob byte
  byte sbb;
  read(sin, sbb);
  if (sbb != SILENT_BOB_BYTE)
    throw std::runtime_error("speech impediment bob");

  // retrieve other node's ephermal public key
  SecByteBlock yourEphermalPublic(agree.PublicKeyLength());
  readMPI(sin, yourEphermalPublic, yourEphermalPublic.size());

  // generate rijndael key using agreement algorithm and hashing
  SecByteBlock rijndaelKey(16);
  makeKey(rijndaelKey, rijndaelKey.size(), agree, myEphermalPrivate, yourEphermalPublic);

  // fill up pcfb initialization vector and send as plaintext
  SecByteBlock iv(Rijndael::BLOCKSIZE);
  rng.GenerateBlock(iv, iv.size());
  write(sout, iv, iv.size());
  flush(sout);

  // after this send everything via rijndael
  setKey(encryption, rijndaelKey, rijndaelKey.size(), iv);
  StreamTransformationFilter cwrite(encryption, new MySocketSink(sock));

  // send public key
  writeMPI(cwrite, myPublic);
  DL_GroupParameters_GFP const & signParams = sign.GetKey().GetGroupParameters();
  writeMPI(cwrite, signParams.GetModulus());
  writeMPI(cwrite, signParams.GetSubgroupOrder());
  writeMPI(cwrite, signParams.GetGenerator());

  // put together a message we can proudly sign
  DSA_MessageAccumulator signMsg;
  initAccumulator(signMsg, sign, rng);
  HashFilter signbt(signMsg);
  writeMPI(signbt, signParams.GetModulus());
  writeMPI(signbt, signParams.GetSubgroupOrder());
  writeMPI(signbt, signParams.GetGenerator());
  writeMPI(signbt, myPublic);
  writeMPI(signbt, myEphermalPublic, myEphermalPublic.size());
  writeMPI(signbt, yourEphermalPublic, yourEphermalPublic.size());

  // sign message and send signature
  writeSignature(cwrite, sign, signMsg, rng);
  flush(cwrite);

  // read iv and initialize rijndael cfb mode
  read(sin, iv, iv.size());
  setKey(decryption, rijndaelKey, rijndaelKey.size(), iv);
  MySocketSource cread(sock, false, new StreamTransformationFilter(decryption));
  sin.CopyTo(*cread.AttachedTransformation());

  // put together the message that other node has proudly signed
  DSA_MessageAccumulator verifyMsg;
  HashFilter verifybt(verifyMsg);
  writeMPI(verifybt, myEphermalPublic, myEphermalPublic.size());
  writeMPI(verifybt, yourEphermalPublic, yourEphermalPublic.size());

  // read and verify signature
  readSignature(cread, verify, verifyMsg);
}


/*- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -
  Test Code
- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -- - - -*/

byte serverPrivate[20] =
{
  0x50, 0x05, 0xee, 0x93, 0xc6, 0xf8, 0x1a, 0x48,
  0x14, 0x8b, 0xc1, 0x45, 0xb3, 0x1a, 0x9d, 0x2c,
  0xd0, 0x35, 0xb9, 0x10
};

byte serverPublic[128] =
{
  0xc9, 0xe5, 0x51, 0x80, 0x48, 0x8e, 0xd4, 0x47,
  0xf5, 0x78, 0x34, 0xe3, 0xa9, 0xb7, 0x09, 0xd5,
  0x76, 0xf9, 0x32, 0x18, 0x64, 0xef, 0x90, 0x18,
  0x47, 0xff, 0x02, 0xc0, 0xc8, 0x6f, 0xcf, 0x34,
  0x53, 0xe1, 0x00, 0xbf, 0x1a, 0x8d, 0x7f, 0x11,
  0x1e, 0xb2, 0x9f, 0x7b, 0x12, 0x00, 0xaa, 0xf5,
  0x60, 0x1a, 0x99, 0x0d, 0x5e, 0x73, 0xc5, 0x5c,
  0x39, 0xf8, 0xd8, 0x3a, 0xc6, 0x43, 0x8b, 0xc6,
  0xea, 0xef, 0x7d, 0xd7, 0x9d, 0xf1, 0x2e, 0xd9,
  0x8b, 0x54, 0xdd, 0x0b, 0x44, 0xc9, 0xf0, 0x41,
  0xd3, 0x37, 0x9a, 0xb3, 0xce, 0x12, 0xdd, 0x3a,
  0x99, 0x0f, 0xee, 0x37, 0x8a, 0x0b, 0x40, 0x4f,
  0x4b, 0x6e, 0x9b, 0x29, 0xe3, 0xf0, 0x7c, 0xda,
  0x2b, 0xac, 0xc2, 0xe7, 0xa9, 0x21, 0x45, 0x0d,
  0xf4, 0x0c, 0x7b, 0xbe, 0x3a, 0x16, 0x46, 0x89,
  0xc3, 0xb1, 0x56, 0x98, 0x45, 0xe2, 0x3c, 0xc4
};

static bool parseArgs(int argc, char **argv, bool &server, word16 &port)
{
  if (argc > 1 && std::istringstream(argv[1]) >> port)
  {
    if (argc == 2)
    {
      server = false;
      return true;
    }
    else if (argc == 3 && strcmp(argv[2], "server") == 0)
    {
      server = true;
      return true;
    }
  }
  return false;
}

int main(int argc, char **argv)
{
  try
  {
    // read arguments
    word16 port;
    bool server;

    if (!parseArgs(argc, argv, server, port))
    {
      std::cerr << "Usage: " << argv[0] << " port [\"server\"]" << endl;
      return 1;
    }

    // start real work
    AutoSeededX917RNG<DES_EDE3> rng;

    DL_GroupParameters_GFP_DefaultSafePrime DHgroup;
    DHgroup.Initialize(INTEGER(DHgroup_Modulus),
                       INTEGER(DHgroup_Generator));

    DL_GroupParameters_GFP_DefaultSafePrime DSAgroupC;
    DSAgroupC.Initialize(INTEGER(DSAgroupC_Modulus),
                         INTEGER(DSAgroupC_Divisor),
                         INTEGER(DSAgroupC_Generator));

    Socket::StartSockets();

    CFB_Mode<Rijndael>::Encryption encryption;
    CFB_Mode<Rijndael>::Decryption decryption;

    if (server)
    {
      cout << "servering on port " << port << endl;

      DH agree(DHgroup);
      DSA::Signer sign(DSAgroupC, INTEGER(serverPrivate));

      Socket listener, socket;
      listener.Create();
      listener.Bind(port);
      listener.Listen(5);
      listener.Accept(socket);
      disableNagle(socket);

      cout << "connected" << endl;

      negotiateInbound(socket, encryption, decryption, sign, rng, agree);

      cout << "negotiation successful" << endl;
    }
    else
    {
      cout << "clienting to port " << port << endl;

      Integer myPriv, myPub;
      generateKeyPair(DSAgroupC, rng, myPriv, myPub);

      DH agree(DHgroup);
      DSA::Verifier verify(DSAgroupC, INTEGER(serverPublic));
      DSA::Signer sign(DSAgroupC, myPriv);

      Socket socket;
      socket.Create();
      socket.Connect("localhost", port);
      disableNagle(socket);

      cout << "connected" << endl;

      negotiateOutbound(socket, encryption, decryption, verify,
                        rng, agree, sign, myPub);

      cout << "negotiation successful" << endl;
    }

    Socket::ShutdownSockets();
  }
  catch (std::exception & e)
  {
    std::cout << e.what() << std::endl;
  }

  return 0;
}
