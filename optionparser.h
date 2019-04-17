/*
 * The Lean Mean C++ Option Parser
 *
 * Copyright (C) 2012-2017 Matthias S. Benkmann
 *
 * The "Software" in the following 2 paragraphs refers to this file containing
 * the code to The Lean Mean C++ Option Parser.
 * The "Software" does NOT refer to any other files which you
 * may have received alongside this file (e.g. as part of a larger project that
 * incorporates The Lean Mean C++ Option Parser).
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software, to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * NOTE: It is recommended that you read the processed HTML doxygen documentation
 * rather than this source. If you don't know doxygen, it's like javadoc for C++.
 * If you don't want to install doxygen you can find a copy of the processed
 * documentation at
 *
 * http://optionparser.sourceforge.net/
 *
 */

#ifndef OPTIONPARSER_H_
#define OPTIONPARSER_H_

#ifdef _MSC_VER
#include <intrin.h>
#pragma intrinsic(_BitScanReverse)
#endif

namespace option
{

#ifdef _MSC_VER
struct MSC_Builtin_CLZ
{
  static int builtin_clz(unsigned x)
  {
    unsigned long index;
    _BitScanReverse(&index, x);
    return 32-index; // int is always 32bit on Windows, even for target x64
  }
};
#define __builtin_clz(x) MSC_Builtin_CLZ::builtin_clz(x)
#endif

class Option;

enum ArgStatus
{
  ARG_NONE,
  ARG_OK,
  ARG_IGNORE,
  ARG_ILLEGAL
};

typedef ArgStatus (*CheckArg)(const Option& option, bool msg);

struct Descriptor
{
  const unsigned index;

  const int type;

  const char* const shortopt;

  const char* const longopt;

  const CheckArg check_arg;

  const char* help;
};

class Option
{
  Option* next_;
  Option* prev_;
public:
  const Descriptor* desc;

  const char* name;

  const char* arg;

  int namelen;

  int type() const
  {
    return desc == 0 ? 0 : desc->type;
  }

  int index() const
  {
    return desc == 0 ? -1 : (int)desc->index;
  }

  int count() const
  {
    int c = (desc == 0 ? 0 : 1);
    const Option* p = first();
    while (!p->isLast())
    {
      ++c;
      p = p->next_;
    };
    return c;
  }

  bool isFirst() const
  {
    return isTagged(prev_);
  }

  bool isLast() const
  {
    return isTagged(next_);
  }

  Option* first()
  {
    Option* p = this;
    while (!p->isFirst())
      p = p->prev_;
    return p;
  }

  const Option* first() const
  {
    return const_cast<Option*>(this)->first();
  }

  Option* last()
  {
    return first()->prevwrap();
  }

  const Option* last() const
  {
    return first()->prevwrap();
  }

  Option* prev()
  {
    return isFirst() ? 0 : prev_;
  }

  Option* prevwrap()
  {
    return untag(prev_);
  }

  const Option* prevwrap() const
  {
    return untag(prev_);
  }

  Option* next()
  {
    return isLast() ? 0 : next_;
  }

  const Option* next() const
  {
    return isLast() ? 0 : next_;
  }

  Option* nextwrap()
  {
    return untag(next_);
  }

  void append(Option* new_last)
  {
    Option* p = last();
    Option* f = first();
    p->next_ = new_last;
    new_last->prev_ = p;
    new_last->next_ = tag(f);
    f->prev_ = tag(new_last);
  }

  operator const Option*() const
  {
    return desc ? this : 0;
  }

  operator Option*()
  {
    return desc ? this : 0;
  }

  Option() :
      desc(0), name(0), arg(0), namelen(0)
  {
    prev_ = tag(this);
    next_ = tag(this);
  }

  Option(const Descriptor* desc_, const char* name_, const char* arg_)
  {
    init(desc_, name_, arg_);
  }

  void operator=(const Option& orig)
  {
    init(orig.desc, orig.name, orig.arg);
  }

  Option(const Option& orig)
  {
    init(orig.desc, orig.name, orig.arg);
  }

private:
  void init(const Descriptor* desc_, const char* name_, const char* arg_)
  {
    desc = desc_;
    name = name_;
    arg = arg_;
    prev_ = tag(this);
    next_ = tag(this);
    namelen = 0;
    if (name == 0)
      return;
    namelen = 1;
    if (name[0] != '-')
      return;
    while (name[namelen] != 0 && name[namelen] != '=')
      ++namelen;
  }

  static Option* tag(Option* ptr)
  {
    return (Option*) ((unsigned long long) ptr | 1);
  }

  static Option* untag(Option* ptr)
  {
    return (Option*) ((unsigned long long) ptr & ~1ull);
  }

  static bool isTagged(Option* ptr)
  {
    return ((unsigned long long) ptr & 1);
  }
};

struct Arg
{
  static ArgStatus None(const Option&, bool)
  {
    return ARG_NONE;
  }

  static ArgStatus Optional(const Option& option, bool)
  {
    if (option.arg && option.name[option.namelen] != 0)
      return ARG_OK;
    else
      return ARG_IGNORE;
  }
};

struct Stats
{
  unsigned buffer_max;

  unsigned options_max;

  Stats() :
      buffer_max(1), options_max(1) // 1 more than necessary as sentinel
  {
  }

  Stats(bool gnu, const Descriptor usage[], int argc, const char** argv, int min_abbr_len = 0, //
        bool single_minus_longopt = false) :
      buffer_max(1), options_max(1) // 1 more than necessary as sentinel
  {
    add(gnu, usage, argc, argv, min_abbr_len, single_minus_longopt);
  }

  Stats(bool gnu, const Descriptor usage[], int argc, char** argv, int min_abbr_len = 0, //
        bool single_minus_longopt = false) :
      buffer_max(1), options_max(1) // 1 more than necessary as sentinel
  {
    add(gnu, usage, argc, (const char**) argv, min_abbr_len, single_minus_longopt);
  }

  Stats(const Descriptor usage[], int argc, const char** argv, int min_abbr_len = 0, //
        bool single_minus_longopt = false) :
      buffer_max(1), options_max(1) // 1 more than necessary as sentinel
  {
    add(false, usage, argc, argv, min_abbr_len, single_minus_longopt);
  }

  Stats(const Descriptor usage[], int argc, char** argv, int min_abbr_len = 0, //
        bool single_minus_longopt = false) :
      buffer_max(1), options_max(1) // 1 more than necessary as sentinel
  {
    add(false, usage, argc, (const char**) argv, min_abbr_len, single_minus_longopt);
  }

  void add(bool gnu, const Descriptor usage[], int argc, const char** argv, int min_abbr_len = 0, //
           bool single_minus_longopt = false);

  void add(bool gnu, const Descriptor usage[], int argc, char** argv, int min_abbr_len = 0, //
           bool single_minus_longopt = false)
  {
    add(gnu, usage, argc, (const char**) argv, min_abbr_len, single_minus_longopt);
  }

  void add(const Descriptor usage[], int argc, const char** argv, int min_abbr_len = 0, //
           bool single_minus_longopt = false)
  {
    add(false, usage, argc, argv, min_abbr_len, single_minus_longopt);
  }

  void add(const Descriptor usage[], int argc, char** argv, int min_abbr_len = 0, //
           bool single_minus_longopt = false)
  {
    add(false, usage, argc, (const char**) argv, min_abbr_len, single_minus_longopt);
  }
private:
  class CountOptionsAction;
};

class Parser
{
  int op_count; 
  int nonop_count; 
  const char** nonop_args; 
  bool err; 
public:

  Parser() :
      op_count(0), nonop_count(0), nonop_args(0), err(false)
  {
  }

  Parser(bool gnu, const Descriptor usage[], int argc, const char** argv, Option options[], Option buffer[],
         int min_abbr_len = 0, bool single_minus_longopt = false, int bufmax = -1) :
      op_count(0), nonop_count(0), nonop_args(0), err(false)
  {
    parse(gnu, usage, argc, argv, options, buffer, min_abbr_len, single_minus_longopt, bufmax);
  }

  Parser(bool gnu, const Descriptor usage[], int argc, char** argv, Option options[], Option buffer[],
         int min_abbr_len = 0, bool single_minus_longopt = false, int bufmax = -1) :
      op_count(0), nonop_count(0), nonop_args(0), err(false)
  {
    parse(gnu, usage, argc, (const char**) argv, options, buffer, min_abbr_len, single_minus_longopt, bufmax);
  }

  Parser(const Descriptor usage[], int argc, const char** argv, Option options[], Option buffer[], int min_abbr_len = 0,
         bool single_minus_longopt = false, int bufmax = -1) :
      op_count(0), nonop_count(0), nonop_args(0), err(false)
  {
    parse(false, usage, argc, argv, options, buffer, min_abbr_len, single_minus_longopt, bufmax);
  }

  Parser(const Descriptor usage[], int argc, char** argv, Option options[], Option buffer[], int min_abbr_len = 0,
         bool single_minus_longopt = false, int bufmax = -1) :
      op_count(0), nonop_count(0), nonop_args(0), err(false)
  {
    parse(false, usage, argc, (const char**) argv, options, buffer, min_abbr_len, single_minus_longopt, bufmax);
  }

  void parse(bool gnu, const Descriptor usage[], int argc, const char** argv, Option options[], Option buffer[],
             int min_abbr_len = 0, bool single_minus_longopt = false, int bufmax = -1);

  void parse(bool gnu, const Descriptor usage[], int argc, char** argv, Option options[], Option buffer[],
             int min_abbr_len = 0, bool single_minus_longopt = false, int bufmax = -1)
  {
    parse(gnu, usage, argc, (const char**) argv, options, buffer, min_abbr_len, single_minus_longopt, bufmax);
  }

  void parse(const Descriptor usage[], int argc, const char** argv, Option options[], Option buffer[],
             int min_abbr_len = 0, bool single_minus_longopt = false, int bufmax = -1)
  {
    parse(false, usage, argc, argv, options, buffer, min_abbr_len, single_minus_longopt, bufmax);
  }

  void parse(const Descriptor usage[], int argc, char** argv, Option options[], Option buffer[], int min_abbr_len = 0,
             bool single_minus_longopt = false, int bufmax = -1)
  {
    parse(false, usage, argc, (const char**) argv, options, buffer, min_abbr_len, single_minus_longopt, bufmax);
  }

  int optionsCount()
  {
    return op_count;
  }

  int nonOptionsCount()
  {
    return nonop_count;
  }

  const char** nonOptions()
  {
    return nonop_args;
  }

  const char* nonOption(int i)
  {
    return nonOptions()[i];
  }

  bool error()
  {
    return err;
  }

private:
  friend struct Stats;
  class StoreOptionAction;
  struct Action;

  static bool workhorse(bool gnu, const Descriptor usage[], int numargs, const char** args, Action& action,
                        bool single_minus_longopt, bool print_errors, int min_abbr_len);

  static bool streq(const char* st1, const char* st2)
  {
    while (*st1 != 0)
      if (*st1++ != *st2++)
        return false;
    return (*st2 == 0 || *st2 == '=');
  }

  static bool streqabbr(const char* st1, const char* st2, long long min)
  {
    const char* st1start = st1;
    while (*st1 != 0 && (*st1 == *st2))
    {
      ++st1;
      ++st2;
    }

    return (*st1 == 0 || (min > 0 && (st1 - st1start) >= min)) && (*st2 == 0 || *st2 == '=');
  }

  static bool instr(char ch, const char* st)
  {
    while (*st != 0 && *st != ch)
      ++st;
    return *st == ch;
  }

  static void shift(const char** args, int count)
  {
    for (int i = 0; i > -count; --i)
    {
      const char* temp = args[i];
      args[i] = args[i - 1];
      args[i - 1] = temp;
    }
  }
};

struct Parser::Action
{
  virtual bool perform(Option&)
  {
    return true;
  }

  virtual bool finished(int numargs, const char** args)
  {
    (void) numargs;
    (void) args;
    return true;
  }
};

class Stats::CountOptionsAction: public Parser::Action
{
  unsigned* buffer_max;
public:
  CountOptionsAction(unsigned* buffer_max_) :
      buffer_max(buffer_max_)
  {
  }

  bool perform(Option&)
  {
    if (*buffer_max == 0x7fffffff)
      return false; // overflow protection: don't accept number of options that doesn't fit signed int
    ++*buffer_max;
    return true;
  }
};

class Parser::StoreOptionAction: public Parser::Action
{
  Parser& parser;
  Option* options;
  Option* buffer;
  int bufmax; 
public:
  StoreOptionAction(Parser& parser_, Option options_[], Option buffer_[], int bufmax_) :
      parser(parser_), options(options_), buffer(buffer_), bufmax(bufmax_)
  {
    // find first empty slot in buffer (if any)
    int bufidx = 0;
    while ((bufmax < 0 || bufidx < bufmax) && buffer[bufidx])
      ++bufidx;

    // set parser's optionCount
    parser.op_count = bufidx;
  }

  bool perform(Option& option)
  {
    if (bufmax < 0 || parser.op_count < bufmax)
    {
      if (parser.op_count == 0x7fffffff)
        return false; // overflow protection: don't accept number of options that doesn't fit signed int

      buffer[parser.op_count] = option;
      int idx = buffer[parser.op_count].desc->index;
      if (options[idx])
        options[idx].append(buffer[parser.op_count]);
      else
        options[idx] = buffer[parser.op_count];
      ++parser.op_count;
    }
    return true; // NOTE: an option that is discarded because of a full buffer is not fatal
  }

  bool finished(int numargs, const char** args)
  {
    // only overwrite non-option argument list if there's at least 1
    // new non-option argument. Otherwise we keep the old list. This
    // makes it easy to use default non-option arguments.
    if (numargs > 0)
    {
      parser.nonop_count = numargs;
      parser.nonop_args = args;
    }

    return true;
  }
};

inline void Parser::parse(bool gnu, const Descriptor usage[], int argc, const char** argv, Option options[],
                          Option buffer[], int min_abbr_len, bool single_minus_longopt, int bufmax)
{
  StoreOptionAction action(*this, options, buffer, bufmax);
  err = !workhorse(gnu, usage, argc, argv, action, single_minus_longopt, true, min_abbr_len);
}

inline void Stats::add(bool gnu, const Descriptor usage[], int argc, const char** argv, int min_abbr_len,
                       bool single_minus_longopt)
{
  // determine size of options array. This is the greatest index used in the usage + 1
  int i = 0;
  while (usage[i].shortopt != 0)
  {
    if (usage[i].index + 1 >= options_max)
      options_max = (usage[i].index + 1) + 1; // 1 more than necessary as sentinel

    ++i;
  }

  CountOptionsAction action(&buffer_max);
  Parser::workhorse(gnu, usage, argc, argv, action, single_minus_longopt, false, min_abbr_len);
}

inline bool Parser::workhorse(bool gnu, const Descriptor usage[], int numargs, const char** args, Action& action,
                              bool single_minus_longopt, bool print_errors, int min_abbr_len)
{
  // protect against NULL pointer
  if (args == 0)
    numargs = 0;

  int nonops = 0;

  while (numargs != 0 && *args != 0)
  {
    const char* param = *args; // param can be --long-option, -srto or non-option argument

    // in POSIX mode the first non-option argument terminates the option list
    // a lone minus character is a non-option argument
    if (param[0] != '-' || param[1] == 0)
    {
      if (gnu)
      {
        ++nonops;
        ++args;
        if (numargs > 0)
          --numargs;
        continue;
      }
      else
        break;
    }

    // -- terminates the option list. The -- itself is skipped.
    if (param[1] == '-' && param[2] == 0)
    {
      shift(args, nonops);
      ++args;
      if (numargs > 0)
        --numargs;
      break;
    }

    bool handle_short_options;
    const char* longopt_name;
    if (param[1] == '-') // if --long-option
    {
      handle_short_options = false;
      longopt_name = param + 2;
    }
    else
    {
      handle_short_options = true;
      longopt_name = param + 1; //for testing a potential -long-option
    }

    bool try_single_minus_longopt = single_minus_longopt;
    bool have_more_args = (numargs > 1 || numargs < 0); // is referencing argv[1] valid?

    do // loop over short options in group, for long options the body is executed only once
    {
      int idx = 0;

      const char* optarg = 0;

      /******************** long option **********************/
      if (handle_short_options == false || try_single_minus_longopt)
      {
        idx = 0;
        while (usage[idx].longopt != 0 && !streq(usage[idx].longopt, longopt_name))
          ++idx;

        if (usage[idx].longopt == 0 && min_abbr_len > 0) // if we should try to match abbreviated long options
        {
          int i1 = 0;
          while (usage[i1].longopt != 0 && !streqabbr(usage[i1].longopt, longopt_name, min_abbr_len))
            ++i1;
          if (usage[i1].longopt != 0)
          { // now test if the match is unambiguous by checking for another match
            int i2 = i1 + 1;
            while (usage[i2].longopt != 0 && !streqabbr(usage[i2].longopt, longopt_name, min_abbr_len))
              ++i2;

            if (usage[i2].longopt == 0) // if there was no second match it's unambiguous, so accept i1 as idx
              idx = i1;
          }
        }

        // if we found something, disable handle_short_options (only relevant if single_minus_longopt)
        if (usage[idx].longopt != 0)
          handle_short_options = false;

        try_single_minus_longopt = false; // prevent looking for longopt in the middle of shortopt group

        optarg = longopt_name;
        while (*optarg != 0 && *optarg != '=')
          ++optarg;
        if (*optarg == '=') // attached argument
          ++optarg;
        else
          // possibly detached argument
          optarg = (have_more_args ? args[1] : 0);
      }

      /************************ short option ***********************************/
      if (handle_short_options)
      {
        if (*++param == 0) // point at the 1st/next option character
          break; // end of short option group

        idx = 0;
        while (usage[idx].shortopt != 0 && !instr(*param, usage[idx].shortopt))
          ++idx;

        if (param[1] == 0) // if the potential argument is separate
          optarg = (have_more_args ? args[1] : 0);
        else
          // if the potential argument is attached
          optarg = param + 1;
      }

      const Descriptor* descriptor = &usage[idx];

      if (descriptor->shortopt == 0) /**************  unknown option ********************/
      {
        // look for dummy entry (shortopt == "" and longopt == "") to use as Descriptor for unknown options
        idx = 0;
        while (usage[idx].shortopt != 0 && (usage[idx].shortopt[0] != 0 || usage[idx].longopt[0] != 0))
          ++idx;
        descriptor = (usage[idx].shortopt == 0 ? 0 : &usage[idx]);
      }

      if (descriptor != 0)
      {
        Option option(descriptor, param, optarg);
        switch (descriptor->check_arg(option, print_errors))
        {
          case ARG_ILLEGAL:
            return false; // fatal
          case ARG_OK:
            // skip one element of the argument vector, if it's a separated argument
            if (optarg != 0 && have_more_args && optarg == args[1])
            {
              shift(args, nonops);
              if (numargs > 0)
                --numargs;
              ++args;
            }

            // No further short options are possible after an argument
            handle_short_options = false;

            break;
          case ARG_IGNORE:
          case ARG_NONE:
            option.arg = 0;
            break;
        }

        if (!action.perform(option))
          return false;
      }

    } while (handle_short_options);

    shift(args, nonops);
    ++args;
    if (numargs > 0)
      --numargs;

  } // while

  if (numargs > 0 && *args == 0) // It's a bug in the caller if numargs is greater than the actual number
    numargs = 0; // of arguments, but as a service to the user we fix this if we spot it.

  if (numargs < 0) // if we don't know the number of remaining non-option arguments
  { // we need to count them
    numargs = 0;
    while (args[numargs] != 0)
      ++numargs;
  }

  return action.finished(numargs + nonops, args - nonops);
}

struct PrintUsageImplementation
{
  struct IStringWriter
  {
    virtual void operator()(const char*, int)
    {
    }
  };

  template<typename Function>
  struct FunctionWriter: public IStringWriter
  {
    Function* write;

    virtual void operator()(const char* str, int size)
    {
      (*write)(str, size);
    }

    FunctionWriter(Function* w) :
        write(w)
    {
    }
  };

  template<typename OStream>
  struct OStreamWriter: public IStringWriter
  {
    OStream& ostream;

    virtual void operator()(const char* str, int size)
    {
      ostream.write(str, size);
    }

    OStreamWriter(OStream& o) :
        ostream(o)
    {
    }
  };

  template<typename Temporary>
  struct TemporaryWriter: public IStringWriter
  {
    const Temporary& userstream;

    virtual void operator()(const char* str, int size)
    {
      userstream.write(str, size);
    }

    TemporaryWriter(const Temporary& u) :
        userstream(u)
    {
    }
  };

  template<typename Syscall>
  struct SyscallWriter: public IStringWriter
  {
    Syscall* write;
    int fd;

    virtual void operator()(const char* str, int size)
    {
      (*write)(fd, str, size);
    }

    SyscallWriter(Syscall* w, int f) :
        write(w), fd(f)
    {
    }
  };

  template<typename Function, typename Stream>
  struct StreamWriter: public IStringWriter
  {
    Function* fwrite;
    Stream* stream;

    virtual void operator()(const char* str, int size)
    {
      (*fwrite)(str, size, 1, stream);
    }

    StreamWriter(Function* w, Stream* s) :
        fwrite(w), stream(s)
    {
    }
  };

  static void upmax(int& i1, int i2)
  {
    i1 = (i1 >= i2 ? i1 : i2);
  }

  static void indent(IStringWriter& write, int& x, int want_x)
  {
    int indent = want_x - x;
    if (indent < 0)
    {
      write("\n", 1);
      indent = want_x;
    }

    if (indent > 0)
    {
      char space = ' ';
      for (int i = 0; i < indent; ++i)
        write(&space, 1);
      x = want_x;
    }
  }

  static bool isWideChar(unsigned ch)
  {
    if (ch == 0x303F)
      return false;

    return ((0x1100 <= ch && ch <= 0x115F) || (0x2329 <= ch && ch <= 0x232A) || (0x2E80 <= ch && ch <= 0xA4C6)
        || (0xA960 <= ch && ch <= 0xA97C) || (0xAC00 <= ch && ch <= 0xD7FB) || (0xF900 <= ch && ch <= 0xFAFF)
        || (0xFE10 <= ch && ch <= 0xFE6B) || (0xFF01 <= ch && ch <= 0xFF60) || (0xFFE0 <= ch && ch <= 0xFFE6)
        || (0x1B000 <= ch));
  }

  class LinePartIterator
  {
    const Descriptor* tablestart; 
    const Descriptor* rowdesc; 
    const char* rowstart; 
    const char* ptr; 
    int col; 
    int len; 
    int screenlen; 
    int max_line_in_block; 
    int line_in_block; 
    int target_line_in_block; 
    bool hit_target_line; 

    void update_length()
    {
      screenlen = 0;
      for (len = 0; ptr[len] != 0 && ptr[len] != '\v' && ptr[len] != '\t' && ptr[len] != '\n'; ++len)
      {
        ++screenlen;
        unsigned ch = (unsigned char) ptr[len];
        if (ch > 0xC1) // everything <= 0xC1 (yes, even 0xC1 itself) is not a valid UTF-8 start byte
        {
          // int __builtin_clz (unsigned int x)
          // Returns the number of leading 0-bits in x, starting at the most significant bit
          unsigned mask = (unsigned) -1 >> __builtin_clz(ch ^ 0xff);
          ch = ch & mask; // mask out length bits, we don't verify their correctness
          while (((unsigned char) ptr[len + 1] ^ 0x80) <= 0x3F) // while next byte is continuation byte
          {
            ch = (ch << 6) ^ (unsigned char) ptr[len + 1] ^ 0x80; // add continuation to char code
            ++len;
          }
          // ch is the decoded unicode code point
          if (ch >= 0x1100 && isWideChar(ch)) // the test for 0x1100 is here to avoid the function call in the Latin case
            ++screenlen;
        }
      }
    }

  public:
    LinePartIterator(const Descriptor usage[]) :
        tablestart(usage), rowdesc(0), rowstart(0), ptr(0), col(-1), len(0), max_line_in_block(0), line_in_block(0),
        target_line_in_block(0), hit_target_line(true)
    {
    }

    bool nextTable()
    {
      // If this is NOT the first time nextTable() is called after the constructor,
      // then skip to the next table break (i.e. a Descriptor with help == 0)
      if (rowdesc != 0)
      {
        while (tablestart->help != 0 && tablestart->shortopt != 0)
          ++tablestart;
      }

      // Find the next table after the break (if any)
      while (tablestart->help == 0 && tablestart->shortopt != 0)
        ++tablestart;

      restartTable();
      return rowstart != 0;
    }

    void restartTable()
    {
      rowdesc = tablestart;
      rowstart = tablestart->help;
      ptr = 0;
    }

    bool nextRow()
    {
      if (ptr == 0)
      {
        restartRow();
        return rowstart != 0;
      }

      while (*ptr != 0 && *ptr != '\n')
        ++ptr;

      if (*ptr == 0)
      {
        if ((rowdesc + 1)->help == 0) // table break
          return false;

        ++rowdesc;
        rowstart = rowdesc->help;
      }
      else // if (*ptr == '\n')
      {
        rowstart = ptr + 1;
      }

      restartRow();
      return true;
    }

    void restartRow()
    {
      ptr = rowstart;
      col = -1;
      len = 0;
      screenlen = 0;
      max_line_in_block = 0;
      line_in_block = 0;
      target_line_in_block = 0;
      hit_target_line = true;
    }

    bool next()
    {
      if (ptr == 0)
        return false;

      if (col == -1)
      {
        col = 0;
        update_length();
        return true;
      }

      ptr += len;
      while (true)
      {
        switch (*ptr)
        {
          case '\v':
            upmax(max_line_in_block, ++line_in_block);
            ++ptr;
            break;
          case '\t':
            if (!hit_target_line) // if previous column did not have the targetline
            { // then "insert" a 0-length part
              update_length();
              hit_target_line = true;
              return true;
            }

            hit_target_line = false;
            line_in_block = 0;
            ++col;
            ++ptr;
            break;
          case 0:
          case '\n':
            if (!hit_target_line) // if previous column did not have the targetline
            { // then "insert" a 0-length part
              update_length();
              hit_target_line = true;
              return true;
            }

            if (++target_line_in_block > max_line_in_block)
            {
              update_length();
              return false;
            }

            hit_target_line = false;
            line_in_block = 0;
            col = 0;
            ptr = rowstart;
            continue;
          default:
            ++ptr;
            continue;
        } // switch

        if (line_in_block == target_line_in_block)
        {
          update_length();
          hit_target_line = true;
          return true;
        }
      } // while
    }

    int column()
    {
      return col;
    }

    int line()
    {
      return target_line_in_block; // NOT line_in_block !!! It would be wrong if !hit_target_line
    }

    int length()
    {
      return len;
    }

    int screenLength()
    {
      return screenlen;
    }

    const char* data()
    {
      return ptr;
    }
  };

  class LineWrapper
  {
    static const int bufmask = 15; 

    int lenbuf[bufmask + 1];
    const char* datbuf[bufmask + 1];
    int x;
    int width;
    int head; 
    int tail; 

    bool wrote_something;

    bool buf_empty()
    {
      return ((tail + 1) & bufmask) == head;
    }

    bool buf_full()
    {
      return tail == head;
    }

    void buf_store(const char* data, int len)
    {
      lenbuf[head] = len;
      datbuf[head] = data;
      head = (head + 1) & bufmask;
    }

    void buf_next()
    {
      tail = (tail + 1) & bufmask;
    }

    void output(IStringWriter& write, const char* data, int len)
    {
      if (buf_full())
        write_one_line(write);

      buf_store(data, len);
    }

    void write_one_line(IStringWriter& write)
    {
      if (wrote_something) // if we already wrote something, we need to start a new line
      {
        write("\n", 1);
        int _ = 0;
        indent(write, _, x);
      }

      if (!buf_empty())
      {
        buf_next();
        write(datbuf[tail], lenbuf[tail]);
      }

      wrote_something = true;
    }
  public:

    void flush(IStringWriter& write)
    {
      if (buf_empty())
        return;
      int _ = 0;
      indent(write, _, x);
      wrote_something = false;
      while (!buf_empty())
        write_one_line(write);
      write("\n", 1);
    }

    void process(IStringWriter& write, const char* data, int len)
    {
      wrote_something = false;

      while (len > 0)
      {
        if (len <= width) // quick test that works because utf8width <= len (all wide chars have at least 2 bytes)
        {
          output(write, data, len);
          len = 0;
        }
        else // if (len > width)  it's possible (but not guaranteed) that utf8len > width
        {
          int utf8width = 0;
          int maxi = 0;
          while (maxi < len && utf8width < width)
          {
            int charbytes = 1;
            unsigned ch = (unsigned char) data[maxi];
            if (ch > 0xC1) // everything <= 0xC1 (yes, even 0xC1 itself) is not a valid UTF-8 start byte
            {
              // int __builtin_clz (unsigned int x)
              // Returns the number of leading 0-bits in x, starting at the most significant bit
              unsigned mask = (unsigned) -1 >> __builtin_clz(ch ^ 0xff);
              ch = ch & mask; // mask out length bits, we don't verify their correctness
              while ((maxi + charbytes < len) && //
                  (((unsigned char) data[maxi + charbytes] ^ 0x80) <= 0x3F)) // while next byte is continuation byte
              {
                ch = (ch << 6) ^ (unsigned char) data[maxi + charbytes] ^ 0x80; // add continuation to char code
                ++charbytes;
              }
              // ch is the decoded unicode code point
              if (ch >= 0x1100 && isWideChar(ch)) // the test for 0x1100 is here to avoid the function call in the Latin case
              {
                if (utf8width + 2 > width)
                  break;
                ++utf8width;
              }
            }
            ++utf8width;
            maxi += charbytes;
          }

          // data[maxi-1] is the last byte of the UTF-8 sequence of the last character that fits
          // onto the 1st line. If maxi == len, all characters fit on the line.

          if (maxi == len)
          {
            output(write, data, len);
            len = 0;
          }
          else // if (maxi < len)  at least 1 character (data[maxi] that is) doesn't fit on the line
          {
            int i;
            for (i = maxi; i >= 0; --i)
              if (data[i] == ' ')
                break;

            if (i >= 0)
            {
              output(write, data, i);
              data += i + 1;
              len -= i + 1;
            }
            else // did not find a space to split at => split before data[maxi]
            { // data[maxi] is always the beginning of a character, never a continuation byte
              output(write, data, maxi);
              data += maxi;
              len -= maxi;
            }
          }
        }
      }
      if (!wrote_something) // if we didn't already write something to make space in the buffer
        write_one_line(write); // write at most one line of actual output
    }

    LineWrapper(int x1, int x2) :
        x(x1), width(x2 - x1), head(0), tail(bufmask)
    {
      if (width < 2) // because of wide characters we need at least width 2 or the code breaks
        width = 2;
    }
  };

  static void printUsage(IStringWriter& write, const Descriptor usage[], int width = 80, //
                         int last_column_min_percent = 50, int last_column_own_line_max_percent = 75)
  {
    if (width < 1) // protect against nonsense values
      width = 80;

    if (width > 10000) // protect against overflow in the following computation
      width = 10000;

    int last_column_min_width = ((width * last_column_min_percent) + 50) / 100;
    int last_column_own_line_max_width = ((width * last_column_own_line_max_percent) + 50) / 100;
    if (last_column_own_line_max_width == 0)
      last_column_own_line_max_width = 1;

    LinePartIterator part(usage);
    while (part.nextTable())
    {

      /***************** Determine column widths *******************************/

      const int maxcolumns = 8; // 8 columns are enough for everyone
      int col_width[maxcolumns];
      int lastcolumn;
      int leftwidth;
      int overlong_column_threshold = 10000;
      do
      {
        lastcolumn = 0;
        for (int i = 0; i < maxcolumns; ++i)
          col_width[i] = 0;

        part.restartTable();
        while (part.nextRow())
        {
          while (part.next())
          {
            if (part.column() < maxcolumns)
            {
              upmax(lastcolumn, part.column());
              if (part.screenLength() < overlong_column_threshold)
                // We don't let rows that don't use table separators (\t or \v) influence
                // the width of column 0. This allows the user to interject section headers
                // or explanatory paragraphs that do not participate in the table layout.
                if (part.column() > 0 || part.line() > 0 || part.data()[part.length()] == '\t'
                    || part.data()[part.length()] == '\v')
                  upmax(col_width[part.column()], part.screenLength());
            }
          }
        }

        /*
         * If the last column doesn't fit on the same
         * line as the other columns, we can fix that by starting it on its own line.
         * However we can't do this for any of the columns 0..lastcolumn-1.
         * If their sum exceeds the maximum width we try to fix this by iteratively
         * ignoring the widest line parts in the width determination until
         * we arrive at a series of column widths that fit into one line.
         * The result is a layout where everything is nicely formatted
         * except for a few overlong fragments.
         * */

        leftwidth = 0;
        overlong_column_threshold = 0;
        for (int i = 0; i < lastcolumn; ++i)
        {
          leftwidth += col_width[i];
          upmax(overlong_column_threshold, col_width[i]);
        }

      } while (leftwidth > width);

      /**************** Determine tab stops and last column handling **********************/

      int tabstop[maxcolumns];
      tabstop[0] = 0;
      for (int i = 1; i < maxcolumns; ++i)
        tabstop[i] = tabstop[i - 1] + col_width[i - 1];

      int rightwidth = width - tabstop[lastcolumn];
      bool print_last_column_on_own_line = false;
      if (rightwidth < last_column_min_width &&  // if we don't have the minimum requested width for the last column
            ( col_width[lastcolumn] == 0 ||      // and all last columns are > overlong_column_threshold
              rightwidth < col_width[lastcolumn] // or there is at least one last column that requires more than the space available
            )
          )
      {
        print_last_column_on_own_line = true;
        rightwidth = last_column_own_line_max_width;
      }

      // If lastcolumn == 0 we must disable print_last_column_on_own_line because
      // otherwise 2 copies of the last (and only) column would be output.
      // Actually this is just defensive programming. It is currently not
      // possible that lastcolumn==0 and print_last_column_on_own_line==true
      // at the same time, because lastcolumn==0 => tabstop[lastcolumn] == 0 =>
      // rightwidth==width => rightwidth>=last_column_min_width  (unless someone passes
      // a bullshit value >100 for last_column_min_percent) => the above if condition
      // is false => print_last_column_on_own_line==false
      if (lastcolumn == 0)
        print_last_column_on_own_line = false;

      LineWrapper lastColumnLineWrapper(width - rightwidth, width);
      LineWrapper interjectionLineWrapper(0, width);

      part.restartTable();

      /***************** Print out all rows of the table *************************************/

      while (part.nextRow())
      {
        int x = -1;
        while (part.next())
        {
          if (part.column() > lastcolumn)
            continue; // drop excess columns (can happen if lastcolumn == maxcolumns-1)

          if (part.column() == 0)
          {
            if (x >= 0)
              write("\n", 1);
            x = 0;
          }

          indent(write, x, tabstop[part.column()]);

          if ((part.column() < lastcolumn)
              && (part.column() > 0 || part.line() > 0 || part.data()[part.length()] == '\t'
                  || part.data()[part.length()] == '\v'))
          {
            write(part.data(), part.length());
            x += part.screenLength();
          }
          else // either part.column() == lastcolumn or we are in the special case of
               // an interjection that doesn't contain \v or \t
          {
            // NOTE: This code block is not necessarily executed for
            // each line, because some rows may have fewer columns.

            LineWrapper& lineWrapper = (part.column() == 0) ? interjectionLineWrapper : lastColumnLineWrapper;

            if (!print_last_column_on_own_line || part.column() != lastcolumn)
              lineWrapper.process(write, part.data(), part.length());
          }
        } // while

        if (print_last_column_on_own_line)
        {
          part.restartRow();
          while (part.next())
          {
            if (part.column() == lastcolumn)
            {
              write("\n", 1);
              int _ = 0;
              indent(write, _, width - rightwidth);
              lastColumnLineWrapper.process(write, part.data(), part.length());
            }
          }
        }

        write("\n", 1);
        lastColumnLineWrapper.flush(write);
        interjectionLineWrapper.flush(write);
      }
    }
  }

}
;

template<typename OStream>
void printUsage(OStream& prn, const Descriptor usage[], int width = 80, int last_column_min_percent = 50,
                int last_column_own_line_max_percent = 75)
{
  PrintUsageImplementation::OStreamWriter<OStream> write(prn);
  PrintUsageImplementation::printUsage(write, usage, width, last_column_min_percent, last_column_own_line_max_percent);
}

template<typename Function>
void printUsage(Function* prn, const Descriptor usage[], int width = 80, int last_column_min_percent = 50,
                int last_column_own_line_max_percent = 75)
{
  PrintUsageImplementation::FunctionWriter<Function> write(prn);
  PrintUsageImplementation::printUsage(write, usage, width, last_column_min_percent, last_column_own_line_max_percent);
}

template<typename Temporary>
void printUsage(const Temporary& prn, const Descriptor usage[], int width = 80, int last_column_min_percent = 50,
                int last_column_own_line_max_percent = 75)
{
  PrintUsageImplementation::TemporaryWriter<Temporary> write(prn);
  PrintUsageImplementation::printUsage(write, usage, width, last_column_min_percent, last_column_own_line_max_percent);
}

template<typename Syscall>
void printUsage(Syscall* prn, int fd, const Descriptor usage[], int width = 80, int last_column_min_percent = 50,
                int last_column_own_line_max_percent = 75)
{
  PrintUsageImplementation::SyscallWriter<Syscall> write(prn, fd);
  PrintUsageImplementation::printUsage(write, usage, width, last_column_min_percent, last_column_own_line_max_percent);
}

template<typename Function, typename Stream>
void printUsage(Function* prn, Stream* stream, const Descriptor usage[], int width = 80, int last_column_min_percent =
                    50,
                int last_column_own_line_max_percent = 75)
{
  PrintUsageImplementation::StreamWriter<Function, Stream> write(prn, stream);
  PrintUsageImplementation::printUsage(write, usage, width, last_column_min_percent, last_column_own_line_max_percent);
}

}
// namespace option

#endif /* OPTIONPARSER_H_ */
