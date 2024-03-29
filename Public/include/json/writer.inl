/**********************************************

License: BSD
Project Webpage: http://cajun-jsonapi.sourceforge.net/
Author: Terry Caton

***********************************************/

#include "writer.h"
#include <iostream>
#include <iomanip>

/*  

TODO:
* better documentation
* unicode character encoding

*/

namespace json
{


inline void Writer::Write(const UnknownElement& elementRoot, std::ostream& ostr, bool compact) { Write_i(elementRoot, ostr, compact); }
inline void Writer::Write(const Object& object, std::ostream& ostr, bool compact)              { Write_i(object, ostr, compact); }
inline void Writer::Write(const Array& array, std::ostream& ostr, bool compact)                { Write_i(array, ostr, compact); }
inline void Writer::Write(const String& string, std::ostream& ostr, bool ignore)               { Write_i(string, ostr, ignore); }
inline void Writer::Write(const Number& number, std::ostream& ostr, bool ignore)               { Write_i(number, ostr, ignore); }
inline void Writer::Write(const Boolean& boolean, std::ostream& ostr, bool ignore)             { Write_i(boolean, ostr, ignore); }
inline void Writer::Write(const Null& null, std::ostream& ostr, bool ignore)                   { Write_i(null, ostr, ignore); }
inline void Writer::WriteString(const String& string, std::ostream& ostr)                      { Write_s(string, ostr); }


inline Writer::Writer(std::ostream& ostr, bool compact) :
   m_ostr(ostr),
   m_nTabDepth(0),
   m_bCompact(compact)
{}

inline void Writer::Write_s(const String& string, std::ostream& ostr)
{
    Writer writer(ostr, true);
    writer.Write_s(string);
    ostr.flush(); // all done
}

template <typename ElementTypeT>
inline void Writer::Write_i(const ElementTypeT& element, std::ostream& ostr, bool compact)
{
   Writer writer(ostr, compact);
   writer.Write_i(element);
   ostr.flush(); // all done
}

inline void Writer::Write_i(const Array& array)
{
   if (array.Empty())
      m_ostr << "[]";
   else
   {
      m_ostr << '[';
      if (!m_bCompact) {
          m_ostr << std::endl;
          ++m_nTabDepth;
      }

      Array::const_iterator it(array.Begin()),
                            itEnd(array.End());
      while (it != itEnd) {
         m_ostr << std::string(m_nTabDepth, '\t');
         
         Write_i(*it);

         if (++it != itEnd)
             m_ostr << ',';
         if (!m_bCompact) {
             m_ostr << std::endl;
         }
      }

      if (!m_bCompact) {
          --m_nTabDepth;
      }
      m_ostr << std::string(m_nTabDepth, '\t') << ']';
   }
}

inline void Writer::Write_i(const Object& object)
{
   if (object.Empty())
      m_ostr << "{}";
   else
   {
       m_ostr << '{';
       if (!m_bCompact) {
           m_ostr << std::endl;
           ++m_nTabDepth;
       }

      Object::const_iterator it(object.Begin()),
                             itEnd(object.End());
      while (it != itEnd) {
         m_ostr << std::string(m_nTabDepth, '\t') << '"' << it->name << "\":";
         Write_i(it->element); 

         if (++it != itEnd)
             m_ostr << ',';
         if (!m_bCompact) {
             m_ostr << std::endl;
         }
      }

      if (!m_bCompact) {
          --m_nTabDepth;
      }
      m_ostr << std::string(m_nTabDepth, '\t') << '}';
   }
}

inline void Writer::Write_i(const Number& numberElement)
{
   m_ostr << std::dec << std::setprecision(20) << numberElement.Value();
}

inline void Writer::Write_i(const Boolean& booleanElement)
{
   m_ostr << (booleanElement.Value() ? "true" : "false");
}

inline void Writer::Write_s(const String& stringElement)
{
   const std::string& s = stringElement.Value();
   std::string::const_iterator it(s.begin()),
                               itEnd(s.end());
   for (; it != itEnd; ++it)
   {
/*
      // check for UTF-8 unicode encoding
      unsigned char u = static_cast<unsigned char>(*it);
      if (u & 0xc0) {
         if ((u & 0xe0) == 0xc0) {
            // two-character sequence
            int x = (*it & 0x1f) << 6;
            if ((it + 1) == itEnd) {
               m_ostr << *it; continue;
            }
            u = static_cast<unsigned char>(*(it + 1));
            if ((u & 0xc0) == 0x80) {
               x |= u & 0x3f;
               m_ostr << "\\u" << std::hex << std::setfill('0')
                  << std::setw(4) << x;
               ++it;
               continue;
            }

         } else if ((u & 0xf0) == 0xe0) {
            // three-character sequence
            int x = (u & 0x0f) << 12;
            if ((it + 1) == itEnd) {
               m_ostr << *it; continue;
            }
            u = static_cast<unsigned char>(*(it + 1));
            if ((u & 0xc0) == 0x80) {
               x |= (u & 0x3f) << 6;
               if ((it + 2) == itEnd) {
                  m_ostr << *it; continue;
               }
               u = static_cast<unsigned char>(*(it + 2));
               if ((u & 0xc0) == 0x80) {
                  x |= u & 0x3f;
                  m_ostr << "\\u" << std::hex << std::setfill('0')
                     << std::setw(4) << x;
                  it = it + 2;
                  continue;
               }
            }
         }
      }
*/

      switch (*it)
      {
         case '"':         m_ostr << "\\\"";   break;
         case '\\':        m_ostr << "\\\\";   break;
         case '\b':        m_ostr << "\\b";    break;
         case '\f':        m_ostr << "\\f";    break;
         case '\n':        m_ostr << "\\n";    break;
         case '\r':        m_ostr << "\\r";    break;
         case '\t':        m_ostr << "\\t";    break;
         default:          m_ostr << *it;      break;
      }
   }
}

inline void Writer::Write_i(const String& stringElement)
{
   m_ostr << '"';
   Write_s(stringElement);
   m_ostr << '"';
}

inline void Writer::Write_i(const Null& )
{
   m_ostr << "null";
}

inline void Writer::Write_i(const UnknownElement& unknown)
{
   unknown.Accept(*this); 
}

inline void Writer::Visit(const Array& array)       { Write_i(array); }
inline void Writer::Visit(const Object& object)     { Write_i(object); }
inline void Writer::Visit(const Number& number)     { Write_i(number); }
inline void Writer::Visit(const String& string)     { Write_i(string); }
inline void Writer::Visit(const Boolean& boolean)   { Write_i(boolean); }
inline void Writer::Visit(const Null& null)         { Write_i(null); }



} // End namespace
