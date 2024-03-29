﻿/**********************************************

License: BSD
Project Webpage: http://cajun-jsonapi.sourceforge.net/
Author: Terry Caton

***********************************************/

#pragma once

#include <deque>
#include <list>
#include <string>
#include <stdexcept>

/*  

TODO:
* better documentation (doxygen?)
* Unicode support
* parent element accessors

*/

namespace json
{

enum ElementType
{
    TYPE_OBJECT,
    TYPE_ARRAY,
    TYPE_NUMBER,
    TYPE_BOOLEAN,
    TYPE_STRING,
    TYPE_NULL,
};

/////////////////////////////////////////////////
// forward declarations (more info further below)


class Visitor;
class ConstVisitor;

template <typename ValueTypeT>
class TrivialType_T;

typedef TrivialType_T<double> Number;
typedef TrivialType_T<bool> Boolean;
typedef TrivialType_T<std::string> String;

class Object;
class Array;
class Null;



/////////////////////////////////////////////////////////////////////////
// Exception - base class for all JSON-related runtime errors

class Exception : public std::runtime_error
{
public:
   Exception(const std::string& sMessage);
};

/////////////////////////////////////////////////////////////////////////
// BaseElement

template <typename ElementTypeT>
class BaseElement
{
public:
    virtual void Load(std::istream& istr);
    virtual void Dump(std::ostream& ostr, bool compact = true) const;
    virtual void Parse(const std::string& str);
    virtual std::string Pack(bool compact = true) const;
};

/////////////////////////////////////////////////////////////////////////
// UnknownElement - provides a typesafe surrogate for any of the JSON-
//  sanctioned element types. This class allows the Array and Object
//  class to effectively contain a heterogeneous set of child elements.
// The cast operators provide convenient implicit downcasting, while
//  preserving dynamic type safety by throwing an exception during a
//  a bad cast. 
// The object & array element index operators (operators [std::string]
//  and [size_t]) provide convenient, quick access to child elements.
//  They are a logical extension of the cast operators. These child
//  element accesses can be chained together, allowing the following
//  (when document structure is well-known):
//  String str = objInvoices[1]["Customer"]["Company"];


class UnknownElement : public BaseElement<UnknownElement>
{
public:
   UnknownElement();
   UnknownElement(const UnknownElement& unknown);
   UnknownElement(const Object& object);
   UnknownElement(const Array& array);
   UnknownElement(const Number& number);
   UnknownElement(const Boolean& boolean);
   UnknownElement(const String& string);
   UnknownElement(const Null& null);

   ~UnknownElement();

   UnknownElement& operator = (const UnknownElement& unknown);

   // implicit cast to actual element type. throws on failure
   operator const Object& () const;
   operator const Array& () const;
   operator const Number& () const;
   operator const Boolean& () const;
   operator const String& () const;
   operator const Null& () const;

   // implicit cast to actual element type. *converts* on failure, and always returns success
   operator Object& ();
   operator Array& ();
   operator Number& ();
   operator Boolean& ();
   operator String& ();
   operator Null& ();

   // provides quick access to children when real element type is object
   UnknownElement& operator[] (const std::string& key);
   const UnknownElement& operator[] (const std::string& key) const;

   // provides quick access to children when real element type is array
   UnknownElement& operator[] (size_t index);
   const UnknownElement& operator[] (size_t index) const;

   // implements visitor pattern
   void Accept(ConstVisitor& visitor) const;
   void Accept(Visitor& visitor);

   // tests equality. first checks type, then value if possible
   bool operator == (const UnknownElement& element) const;

   ElementType Type() const;

   virtual void Dump(std::ostream& oss, bool compact = true) const;

   const std::string & ToString() const;
   const double & ToNumber() const;
   const bool & ToBoolean() const;

   UnknownElement& operator = (const std::string & value);
   UnknownElement& operator = (const char * value);
   UnknownElement& operator = (const long & value);
   UnknownElement& operator = (const long long & value);
   UnknownElement& operator = (const unsigned long & value);
   UnknownElement& operator = (const unsigned long long & value);
   UnknownElement& operator = (const float & value);
   UnknownElement& operator = (const double & value);
   UnknownElement& operator = (const bool & value);

private:
   class Imp;

   template <typename ElementTypeT>
   class Imp_T;

   class CastVisitor;
   class ConstCastVisitor;
   
   template <typename ElementTypeT>
   class CastVisitor_T;

   template <typename ElementTypeT>
   class ConstCastVisitor_T;

   template <typename ElementTypeT>
   const ElementTypeT& CastTo() const;

   template <typename ElementTypeT>
   ElementTypeT& ConvertTo();

   Imp* m_pImp;
};


/////////////////////////////////////////////////////////////////////////////////
// Array - mimics std::deque<UnknownElement>. The array contents are effectively 
//  heterogeneous thanks to the ElementUnknown class. push_back has been replaced 
//  by more generic insert functions.

class Array : public BaseElement<Array>
{
public:
   typedef std::deque<UnknownElement> Elements;
   typedef Elements::iterator iterator;
   typedef Elements::const_iterator const_iterator;

   Array(const std::string& str = std::string());

   iterator Begin();
   iterator End();
   const_iterator Begin() const;
   const_iterator End() const;
   
   iterator Insert(const UnknownElement& element, iterator itWhere);
   iterator Insert(const UnknownElement& element);
   iterator Erase(iterator itWhere);
   void Resize(size_t newSize);
   void Clear();

   size_t Size() const;
   bool Empty() const;

   UnknownElement& operator[] (size_t index);
   const UnknownElement& operator[] (size_t index) const;

   bool operator == (const Array& array) const;

   ElementType Type() const;

private:
   Elements m_Elements;
};


/////////////////////////////////////////////////////////////////////////////////
// Object - mimics std::map<std::string, UnknownElement>. The member value 
//  contents are effectively heterogeneous thanks to the UnknownElement class

class Object : public BaseElement<Object>
{
public:
   struct Member {
      Member(const std::string& nameIn = std::string(), const UnknownElement& elementIn = UnknownElement());

      bool operator == (const Member& member) const;

      std::string name;
      UnknownElement element;
   };

   typedef std::list<Member> Members; // map faster, but does not preserve order
   typedef Members::iterator iterator;
   typedef Members::const_iterator const_iterator;

   Object(const std::string& str = std::string());

   bool operator == (const Object& object) const;

   iterator Begin();
   iterator End();
   const_iterator Begin() const;
   const_iterator End() const;

   size_t Size() const;
   bool Empty() const;

   iterator Find(const std::string& name);
   const_iterator Find(const std::string& name) const;

   iterator Insert(const Member& member);
   iterator Insert(const Member& member, iterator itWhere);
   iterator Erase(iterator itWhere);
   void Clear();

   UnknownElement& operator [](const std::string& name);
   const UnknownElement& operator [](const std::string& name) const;

   ElementType Type() const;

private:
   class Finder;

   Members m_Members;
};


/////////////////////////////////////////////////////////////////////////////////
// TrivialType_T - class template for encapsulates a simple data type, such as
//  a string, number, or boolean. Provides implicit const & noncost cast operators
//  for that type, allowing "DataTypeT type = trivialType;"


template <typename DataTypeT>
class TrivialType_T : public BaseElement<TrivialType_T<DataTypeT> >
{
public:
   TrivialType_T(const DataTypeT& t = DataTypeT());

   operator DataTypeT&();
   operator const DataTypeT&() const;

   DataTypeT& Value();
   const DataTypeT& Value() const;

   bool operator == (const TrivialType_T<DataTypeT>& trivial) const;

   ElementType Type() const;

private:
   DataTypeT m_tValue;
};


/////////////////////////////////////////////////////////////////////////////////
// Null - doesn't do much of anything but satisfy the JSON spec. It is the default
//  element type of UnknownElement

class Null : public BaseElement<Null>
{
public:
   bool operator == (const Null& trivial) const;

   ElementType Type() const;
};


} // End namespace


#include "elements.inl"
