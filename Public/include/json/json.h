/*!
 * date:    11/18/2016
 * Contact: uckzou@tencent.com
 */
#pragma once
#include <map>
#include "elements.h"
#include "reader.h"
#include "writer.h"

class CJson : public json::Object
{
public:
    CJson(const std::string& str = std::string()) : json::Object(str) {}

    std::string Marshal(char separator) const
    {
        return Marshal(separator, *(json::Object*)this);
    }

protected:
    std::string Marshal(char separator, json::Object& object) const
    {
        std::map<std::string, std::string> mpmar;
        for (json::Object::iterator it = object.Begin(); it != object.End(); ++it)
        {
            mpmar[it->name] = Marshal(separator, it->element);
        }

        std::string smar;
        for (std::map<std::string, std::string>::iterator it = mpmar.begin(); it != mpmar.end(); ++it)
        {
            if (!smar.empty())
            {
                smar += separator;
            }
            smar += it->first + '=' + it->second;
        }
        return smar;
    }
    std::string Marshal(char separator, json::Array& array) const
    {
        std::string smar;
        for (json::Array::iterator it = array.Begin(); it != array.End(); ++it)
        {
            if (!smar.empty())
            {
                smar += ',';
            }
            smar += Marshal(separator, *it);
        }
        return smar;
    }
    std::string Marshal(char separator, json::UnknownElement& element) const
    {
        std::string smar;
        switch (element.Type())
        {
        case json::TYPE_OBJECT:
            smar = Marshal(separator, (json::Object &)element);
            break;
        case json::TYPE_ARRAY:
            smar = Marshal(separator, (json::Array &)element);
            break;
        case json::TYPE_STRING:
        case json::TYPE_NUMBER:
        case json::TYPE_BOOLEAN:
        case json::TYPE_NULL:
        default:
            smar = element.Pack(true);
            break;
        }
        return smar;
    }

};
