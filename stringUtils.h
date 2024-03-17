#ifndef STRINGUTILS_H
#define STRINGUTILS_H

#include <vector>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <iostream>

/*
remove blank spaces before/after the string
*/
std::string strip(std::string str) {
    int start = str.find_first_not_of(" \t\r\f\v");
    if (start == std::string::npos) {
        return "";
    }
    int end = str.find_last_not_of(" \t\r\f\v");
    return str.substr(start, end - start + 1);
}

/*
remove prefix from string
*/
std::string remove_prefix(const std::string &fullString, const std::string &prefix) {
    if (fullString.length() < prefix.length()) {
        throw (0);
    }
    return fullString.substr(prefix.length());
}

/*
split a string
*/
std::vector<std::string> split(const std::string &s, char delim) 
{
    std::vector<std::string> elems;
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) 
    {
        if(!item.empty())
        {
            elems.push_back(item);
        }
    }
    return elems;
}

#endif // STRINGUTILS_H
