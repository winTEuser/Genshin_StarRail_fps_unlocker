// Read an INI file into easy-to-access name/value pairs.

// inih and INIReader are released under the New BSD license (see LICENSE.txt).
// Go to the project home page for more info:
//
// https://github.com/benhoyt/inih
/* inih -- simple .INI file parser

inih is released under the New BSD license (see LICENSE.txt). Go to the project
home page for more info:

https://github.com/benhoyt/inih

*/
#pragma warning( disable : 4996 )

#ifndef __INI_H__
#define __INI_H__

/* Make this header file easier to include in C++ code */
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

    /* Typedef for prototype of handler function. */
    typedef int (*ini_handler)(void* user, const wchar_t* section, const wchar_t* name, const wchar_t* value);

    /* Typedef for prototype of fgets-style reader function. */
    typedef wchar_t* (*ini_reader)(wchar_t* str, int num, void* stream);

    /* Parse given INI-style file. May have [section]s, name=value pairs
       (whitespace stripped), and comments starting with ';' (semicolon). Section
       is "" if name=value pair parsed before any section heading. name:value
       pairs are also supported as a concession to Python's configparser.

       For each name=value pair parsed, call handler function with given user
       pointer as well as section, name, and value (data only valid for duration
       of handler call). Handler should return nonzero on success, zero on error.

       Returns 0 on success, line number of first error on parse error (doesn't
       stop on first error), -1 on file open error, or -2 on memory allocation
       error (only when INI_USE_STACK is zero).
    */
    int ini_parse(const wchar_t* filename, ini_handler handler, void* user);

    /* Same as ini_parse(), but takes a FILE* instead of filename. This doesn't
       close the file when it's finished -- the caller must do that. */
    int ini_parse_file(FILE* file, ini_handler handler, void* user);

    /* Same as ini_parse(), but takes an ini_reader function pointer instead of
       filename. Used for implementing custom or string-based I/O. */
    int ini_parse_stream(ini_reader reader, void* stream, ini_handler handler,
        void* user);

    /* Nonzero to allow multi-line value parsing, in the style of Python's
       configparser. If allowed, ini_parse() will call the handler with the same
       name for each subsequent line parsed. */
#ifndef INI_ALLOW_MULTILINE
#define INI_ALLOW_MULTILINE 1
#endif

       /* Nonzero to allow a UTF-16LE BOM sequence (0xFEFF) at the start of
          the file. See http://code.google.com/p/inih/issues/detail?id=21 */
#ifndef INI_ALLOW_BOM
#define INI_ALLOW_BOM 1
#endif

          /* Nonzero to allow inline comments (with valid inline comment characters
             specified by INI_INLINE_COMMENT_PREFIXES). Set to 0 to turn off and match
             Python 3.2+ configparser behaviour. */
#ifndef INI_ALLOW_INLINE_COMMENTS
#define INI_ALLOW_INLINE_COMMENTS 0
#endif
#ifndef INI_INLINE_COMMENT_PREFIXES
#define INI_INLINE_COMMENT_PREFIXES L";"
#endif


/* Stop parsing on first error (default is to keep parsing). */
#ifndef INI_STOP_ON_FIRST_ERROR
#define INI_STOP_ON_FIRST_ERROR 1
#endif

/* Maximum line length for any line in INI file. */
#ifndef INI_MAX_LINE
#define INI_MAX_LINE 0x2000
#endif

#ifdef __cplusplus
}
#endif

/* inih -- simple .INI file parser

inih is released under the New BSD license (see LICENSE.txt). Go to the project
home page for more info:

https://github.com/benhoyt/inih

*/

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>


#define MAX_SECTION 0x1000
#define MAX_NAME 0x1000

static bool isspace0(wchar_t wcstr)
{
    switch (wcstr)
    {
    case 0x20: // space
        return true;
    case 0x09: // "\t"
        return true;
    case 0x0A: // "\n"
        return true;
    case 0x0B: // "\v"
        return true;
    case 0x0C: // "\f"
        return true;
    case 0x0D: // "\r"
        return true;
    default:
        return false;
    }
}

/* Strip whitespace chars off end of given string, in place. Return s. */
static wchar_t* rstrip(wchar_t* s)
{
    wchar_t* p = s + wcslen(s);
    while (p > s && isspace0((wchar_t)(*--p)))
        *p = 0;
    return s;
}

/* Return pointer to first non-whitespace char in given string. */
static wchar_t* lskip(const wchar_t* s)
{
    while (*s && isspace0((wchar_t)(*s)))
        s++;
    return (wchar_t*)s;
}

//convert to lower
static void towlower0(wchar_t* wchar)
{
    wchar_t tem = *wchar;
    while (tem != 0)
    {
        if (tem >= 'A' && tem <= 'Z')
        {
            *wchar += 0x20;
        }
        wchar++;
        tem = *wchar;
    }
}

/* Return pointer to first char (of chars) or inline comment in given string,
   or pointer to null at end of string if neither found. Inline comment must
   be prefixed by a whitespace character to register as a comment. */
inline static wchar_t* find_chars_or_comment(const wchar_t* s, const wchar_t* chars)
{
#if INI_ALLOW_INLINE_COMMENTS
    int was_space = 0;
    while (*s && (!chars || !wcschr(chars, *s)) && !(was_space && wcschr(INI_INLINE_COMMENT_PREFIXES, *s))) 
    {
        was_space = isspace((wchar_t)(*s));
        s++;
    }
#else
    while (*s && (!chars || !wcschr(chars, *s)))
        s++;
#endif
    return (wchar_t*)s;
}

/* Version of strncpy that ensures dest (size bytes) is null-terminated. */
static void strncpy0(wchar_t* dest, const wchar_t* src, size_t size)
{
    if (size % 2) return;
    size /= 2;
    size_t copy_size = 0;
    while ((copy_size < size) && (*(src + copy_size) != 0))
    {
        *(dest + copy_size) = *(src + copy_size);
        copy_size++;
    }

    *(wchar_t*)(dest + copy_size) = 0;
    return;
}

//if equl return true else return false
inline static bool wcstrcmp0(const wchar_t* fir, const wchar_t* sec)
{
    int i = 0;
    while ((*(fir + i)) == (*(sec + i)))
    {
        if (*(fir + i) == 0)
            return 1;
        i++;
    }
    return 0;
}

static wchar_t* Read_line(wchar_t* deststr, size_t num, wchar_t** stream_rawstr)
{
    wchar_t* rawstr = 0;
    wchar_t* nextlineptr = *stream_rawstr;
    if (nextlineptr)
        rawstr = nextlineptr;
    else
        rawstr = *(wchar_t**)((char*)stream_rawstr + sizeof(uintptr_t));
    if (!rawstr) return 0;
    if (!*(rawstr)) return 0;
    size_t i = 0;
    while ((*(rawstr + i) != 0x0A) && (*(rawstr + i) != 0))
    {
        *(deststr + i) = *(rawstr + i);
        i++;
    }
    *(uintptr_t*)(deststr + i) = 0;
    *stream_rawstr = (rawstr + i + 1);
    return deststr;
}

/* See documentation in header file. */
 int ini_parse_stream(ini_reader reader, void* stream, ini_handler handler, void* user)
{
    wchar_t* start;
    wchar_t* end;
    wchar_t* name;
    wchar_t* value;

    wchar_t** inputstr = (wchar_t**)stream;
    int lineno = 0;
    int error = 0;

    wchar_t* section = (wchar_t*)malloc(MAX_SECTION);
    wchar_t* prev_name = (wchar_t*)malloc(MAX_NAME);
    wchar_t* line = (wchar_t*)malloc(INI_MAX_LINE);
    if (!section || !prev_name || !line) 
        return -1;

    *(uint64_t*)section = 0;
    *(uint64_t*)prev_name = 0;
    *(uint64_t*)line = 0;

    if (reader(line, INI_MAX_LINE, inputstr) == NULL)
    {
        error = -1;
        goto __exit_block;
    }
    *(uintptr_t*)inputstr = 0;

    if (Read_line(line, INI_MAX_LINE, inputstr) != NULL)
    { 

        lineno++;
        start = line;

#if INI_ALLOW_BOM
        if (start[0] == 0xFEFF)
        {
            start++;
        }
#endif
        /* Scan through stream line by line */
        while (1)
        {
            start = lskip(rstrip(start));
            if (*start == L';' || *start == L'#') 
            {
                /* Per Python configparser, allow both ; and # comments at the
                   start of a line */
            }
#if INI_ALLOW_MULTILINE
            else if (*prev_name && *start && start > line) 
            {

#if INI_ALLOW_INLINE_COMMENTS
                end = find_chars_or_comment(start, NULL);
                if (*end)
                    *end = 0;
                rstrip(start);
#endif

                /* Non-blank line with leading whitespace, treat as continuation
                   of previous name's value (as per Python configparser). */
                if (!handler(user, section, prev_name, start) && !error)
                    error = lineno;
            }
#endif
            else if (*start == L'[') 
            {
                /* A "[section]" line */
                end = find_chars_or_comment(start + 1, L"]");
                if (*end == L']') {
                    *end = 0;
                    strncpy0(section, start + 1, MAX_SECTION);
                    *(uint64_t*)prev_name = 0;
                }
                else if (!error) {
                    /* No ']' found on section line */
                    error = lineno;
                }
            }
            else if (*start) 
            {
                /* Not a comment, must be a name[=:]value pair */
                end = find_chars_or_comment(start, L"=:");
                if (*end == L'=' || *end == L':') 
                {
                    *end = 0;
                    name = rstrip(start);
                    value = lskip(end + 1);
#if INI_ALLOW_INLINE_COMMENTS
                    end = find_chars_or_comment(value, NULL);
                    if (*end)
                        *end = 0;
#endif
                    rstrip(value);
                    /* Valid name[=:]value pair found, call handler */
                    strncpy0(prev_name, name, MAX_NAME);
                    if (!handler(user, section, name, value) && !error)
                        error = lineno;
                }
                else if (!error) {
                    /* No '=' or ':' found on name[=:]value line */
                    error = lineno;
                }
            }
#if INI_STOP_ON_FIRST_ERROR
            if (error)
                break;
#endif
            if (Read_line(line, INI_MAX_LINE, inputstr) == NULL)
            {
                break;
            }
            lineno++;
            start = line;
        }
    }
    else
    {
        error++;
    }
__exit_block:
    free(section);
    free(prev_name);
    free(line);
    return error;
}

/* See documentation in header file. */
inline int ini_parse_file(FILE* file, ini_handler handler, void* user)
{
    return ini_parse_stream((ini_reader)fgets, file, handler, user);
}

/* See documentation in header file. */
inline int ini_parse(const wchar_t* filename, ini_handler handler, void* user)
{
    FILE* file = nullptr;
    int error;

    file = _wfopen(filename, L"r");
    if (!file)
        return -1;
    error = ini_parse_file(file, handler, user);
    fclose(file);
    return error;
}

#endif /* __INI_H__ */


#ifndef __INIREADER_H__
#define __INIREADER_H__

#include <map>
#include <set>
#include <string>

// Read an INI file into easy-to-access name/value pairs. (Note that I've gone
// for simplicity here rather than speed, but it should be pretty decent.)
class INIReader
{
public:
    // Empty Constructor
    INIReader() {};

    // Construct INIReader and parse given filename. See ini.h for more info
    // about the parsing.
    INIReader(std::wstring filename);

    // Construct INIReader and parse given file. See ini.h for more info
    // about the parsing.
    INIReader(FILE* file);

    // Return the result of ini_parse(), i.e., 0 on success, line number of
    // first error on parse error, or -1 on file open error.
    int ParseError() const;

    // Return the list of sections found in ini file
    const std::set<std::wstring>& Sections() const;

    // Get a string value from INI file, returning default_value if not found.
    std::wstring Get(std::wstring section, std::wstring name, std::wstring default_value) const;

    // Get an integer (long) value from INI file, returning default_value if
    // not found or not a valid integer (decimal "1234", "-1234", or hex "0x4d2").
    long GetInteger(std::wstring section, std::wstring name, long default_value) const;

    // Get a real (floating point double) value from INI file, returning
    // default_value if not found or not a valid floating point value
    // according to strtod().
    double GetReal(std::wstring section, std::wstring name, double default_value) const;

    // Get a single precision floating point number value from INI file, returning
    // default_value if not found or not a valid floating point value
    // according to strtof().
    float GetFloat(std::wstring section, std::wstring name, float default_value) const;

    // Get a boolean value from INI file, returning default_value if not found or if
    // not a valid true/false value. Valid true values are "true", "yes", "on", "1",
    // and valid false values are "false", "no", "off", "0" (not case sensitive).
    bool GetBoolean(std::wstring section, std::wstring name, bool default_value) const;

protected:
    int _error;
    std::map<std::wstring, std::wstring> _values;
    std::set<std::wstring> _sections;
    static std::wstring MakeKey(std::wstring section, std::wstring name);
    static int ValueHandler(void* user, const wchar_t* section, const wchar_t* name, const wchar_t* value);
};

#endif  // __INIREADER_H__


#ifndef __INIREADER__
#define __INIREADER__

#include <algorithm>
#include <cctype>
#include <cstdlib>

inline INIReader::INIReader(std::wstring filename)
{
    _error = ini_parse(filename.c_str(), ValueHandler, this);
}

inline INIReader::INIReader(FILE* file)
{
    _error = ini_parse_file(file, ValueHandler, this);
}

inline int INIReader::ParseError() const
{
    return _error;
}

inline const std::set<std::wstring>& INIReader::Sections() const
{
    return _sections;
}

inline std::wstring INIReader::Get(std::wstring section, std::wstring name, std::wstring default_value) const
{
    std::wstring key = MakeKey(section, name);
    return _values.count(key) ? _values.at(key) : default_value;
}

long INIReader::GetInteger(std::wstring section, std::wstring name, long default_value) const
{
    std::wstring valstr = Get(section, name, L"");
    const wchar_t* value = valstr.c_str();
    wchar_t* end;
    // This parses "1234" (decimal) and also "0x4D2" (hex)
    long n = wcstol(value, &end, 0);
    return end > value ? n : default_value;
}

double INIReader::GetReal(std::wstring section, std::wstring name, double default_value) const
{
    std::wstring valstr = Get(section, name, L"");
    const wchar_t* value = valstr.c_str();
    wchar_t* end;
    double n = wcstod(value, &end);
    return end > value ? n : default_value;
}

float INIReader::GetFloat(std::wstring section, std::wstring name, float default_value) const
{
    std::wstring valstr = Get(section, name, L"");
    const wchar_t* value = valstr.c_str();
    wchar_t* end;
    float n = wcstof(value, &end);
    return end > value ? n : default_value;
}

bool INIReader::GetBoolean(std::wstring section, std::wstring name, bool default_value) const
{
    std::wstring valstr = Get(section, name, L"");
    // Convert to lower case to make string comparisons case-insensitive
    towlower0((wchar_t*)valstr.c_str());
    if (valstr == L"true" || valstr == L"yes" || valstr == L"on" || valstr == L"1")
        return true;
    else if (valstr == L"false" || valstr == L"no" || valstr == L"off" || valstr == L"0")
        return false;
    else
        return default_value;
}

inline std::wstring INIReader::MakeKey(std::wstring section, std::wstring name)
{
    std::wstring key = section + L"=" + name;
    // Convert to lower case to make section/name lookups case-insensitive
    towlower0((wchar_t*)key.c_str());
    return key;
}

int INIReader::ValueHandler(void* user, const wchar_t* section, const wchar_t* name, const wchar_t* value)
{
    INIReader* reader = (INIReader*)user;
    std::wstring key = MakeKey(section, name);
    if (reader->_values[key].size() > 0)
        reader->_values[key] += L"\n";
    reader->_values[key] += value;
    reader->_sections.insert(section);
    return 1;
}


#endif  // __INIREADER__