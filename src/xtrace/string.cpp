#include "string.h"
#include "lock.h"

#include <assert.h>
#include <cstring>

#include <darling/emulation/syscall/common/simple.h>

//
// Helper Functions
//

int vsnprintf_wrapper(char* buffer, size_t len, const char* format, va_list args) {
	va_list string_size_args;
	va_copy(string_size_args, args);
	int size = __simple_vsnprintf(buffer, len, format, string_size_args);
	va_end(string_size_args);

	return size;
}

//
// C++ Implementation
//

namespace xtrace {
    // Static Implementation

    String* String::new_ptr() {
        void* buffer = xtrace_malloc(sizeof(String));
        return new (buffer) String();
    }

    void String::free_ptr(String* obj) {
        obj->~String();
        xtrace_free(obj);
    }
    
    String* String::to_cxx_ptr(xtrace_string_t obj) {
        return (xtrace::String*)obj;
    }

    xtrace_string_t String::to_c_ptr(String* obj) {
        return (xtrace_string_t)obj;
    }

    // Constructor and Destructor
    
    String::String() {
        constructor_internal();
    }

    String::String(const char* other) {
        constructor_internal();
        append(other);

    }

    String::String(const String* other_obj) {
        buffer_capacity = other_obj->buffer_capacity;
        buffer = (char*)xtrace_malloc(buffer_capacity);

        buffer_size = 0;
        append(other_obj->buffer);
    }

    String::~String() {
        destructor_internal();
    }

    // Methods
    
    void String::append(const char* other) {
        // If other is nullptr, use empty string
        other = (other == nullptr) ? "" : other;        
        append_format("%s", other);
    }

    void String::append(const String* other) {
        append(other->c_str());
    }

    void print_array_debug(char* value, size_t size);

    void String::append_format(const char* format, va_list args) {
        // Calculate size
        int other_buffer_size = vsnprintf_wrapper(nullptr, 0, format, args)+1; // vsnprintf length + NULL Terminator
        size_t new_buffer_size = increase_capacity_internal(other_buffer_size-1); // We will replace the current NULL Terminator

        // Point to the NULL Terminator
        char *buffer_append_string = buffer+size();
        vsnprintf_wrapper(buffer_append_string, other_buffer_size, format, args);
        
        buffer_size = new_buffer_size;
    }

    void String::append_format(const char* format, ...) {
        va_list args;
        va_start(args, format);
        append_format(format,args);
        va_end(args);
    }

    const char* String::c_str() const {
        return buffer;
    }

    void String::clear() {
        destructor_internal();
        constructor_internal();
    }

    size_t String::size() {
        // Ignore the null terminator
        return buffer_size-1;
    }

    size_t String::capacity() {
        return buffer_capacity;
    }
    
    // Internal Methods

    void String::constructor_internal() {
        buffer_capacity = 1024;
        buffer = (char*)xtrace_malloc(buffer_capacity*sizeof(char));

        buffer_size = 1;
        buffer[0] = '\0';
    }

    void String::destructor_internal() {
        xtrace_free(buffer);
        buffer = nullptr;
    }

    size_t String::increase_capacity_internal(size_t other_buffer_size) {
        size_t new_buffer_size = buffer_size+other_buffer_size;
        if (new_buffer_size > buffer_capacity) {
            size_t new_buffer_capacity = buffer_capacity + ((new_buffer_size)/1024)*1024 + 1024;
            assert(new_buffer_capacity > buffer_capacity);

            void *new_buffer = xtrace_realloc(buffer,new_buffer_capacity);
            if (new_buffer != nullptr) {
                buffer_capacity = new_buffer_capacity;
                buffer = (char*)new_buffer;
            }
        }

        return new_buffer_size;
    }
}

//
// C Implementation
//

extern "C"
xtrace_string_t xtrace_string_construct() {
    return xtrace::String::to_c_ptr(xtrace::String::new_ptr());
}

extern "C"
void xtrace_string_destruct(xtrace_string_t obj) {
    xtrace::String::free_ptr(xtrace::String::to_cxx_ptr(obj));
}

extern "C"
void xtrace_string_append_c_string(xtrace_string_t obj, const char* other) {
    xtrace::String::to_cxx_ptr(obj)->append(other);
}

extern "C"
void xtrace_string_append_xtrace_string(xtrace_string_t obj, xtrace_string_t other) {
    xtrace::String::to_cxx_ptr(obj)->append(xtrace::String::to_cxx_ptr(other));
}

extern "C"
void xtrace_string_append_format_valist(xtrace_string_t obj, const char* format, va_list args) {
    xtrace::String::to_cxx_ptr(obj)->append_format(format,args);
}

extern "C"
void xtrace_string_append_format(xtrace_string_t obj, const char* format, ...) {
    va_list args;
    va_start(args,format);
    xtrace_string_append_format_valist(obj,format,args);
    va_end(args);
}

extern "C"
void xtrace_string_clear(xtrace_string_t obj) {
    xtrace::String::to_cxx_ptr(obj)->clear();
}

extern "C"
const char* xtrace_string_c_str(xtrace_string_t obj) {
    return xtrace::String::to_cxx_ptr(obj)->c_str();
}

extern "C"
size_t xtrace_string_size(xtrace_string_t obj) {
    return xtrace::String::to_cxx_ptr(obj)->size();
}

extern "C"
size_t xtrace_string_capacity(xtrace_string_t obj) {
    return xtrace::String::to_cxx_ptr(obj)->capacity();
}
