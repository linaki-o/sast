#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace demo {

class Buffer {
public:
    Buffer(int size);
    ~Buffer();

    int size() const { return size_; }
    const char *data() const { return data_; }

private:
    int  size_;
    char *data_;
};

Buffer::Buffer(int size) : size_(size), data_(new char[size]) {
    memset(data_, 0, size);
}

Buffer::~Buffer() {
    delete[] data_;
}

int sum(const std::vector<int> &values)
{
    int total = 0;
    for (const auto &value : values) {
        total += value;
    }
    return total;
}

std::string greet(const std::string &name)
{
    unsigned int i = 0;
    while (i >= 0) {
        --i;
    }
    try {
        return "Hello, " + name;
    } catch (const std::exception &e) {
        return std::string("error");
    }
}

}  // namespace demo
