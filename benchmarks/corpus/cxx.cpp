/*
 * CodeShield benchmark corpus - C++ specific constructs.
 */

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace bench {

class Engine
{
public:
    explicit Engine(int capacity);
    ~Engine();

    int capacity() const { return capacity_; }
    const char *name() const { return name_; }

    void push(int value);

private:
    int         capacity_;
    char       *name_;
    std::vector<int> values_;
};

Engine::Engine(int capacity) : capacity_(capacity), name_(nullptr)
{
    name_ = new char[32];
    std::memset(name_, 0, 32);
}

Engine::~Engine()
{
    delete[] name_;
}

void Engine::push(int value)
{
    values_.push_back(value);
}

int sum_of(const std::vector<int> &values)
{
    int total = 0;

    for (const auto &value : values) {
        total += value;
    }
    return total;
}

std::string greet(const std::string &name)
{
    return "Hello, " + name;
}

/* ------------------------------------------------------------------ */
/* Planted defects                                                     */
/* ------------------------------------------------------------------ */

void copy_name(char *destination, const char *source)
{
    char buffer[32];

    std::strcpy(buffer, source); /* sast:expect SEC-BUF-001 */
    std::strncpy(destination, buffer, sizeof(buffer) - 1);
}

void format_user(const char *user_input)
{
    std::printf(user_input); /* sast:expect SEC-FMT-001 */
}

unsigned int spin_down()
{
    unsigned int counter = 0;

    while (counter >= 0) { /* sast:expect QLT-LOOP-001 */
        counter--;
    }
    return counter;
}
void throw_from_core()
{
    try {
        throw std::runtime_error("failure"); /* sast:expect MISRA-21-012 */
    } catch (const std::exception &error) {
        std::printf("%s\n", error.what());
    }
}

}  // namespace bench
