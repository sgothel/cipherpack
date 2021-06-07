
#include <botan_all.h>
#include <elevator/elevator.hpp>

#include <curl/curl.h>

using namespace elevator;

void Elevator::env_init() noexcept {
    jau::environment::get("elevator");

    curl_global_init(CURL_GLOBAL_ALL);
}
