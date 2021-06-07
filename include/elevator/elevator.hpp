#ifndef ELEVATOR_HPP_
#define ELEVATOR_HPP_

#include <elevator/IOUtil.hpp>
#include <elevator/Cipherpack.hpp>

#include <jau/environment.hpp>

namespace elevator {

class Elevator {
    public:
        static void env_init() noexcept {
            jau::environment::get("elevator");
        }
};

} // namespace elevator

#endif /* ELEVATOR_HPP_ */

