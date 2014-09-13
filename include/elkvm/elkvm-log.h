#pragma once
#include <boost/log/trivial.hpp>

#define LOG_RED    "\033[31m"
#define LOG_GREEN  "\033[32m"
#define LOG_YELLOW "\033[33m"
#define LOG_RESET  "\033[0m"

#define DBG()   BOOST_LOG_TRIVIAL(debug) << LOG_YELLOW
#define INFO()  BOOST_LOG_TRIVIAL(info)
#define ERROR() BOOST_LOG_TRIVIAL(error) << LOG_RED
