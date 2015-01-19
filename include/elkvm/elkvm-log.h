#pragma once
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/sources/logger.hpp>

#define LOG_RED     "\033[31;1m"
#define LOG_GREEN   "\033[32m"
#define LOG_YELLOW  "\033[33m"
#define LOG_BLUE    "\033[34;1m"
#define LOG_MAGENTA "\033[35;1m"
#define LOG_CYAN    "\033[36m"
#define LOG_RESET   "\033[0m"

struct ElkvmLog
{
	boost::log::sources::logger_mt logger;

	ElkvmLog()
	  : logger()
	{
		auto sink = boost::log::add_console_log();
		boost::log::formatter fm =
		    boost::log::expressions::stream
		        << "["
		        << boost::log::expressions::format_date_time< boost::posix_time::ptime >("TimeStamp", "%H:%M:%S.%f")
		        << "] "
		        << boost::log::expressions::message
		        << LOG_RESET;
		        ;
		boost::log::add_common_attributes();
	    sink->set_formatter(fm);
	};
};

extern ElkvmLog globalElkvmLogger;

#define MY_LOG_PREFIX BOOST_LOG(globalElkvmLogger.logger) << LOG_YELLOW \
					  << "(" << std::setw(24) << __func__ << ") " << LOG_RESET

#define DBG()   MY_LOG_PREFIX
#define INFO()  MY_LOG_PREFIX
#define ERROR() MY_LOG_PREFIX << LOG_RED
