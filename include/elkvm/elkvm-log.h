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

/* TSC measurement stuff */

static __inline__ __attribute__((used))
unsigned long long rdtsc(void)
{
  unsigned hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}


#define TSC_FUNCTION_PROLOG(sample_size) \
    static const int _tsc_count = (sample_size); /* number of samples */ \
    static uint64_t _tsc[_tsc_count];   /* sample array */ \
    static int _tsc_idx = 0;            /* next sample to save */ \
    static int _tsc_counter = 0;        /* number of sampling intervals */ \
    uint64_t _tsc1, _tsc2;              /* tsc sample for this call */ \
    _tsc1 = rdtsc();                    /* entry TSC measure */

#define TSC_END do { \
    _tsc2 = rdtsc(); \
    _tsc[_tsc_idx++] = _tsc2 - _tsc1; \
    if (_tsc_idx == _tsc_count) { \
        uint64_t _sum = 0; \
        _tsc_counter += 1; \
        for (unsigned i = 0; i < _tsc_count; ++i) { \
            _sum += _tsc[i]; \
        } \
        INFO() << "[" << _tsc_counter << "] " << _tsc_count \
               << " timestamps: " << std::dec \
               << _sum / _tsc_count << " cycles per call."; \
        _tsc_idx = 0; \
    } \
} while (0)
