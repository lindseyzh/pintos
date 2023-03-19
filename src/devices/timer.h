#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include <round.h>
#include <stdint.h>
#include <list.h>

/** Number of timer interrupts per second. */
#define TIMER_FREQ 100

/** This is a struct used for recording sleeping threads status.
 * If a thread falls into sleep, a sleep_entry element is created for it.
 */
struct sleep_entry{
  struct list_elem elem;
  struct thread* thread_pointer;
  int64_t wakeup_time; // The earlist time a thread can be woken
};

/** A list to store sleep_entry */
struct list sleep_entry_list; 

void timer_init (void);
void timer_calibrate (void);

int64_t timer_ticks (void);
int64_t timer_elapsed (int64_t);

/** Sleep and yield the CPU to other threads. */
void timer_sleep (int64_t ticks);
void timer_msleep (int64_t milliseconds);
void timer_usleep (int64_t microseconds);
void timer_nsleep (int64_t nanoseconds);

/* check if the sleeping threads should be awaken*/
void sleep_check(void);

/** Busy waits. */
void timer_mdelay (int64_t milliseconds);
void timer_udelay (int64_t microseconds);
void timer_ndelay (int64_t nanoseconds);

void timer_print_stats (void);

#endif /**< devices/timer.h */
