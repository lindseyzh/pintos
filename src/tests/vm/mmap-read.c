/** Uses a memory mapping to read a file. */

#include <string.h>
#include <syscall.h>
#include "tests/vm/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void)
{
  char *actual = (char *) 0x10000000;
  int handle;
  mapid_t map;
  size_t i;

  CHECK ((handle = open ("sample.txt")) > 1, "open \"sample.txt\"");
  CHECK ((map = mmap (handle, actual)) != MAP_FAILED, "mmap \"sample.txt\"");

  /* Check that data is correct. */
  if (memcmp (actual, sample, strlen (sample))){
    // size_t a = strlen(sample);
    // size_t b = strlen(actual);
    // size_t len = a < b ? a : b;
    // printf("Length: %d, should be %d\n", a, b);
    // for(size_t i = 0; i < len; i++){
    //   if(sample[i] != actual[i]){
    //     printf("Error in char %d: '%c', should be '%c'\n", 
    //           i, sample[i], actual[i]);
    //   }
    // }
    fail ("read of mmap'd file reported bad data");
  }
  /* Verify that data is followed by zeros. */
  for (i = strlen (sample); i < 4096; i++)
    if (actual[i] != 0)
      fail ("byte %zu of mmap'd region has value %02hhx (should be 0)",
            i, actual[i]);

  munmap (map);
  close (handle);
}
