
/* vim: set ft=c et ts=3 sw=3 sts=3:
 *
 * Copyright (C) 2013 James McLaughlin.  All rights reserved.
 * http://github.com/udp/list
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "list.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

int main (int argc, char * argv [])
{
   list (int, list);
   memset (&list, 0, sizeof (list));

   assert (list_length (list) == 0);

   list_push (list, 6);
   list_push_front (list, 5);
   list_push (list, 7);
   list_push (list, 8);
   list_push (list, 9);
   list_push (list, 10);

   assert (list_length (list) == 6);
   
   list_push_front (list, 4);
   list_push_front (list, 3);
   list_push_front (list, 2);
   list_push_front (list, 1);
   list_push_front (list, 0);

   assert (list_length (list) == 11);

   list_each (list, value)
   {
      printf ("%d ", value);
   }

   printf ("\n");

   assert (!list_find (list, 11));
   assert (list_find (list, 5));

   list_remove (list, 5);

   assert (list_length (list) == 10);
   assert (!list_find (list, 5));

   list_each_elem (list, elem)
   {
       if (*elem % 2 != 0)
           list_elem_remove (elem);
   }

   assert (list_length (list) == 6);

   list_each_r (list, value)
   {
      printf ("%d ", value);
   }

   printf ("\n");

   for (int i = 0; i < 10000; ++ i)
   {
       list_push_front (list, i);
   }

   assert (list_length (list) == 10006);

   int n = 0;

   list_each_elem (list, elem)
   {
       ++ n;
       list_elem_remove (elem);
   }

   assert (n == 10006);

   assert (list_length (list) == 0);

   return 0;
}



