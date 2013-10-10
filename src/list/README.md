
BSD licensed generic linked list for C99, used in [liblacewing][1] and some
other stuff.

Uses `typeof` and statement expressions which are GNU extensions, but will work
with MSVC++ with a [hack][2].

For a usage example, see [test.c][3].

[1]: https://github.com/udp/lacewing
[2]: https://raw.github.com/mozilla/rust/master/src/rt/msvc/typeof.h
[3]: https://github.com/udp/list/blob/master/test.c

Features
--------

   * "Object in list" rather than "list in object": the listed objects do not
     have to be aware of the list

   * The linked list logic (and internal representation) is separate from the
     macros

   * The list head does not require initialisation other than being cleared
     with null bytes

   * The macros are intuitive and do not require any unnecessary parameters.
     In particular, the list type does not need to be passed to each operation.

   * The loop macros expand to the head of a `for` loop, so the syntax for
     using them isn't buggered up.  This means that one can use `break` and
     `continue` normally.

List operations
---------------

     list(type, name)                 Declare a list
     list_push(list, value)           Push value to back
     list_push_front(list, value)     Push value to front
     list_pop(list)                   Pop and return value from back
     list_pop_front(list)             Pop and return value from front
     list_length(list)                Returns the list length
     list_remove(list, value)         Remove first occurrence of value from list
     list_clear(list)                 Clear the list (freeing all memory)

Element (pointer) operations
---------------------------- 

     list_elem_front(list)            Returns element at the front of list
     list_elem_back(list)             Returns element at the back of list
     list_elem_next(elem)             Returns element after elem
     list_elem_prev(elem)             Returns element before elem
     list_elem_remove(elem)           Remove element elem

Loops
-----

     list_each(list, elem) { ... }

Loops through each list element, front to back.  `elem` will be declared and
set to the actual value of each element (not a pointer or iterator)
                     
     list_each_r(list, elem) { ... }

Loops through each list element, back to front.  `elem` will be declared and
set to the actual value of each element (not a pointer or iterator)

     list_each_elem(list, elem) { ... }

Loops through each list element, front to back.  `elem` will be declared and
set to a pointer to each element.
                     
     list_each_r_elem(list, elem) { ... }

Loops through each list element, back to front.  `elem` will be declared and
set to a pointer to each element.

