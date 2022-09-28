/*
 * Contains logic required to transform stack and register values.
 * Based on transformation code written in popcorn-compiler:
 * https://github.com/ssrg-vt/popcorn-compiler.
 *
 * Original Author: Rob Lyerly
 * Current version Author: Abhishek Bapat
 * Date: 09/14/2022
 */

#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include "stack_transform.h"
#include "definitions.h"
#include "util.h"


static st_handle aarch64_handle = NULL;
static st_handle x86_64_handle = NULL;


static int create_file_path(char *fn_buf, const char *bin_fn, const char *suffix)
{
    char *temp;
    if(!fn_buf)
    {
        pr_err("fn_buf is NULL!\n");
        return 1;
    }
    memset(fn_buf, '\0', sizeof(char) * BUF_SIZE);
    temp = strrchr(bin_fn, '/');
    if(!temp){
        pr_err("Could not find / in path!\n");
        return 1;
    }
    strncat(fn_buf, bin_fn, temp-bin_fn+1);
    strcat(fn_buf, "bin/");
    strcat(fn_buf, temp+1);
    strcat(fn_buf, suffix);
    return 0;
}

int initialize(char *bin_fn)
{
    char *x86_64_fn, *aarch64_fn;
    x86_64_fn = (char *)xmalloc(sizeof(char) * BUF_SIZE);
    if(!x86_64_fn){
        pr_err("Could not allocate memory for x86_64_fn!\n");
        return 1;
    }
    if(create_file_path(x86_64_fn, bin_fn, "_x86-64")){
        pr_err("Error creating x86-64 bin path!\n");
        return 1;
    }

    aarch64_fn = (char *)xmalloc(sizeof(char) * BUF_SIZE);
    if(!aarch64_fn){
        pr_err("Could not allocate memory for aarch64_fn!\n");
        return 1;
    }
    if(create_file_path(aarch64_fn, bin_fn, "_aarch64")){
        pr_err("Error creating aarch64 bin path!\n");
        return 1;
    }

    return 0;
}
/*
 * Rewrite from source to destination stack.
 */
int st_userspace_rewrite(void* cur_stack,
                         void* new_stack,
                         enum arch src_arch,
                         void* src_regs,
                         enum arch dest_arch,
                         void* dest_regs)
{
  st_handle src_handle, dest_handle;

  switch(src_arch)
  {
  case ARCH_AARCH64: src_handle = aarch64_handle; break;
  case ARCH_X86_64: src_handle = x86_64_handle; break;
  default: pr_err("Unsupported source architecture!\n"); return 1;
  }

  if(!src_handle)
  {
    pr_err("Could not load rewriting information for source!\n");
    return 1;
  }

  switch(dest_arch)
  {
  case ARCH_AARCH64: dest_handle = aarch64_handle; break;
  case ARCH_X86_64: dest_handle = x86_64_handle; break;
  default: pr_err("Unsupported destination architecture!\n"); return 1;
  }

  if(!dest_handle)
  {
    pr_err("Could not rewriting information for destination!\n");
    return 1;
  }
 
  if(st_rewrite_stack(src_handle, src_regs, cur_stack,
                      dest_handle, dest_regs, new_stack))
  {
    pr_err("stack transformation failed (%s -> %s)\n",
            arch_name(src_handle->arch), arch_name(dest_handle->arch));
    return 1;
  }
  return 0;
}

