.global go

#include "sc.h"

go:
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	movq $55,%rax				/* getsockopt */
	movq $3,%rdi				/* FD */
	movq $0x6,%rsi				/* TCP_LEVEL */
	movq $11, %rdx				/* TCP_INFO */
	leaq  -(DATA_OFFSET)(%rsp),%r10 	/* BUF */
	movq $SZTCP,-(BLEN_OFFSET)(%rsp)
	leaq -(BLEN_OFFSET)(%rsp),%r8		/* sizeof tcp_info */
	syscall
	int3

	retq
.string "END"
