    .section .text.startup
    .globl _start
    .type _start, @function
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __stack_top

    la t0, __data_load
    la t1, __data_start
    la t2, __data_end
1:
    bgeu t1, t2, 2f
    ld t3, 0(t0)
    sd t3, 0(t1)
    addi t0, t0, 8
    addi t1, t1, 8
    j 1b

2:
    la t0, __bss_start
    la t1, __bss_end
3:
    bgeu t0, t1, 4f
    sd zero, 0(t0)
    addi t0, t0, 8
    j 3b

4:
    call main
5:
    wfi
    j 5b
    .size _start, .-_start

