/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __BPF_PROBE_READ_H__
#define __BPF_PROBE_READ_H__

#define ___concat(a, b) a##b
#define ___apply(fn, n) ___concat(fn, n)
#define ___nth(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, __11, N, ...) N

/*
 * return number of provided arguments; used for switch-based variadic macro
 * definitions (see ___last, ___arrow, etc below)
 */
#define ___narg(...) ___nth(_, ##__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
/*
 * return 0 if no arguments are passed, N - otherwise; used for
 * recursively-defined macros to specify termination (0) case, and generic
 * (N) case (e.g., ___read_ptrs, ___core_read)
 */
#define ___empty(...) ___nth(_, ##__VA_ARGS__, N, N, N, N, N, N, N, N, N, N, 0)

#define ___last1(x) x
#define ___last2(a, x) x
#define ___last3(a, b, x) x
#define ___last4(a, b, c, x) x
#define ___last5(a, b, c, d, x) x
#define ___last6(a, b, c, d, e, x) x
#define ___last7(a, b, c, d, e, f, x) x
#define ___last8(a, b, c, d, e, f, g, x) x
#define ___last9(a, b, c, d, e, f, g, h, x) x
#define ___last10(a, b, c, d, e, f, g, h, i, x) x
#define ___last(...) ___apply(___last, ___narg(__VA_ARGS__))(__VA_ARGS__)

#define ___nolast2(a, _) a
#define ___nolast3(a, b, _) a, b
#define ___nolast4(a, b, c, _) a, b, c
#define ___nolast5(a, b, c, d, _) a, b, c, d
#define ___nolast6(a, b, c, d, e, _) a, b, c, d, e
#define ___nolast7(a, b, c, d, e, f, _) a, b, c, d, e, f
#define ___nolast8(a, b, c, d, e, f, g, _) a, b, c, d, e, f, g
#define ___nolast9(a, b, c, d, e, f, g, h, _) a, b, c, d, e, f, g, h
#define ___nolast10(a, b, c, d, e, f, g, h, i, _) a, b, c, d, e, f, g, h, i
#define ___nolast(...) ___apply(___nolast, ___narg(__VA_ARGS__))(__VA_ARGS__)

#define ___arrow1(a) a
#define ___arrow2(a, b) a->b
#define ___arrow3(a, b, c) a->b->c
#define ___arrow4(a, b, c, d) a->b->c->d
#define ___arrow5(a, b, c, d, e) a->b->c->d->e
#define ___arrow6(a, b, c, d, e, f) a->b->c->d->e->f
#define ___arrow7(a, b, c, d, e, f, g) a->b->c->d->e->f->g
#define ___arrow8(a, b, c, d, e, f, g, h) a->b->c->d->e->f->g->h
#define ___arrow9(a, b, c, d, e, f, g, h, i) a->b->c->d->e->f->g->h->i
#define ___arrow10(a, b, c, d, e, f, g, h, i, j) a->b->c->d->e->f->g->h->i->j
#define ___arrow(...) ___apply(___arrow, ___narg(__VA_ARGS__))(__VA_ARGS__)

#define ___type(...) typeof(___arrow(__VA_ARGS__))

#define ___read(read_fn, dst, src_type, src, accessor)                         \
  read_fn((void *)(dst), sizeof(*(dst)), &((src_type)(src))->accessor)

/* "recursively" read a sequence of inner pointers using local __t var */
#define ___rd_first(fn, src, a) ___read(fn, &__t, ___type(src), src, a);
#define ___rd_last(fn, ...)                                                    \
  ___read(fn, &__t, ___type(___nolast(__VA_ARGS__)), __t, ___last(__VA_ARGS__));
#define ___rd_p1(fn, ...)                                                      \
  const void *__t;                                                             \
  ___rd_first(fn, __VA_ARGS__)
#define ___rd_p2(fn, ...)                                                      \
  ___rd_p1(fn, ___nolast(__VA_ARGS__)) ___rd_last(fn, __VA_ARGS__)
#define ___rd_p3(fn, ...)                                                      \
  ___rd_p2(fn, ___nolast(__VA_ARGS__)) ___rd_last(fn, __VA_ARGS__)
#define ___rd_p4(fn, ...)                                                      \
  ___rd_p3(fn, ___nolast(__VA_ARGS__)) ___rd_last(fn, __VA_ARGS__)
#define ___rd_p5(fn, ...)                                                      \
  ___rd_p4(fn, ___nolast(__VA_ARGS__)) ___rd_last(fn, __VA_ARGS__)
#define ___rd_p6(fn, ...)                                                      \
  ___rd_p5(fn, ___nolast(__VA_ARGS__)) ___rd_last(fn, __VA_ARGS__)
#define ___rd_p7(fn, ...)                                                      \
  ___rd_p6(fn, ___nolast(__VA_ARGS__)) ___rd_last(fn, __VA_ARGS__)
#define ___rd_p8(fn, ...)                                                      \
  ___rd_p7(fn, ___nolast(__VA_ARGS__)) ___rd_last(fn, __VA_ARGS__)
#define ___rd_p9(fn, ...)                                                      \
  ___rd_p8(fn, ___nolast(__VA_ARGS__)) ___rd_last(fn, __VA_ARGS__)
#define ___read_ptrs(fn, src, ...)                                             \
  ___apply(___rd_p, ___narg(__VA_ARGS__))(fn, src, __VA_ARGS__)

#define ___core_read0(fn, fn_ptr, dst, src, a)                                 \
  ___read(fn, dst, ___type(src), src, a);
#define ___core_readN(fn, fn_ptr, dst, src, ...)                               \
  ___read_ptrs(fn_ptr, src, ___nolast(__VA_ARGS__))                            \
      ___read(fn, dst, ___type(src, ___nolast(__VA_ARGS__)), __t,              \
              ___last(__VA_ARGS__));
#define ___core_read(fn, fn_ptr, dst, src, a, ...)                             \
  ___apply(___core_read, ___empty(__VA_ARGS__))(fn, fn_ptr, dst, src, a,       \
                                                ##__VA_ARGS__)

#define BPF_PROBE_READ_KERNEL_INTO(dst, src, a, ...)                           \
  ({___core_read(bpf_probe_read_kernel, bpf_probe_read_kernel, dst, (src), a,  \
                 ##__VA_ARGS__)})

#define BPF_PROBE_READ_KERNEL(src, a, ...)                                     \
  ({                                                                           \
    ___type((src), a, ##__VA_ARGS__) __r;                                      \
    BPF_PROBE_READ_KERNEL_INTO(&__r, (src), a, ##__VA_ARGS__);                 \
    __r;                                                                       \
  })

#endif // __BPF_PROBE_READ_H__