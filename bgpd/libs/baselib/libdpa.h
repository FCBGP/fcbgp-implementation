#ifndef _LIBDPA_H_
#define _LIBDPA_H_

/*
 * Dynamic Pointor Array Library.
 */

/*
 * The comparison function must return an integer less than, equal to,
 * or greater than zero if the first argument is considered to be respectively
 * less than, equal to, or greater than the second.
 *
 * If two members compare as equal, their order in the sorted array is undefined.
 */
typedef int (*dpa_cmp_t)(void *pcur, void *pobj);

typedef struct dpa_st {
    int size;
    int used;
    void **array;
} dpa_t;

extern int dpa_init(dpa_t *dpa, int size);
extern void dpa_fini(dpa_t *dpa);
extern dpa_t *dpa_create(int size);
extern void dpa_destroy(dpa_t *dpa);
extern int dpa_size(dpa_t *dpa);
extern int dpa_used(dpa_t *dpa);
extern int dpa_index(dpa_t *dpa, void *obj);
extern int dpa_search(dpa_t *dpa, void *meta, dpa_cmp_t cmp, void **ret_obj);
extern int dpa_bsearch(dpa_t *dpa, void *meta, dpa_cmp_t cmp, void **ret_obj);
extern int dpa_insert(dpa_t *dpa, void *obj, dpa_cmp_t cmp, void **ret_obj);
extern int dpa_delete(dpa_t *dpa, void *obj);
extern int dpa_sort(dpa_t *dpa, dpa_cmp_t cmp);
extern int dpa_push(dpa_t *dpa, void *obj);
extern void *dpa_pop(dpa_t *dpa);

#endif
