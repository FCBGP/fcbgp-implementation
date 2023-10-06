#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "libdpa.h"

int dpa_default_cmp(void *pcur, void *pobj)
{
    void *cur = (*(void **)pcur);
    void *obj = (*(void **)pobj);

    return cur - obj;
}

int dpa_init(dpa_t *dpa, int size)
{
    if (dpa == NULL) {
        return -EINVAL;
    }

    dpa->used = 0;
    dpa->size = size;
    dpa->array = malloc(sizeof(void *) * size);
    if (dpa->array == NULL) {
        free(dpa);
        return -ENOMEM;
    }

    return 0;
}

void dpa_fini(dpa_t *dpa)
{
    if (dpa) {
        free(dpa->array);
    }
}

dpa_t *dpa_create(int size)
{
    dpa_t *dpa = malloc(sizeof(dpa_t));
    if (dpa == NULL) {
        return NULL;
    }

    dpa->used = 0;
    dpa->size = size;
    dpa->array = malloc(sizeof(void *) * size);
    if (dpa->array == NULL) {
        free(dpa);
        return NULL;
    }

    return dpa;
}

void dpa_destroy(dpa_t *dpa)
{
    if (dpa) {
        free(dpa->array);
        free(dpa);
    }
}

int dpa_size(dpa_t *dpa)
{
    if (dpa) {
        return dpa->size;
    }

    return 0;
}

int dpa_used(dpa_t *dpa)
{
    if (dpa) {
        return dpa->used;
    }

    return 0;
}

int dpa_index(dpa_t *dpa, void *obj)
{
    int i;

    if (dpa == NULL) {
        return -EINVAL;
    }

    for (i=0; i<dpa->used; i++) {
        if (dpa->array[i] == obj) {
            return i;
        }
    }

    return -ENOENT;
}

int dpa_search(dpa_t *dpa, void *meta, dpa_cmp_t cmp, void **ret_obj)
{
    int i;
    int ret;

    if (dpa == NULL || cmp == NULL) {
        return -EINVAL;
    }

    for (i=0; i<dpa->used; i++) {
        ret = cmp(&dpa->array[i], &meta);
        if (ret == 0) {
            if (ret_obj) {
                *ret_obj = dpa->array[i];
            }

            return i;
        }
    }

    return -ENOENT;
}

int dpa_bsearch(dpa_t *dpa, void *meta, dpa_cmp_t cmp, void **ret_obj)
{
    int ret;
    int low = 0, high = dpa->used - 1, mid;

    if (dpa == NULL || cmp == NULL) {
        return -EINVAL;
    }

    while (low <= high) {
        mid = (low + high) / 2;
        ret = cmp(&dpa->array[mid], &meta);
        if (ret == 0) {
            if (ret_obj) {
                *ret_obj = dpa->array[mid];
            }

            return mid;
        } else if (ret > 0) {
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }

    return -ENOENT;
}

int dpa_insert(dpa_t *dpa, void *obj, dpa_cmp_t cmp, void **ret_obj)
{
    int i;
    int ret;

    if (ret_obj) {
        *ret_obj = NULL;
    }

    if (dpa->used == dpa->size) {
        int step = 32;
        void **new_array = realloc(dpa->array, (dpa->size + step) * sizeof(void *));
        if (new_array == NULL) {
            return -ENOMEM;
        }

        dpa->size += step;
        dpa->array = new_array;
    }

    if (cmp == NULL) {
        cmp = dpa_default_cmp;
    }

    for (i = 0; i < dpa->used; i++) {
        ret = cmp(&dpa->array[i], &obj);
        if (ret == 0) {
            if (ret_obj) {
                *ret_obj = dpa->array[i];
            }

            return i;
        } else if (ret > 0) {
            break;
        } else {
            continue;
        }
    }

    if (i < dpa->used) {
        memmove(dpa->array + i + 1, dpa->array + i, (dpa->used - i) * sizeof(void *));
    }

    dpa->array[i] = obj;
    dpa->used++;
    return 0;
}

int dpa_delete(dpa_t *dpa, void *obj)
{
    int i;

    if (dpa == NULL) {
        return -EINVAL;
    }

    for (i = 0; i < dpa->used; i++) {
        if (dpa->array[i] == obj) {
            if (i + 1 < dpa->used) {
                memmove(dpa->array + i, dpa->array + i + 1, (dpa->used - i - 1) * sizeof(void *));
            }
            dpa->used--;
            return 0;
        }
    }

    return -ENOENT;
}

int dpa_sort(dpa_t *dpa, dpa_cmp_t cmp)
{
    if (dpa == NULL) {
        return -EINVAL;
    }

    qsort(dpa->array, dpa->used, sizeof(void *), (comparison_fn_t)(cmp ? : dpa_default_cmp));

    return 0;
}

int dpa_push(dpa_t *dpa, void *obj)
{
    int i;

    if (dpa->used == dpa->size) {
        int step = 32;
        void **new_array = realloc(dpa->array, (dpa->size + step) * sizeof(void *));
        if (new_array == NULL) {
            return -ENOMEM;
        }

        dpa->size += step;
        dpa->array = new_array;
    }

    i = dpa->used;
    dpa->array[i] = obj;
    dpa->used++;
    return i;
}

void *dpa_pop(dpa_t *dpa)
{
    void *obj = NULL;

    if (dpa->used == 0) {
        return NULL;
    }

    obj = dpa->array[dpa->used - 1];
    dpa->array[dpa->used - 1] = NULL;
    dpa->used -= 1;

    return obj;
}

