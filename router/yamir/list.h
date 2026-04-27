#ifndef _LIST_H_
#define _LIST_H_

// list api - doubly linked list code
struct list_elem {
    struct list_elem *next;
    struct list_elem *prev;
};

#define list_entry(ptr, type, member) containerof(ptr, type, member)
#define list_isempty(list) ((list)->next == (list))
#define list_inuse(elem) ((elem)->next != NULL)

#define list_first_entry(ptr, type, field) list_entry((ptr)->next, type, field)
#define list_next_entry(ptr, field) list_entry((ptr)->field.next, __typeof__(*ptr), field)
#define list_prev_entry(ptr, field) list_entry((ptr)->field.prev, __typeof__(*ptr), field) 

#define list_first(head, entry, field) \
    list_isempty(head) ? NULL : list_first_entry(head, entry, field)

// iterate over a list (cannot be modifed)
#define list_fornext(head, elem) \
    for ((elem) = (head)->next; (elem) != (head); (elem) = (elem)->next)

#define list_forprev(head, elem) \
    for ((elem) = (head)->prev; (elem) != (head); (elem) = (elem)->prev)

// iterate over a list (can be modifed)
#define list_fornext_safe(head, elem, next) \
    for ((elem) = (head)->next, (next) = (elem)->next; \
        (elem) != (head); \
        (elem) = (next), (next) = (elem)->next)

#define list_forprev_safe(head, elem, prev) \
    for ((elem) = (head)->prev, (prev) = (elem)->prev; \
        (elem) != (head); \
        (elem) = (prev), (prev) = (elem)->prev)

// iterate over list entries (cannot be modifed)
#define list_fornext_entry(head, entry, field) \
    for ((entry) = list_first_entry(head, __typeof__(*entry), field); \
        &(entry)->field != (head); \
        (entry) = list_next_entry(entry, field))

// iterate over list entries (can be modifed)
#define list_fornext_entry_safe(head, entry, next, field) \
    for ((entry) = list_first_entry(head, __typeof__(*entry), field), \
        (next) = list_next_entry(entry, field); \
        &(entry)->field != (head); \
        (entry) = (next), (next) = list_next_entry(next, field))


// init list elem to point to itself
static inline void list_init(struct list_elem *elem)
{
    elem->next = elem;
    elem->prev = elem;
}

// prev <-> node <-> next
static inline void list_chain(struct list_elem *prev,
    struct list_elem *node, struct list_elem *next)
{
    next->prev = node;
    node->next = next;
    node->prev = prev;
    prev->next = node;
}

// add node to start of list
static inline void list_prepend(struct list_elem *head, struct list_elem *node)
{
    list_chain(head, node, head->next);
}

// add node to end of list
static inline void list_append(struct list_elem *head, struct list_elem *node)
{
     list_chain(head->prev, node, head);
}

// remove node from list
static inline void list_remove(struct list_elem *elem)
{
    elem->prev->next = elem->next;
    elem->next->prev = elem->prev;
    elem->next = NULL;
    elem->prev = NULL;
}

static inline void list_replace(struct list_elem *old_elem, struct list_elem *new_elem)
{
    new_elem->prev = old_elem->prev;
    new_elem->next = old_elem->next;

    old_elem->prev = NULL;
    old_elem->next = NULL;

    new_elem->prev->next = new_elem;
    new_elem->next->prev = new_elem;
}

#endif
