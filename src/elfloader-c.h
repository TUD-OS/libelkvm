#ifdef __cplusplus
extern "C" {
#endif

/*
 * Loads an ELF binary into the VM's system_chunk
*/
int elkvm_load_binary(const char *b, struct kvm_pager *pager);

guestptr_t elkvm_loader_get_entry_point();

/*
 * Initialize the virtual machine's heap
 */
int elkvm_heap_initialize(struct elkvm_memory_region *, uint64_t);

#ifdef __cplusplus
}
#endif

