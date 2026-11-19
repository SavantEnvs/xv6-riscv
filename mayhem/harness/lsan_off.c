// Leak detection off for every target (leaks are not the bug class fuzzed here); ASan/UBSan stay on.
int __lsan_is_turned_off(void) { return 1; }
