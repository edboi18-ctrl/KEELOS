/* P3-T7: a shared library of the fixture's own, which musl's dynamic
 * linker must find in /lib, open, and map from the file (private file
 * mappings: text read-only and executable, data writable and private). */
static int counter;

const char *keel_greeting(void)
{
    return "Hello from a musl shared library on Keel";
}

/* Writes the library's own data segment (a private copy of the file's
 * page) and returns the new count. */
int keel_bump(void)
{
    return ++counter;
}
