int printf ( const char * format, ... );

char some_array[16] = {0};
char other_array[16] = {0};

int some_var = 123;

static void other_func() {
    printf("Hello world!\n");
    printf("some_array[0]: %d\n", some_array[0]);
    other_array[0] = 12;
    some_var = 0xdeadbeef;
}

void run() {
    some_array[0] = 1;
    printf("You just ran a ELF object!\n");
    other_func();
    printf("other_array[0]: %d\n", other_array[0]);
    printf("some_var: %d\n", some_var);
}