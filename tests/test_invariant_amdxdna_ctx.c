#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Mock structures matching amdxdna_ctx.c */
typedef struct {
    struct {
        size_t size;
    } mem;
} amdxdna_bo_t;

typedef struct {
    char data[256];
} amdxdna_cmd_t;

/* Simulate the vulnerable memcpy pattern from amdxdna_ctx.c */
static void vulnerable_copy(amdxdna_cmd_t *cmd, const char *err_data, 
                            size_t size, amdxdna_bo_t *abo)
{
    if (!cmd || !err_data || !abo) return;
    
    /* Vulnerable: if abo->mem.size < sizeof(*cmd), underflow occurs */
    size_t copy_len = (size < (abo->mem.size - sizeof(*cmd))) ? 
                      size : (abo->mem.size - sizeof(*cmd));
    
    memcpy(cmd->data, err_data, copy_len);
}

START_TEST(test_buffer_read_overflow_protection)
{
    /* Invariant: Buffer reads never exceed declared length; 
       underflow in size calculation must not cause heap overflow */
    
    amdxdna_cmd_t cmd;
    amdxdna_bo_t abo;
    
    /* Test payloads: exploit case, boundary, valid input */
    const struct {
        size_t abo_size;
        size_t data_size;
        const char *label;
    } payloads[] = {
        { 4, 1024, "underflow: abo_size < sizeof(cmd)" },
        { sizeof(amdxdna_cmd_t), 512, "boundary: abo_size == sizeof(cmd)" },
        { 1024, 256, "valid: abo_size >> sizeof(cmd)" }
    };
    
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
    
    for (int i = 0; i < num_payloads; i++) {
        memset(&cmd, 0, sizeof(cmd));
        abo.mem.size = payloads[i].abo_size;
        
        char *large_data = malloc(payloads[i].data_size);
        ck_assert_ptr_nonnull(large_data);
        memset(large_data, 'A', payloads[i].data_size);
        
        /* Call vulnerable function with oversized input */
        vulnerable_copy(&cmd, large_data, payloads[i].data_size, &abo);
        
        /* Invariant: cmd.data buffer (256 bytes) must not be overwritten beyond bounds */
        for (int j = 256; j < 512; j++) {
            ck_assert_int_eq(((char*)&cmd)[j], 0);
        }
        
        free(large_data);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_read_overflow_protection);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}