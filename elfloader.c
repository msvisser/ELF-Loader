#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include "elfloader.h"

void dump_section_table(elf64_section_header_t *elf_section_headers, size_t section_count, char *section_strtab) {
    printf("IND |                 MAME |     TYPE | FLAG | OFFSET |   SIZE | ADDRESS          |\n");
    printf("----+----------------------+----------+------+--------+--------+------------------+\n");
    for (size_t index = 0; index < section_count; index++) {
        elf64_section_header_t *section = (elf_section_headers + index);
        char *name = (section_strtab + section->name_index);

        printf("%3zu | ", index);
        printf("%20s | ", name);
        printf("%8s | ", ELF_SECTION_TYPE[section->type]);
        printf("%c%c%c%c | ",
            (section->flags & ELF_FLAG_WRITE) ? 'W' : ' ',
            (section->flags & ELF_FLAG_ALLOC) ? 'A' : ' ',
            (section->flags & ELF_FLAG_EXEC) ? 'X' : ' ',
            (section->flags & ~0x7) ? '?' : ' '
        );
        printf("%6llx | ", section->offset);
        printf("%6llx | ", section->size);
        printf("%.16llx | ", section->address);
        printf("\n");
    }
}

int main(int argc, const char **argv) {
    if (argc != 2) {
        return 1;
    }

    const char *object_file_name = argv[1];
    FILE *object_file = fopen(object_file_name, "rb");
    if (object_file == NULL) {
        fprintf(stderr, "Unable to open file\n");
        return 1;
    }

    elf64_header_t *elf_header = malloc(sizeof(elf64_header_t));
    fread(elf_header, sizeof(elf64_header_t), 1, object_file);

    if (elf_header->magic != 0x464c457f) {
        fprintf(stderr, "Invalid ELF header!\n");
        return 1;
    }

    if (elf_header->file_class != ELF_CLASS_64 ||
        elf_header->encoding != ELF_DATA_LITTLE)
    {
        fprintf(stderr, "This file is not 64bit little endian\n");
        return 1;
    }

    if (elf_header->file_type != ELF_FILE_REL) {
        fprintf(stderr, "This file is not a relocatable object file\n");
        return 1;
    }

    if (elf_header->section_header_size != sizeof(elf64_section_header_t)) {
        fprintf(stderr, "Section header size does not match\n");
        return 1;
    }

    // Setup variable for the section headers
    size_t section_count = elf_header->section_header_count;
    size_t section_header_size = sizeof(elf64_section_header_t);
    elf64_section_header_t *elf_section_headers = malloc(section_header_size * section_count);
    // Read section headers from the file
    fseek(object_file, elf_header->section_header_offset, SEEK_SET);
    fread(elf_section_headers, section_header_size, section_count, object_file);

    printf(">> Allocating sections memory and loading string and symbol tables\n");
    for (size_t index = 0; index < section_count; index++) {
        elf64_section_header_t *section = (elf_section_headers + index);

        // If this section should allocate memory and is bigger than 0
        if ((section->flags & ELF_FLAG_ALLOC) && section->size > 0) {
            // Allocate memory, currenty RW so we can write to it
            char *mem = mmap(NULL, section->size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
            if (mem == MAP_FAILED) {
                fprintf(stderr, "Unable to mmap\n");
                return 2;
            }

            if (section->type == ELF_SECTION_PROGBITS) {
                // Read data from the file
                fseek(object_file, section->offset, SEEK_SET);
                fread(mem, section->size, 1, object_file);
            } else if (section->type == ELF_SECTION_NOBITS) {
                // Section is empty, so fill with zeros
                memset(mem, '\0', section->size);
            }
            section->address = (uint64_t)(size_t) mem;
        }

        // Load symbol and string tables from the file
        if (section->type == ELF_SECTION_SYMTAB || section->type == ELF_SECTION_STRTAB) {
            elf64_symbol_t *table = malloc(section->size);

            fseek(object_file, section->offset, SEEK_SET);
            fread(table, section->size, 1, object_file);

            section->address = (uint64_t)(size_t) table;
        }
    }

    printf(">> Applying symbol relocation\n");
    for (size_t index = 0; index < section_count; index++) {
        elf64_section_header_t *section = (elf_section_headers + index);

        if (section->type == ELF_SECTION_RELA) {
            size_t entry_count = section->size / section->entry_size;
            if (section->entry_size != sizeof(elf64_rela_entry_t)) {
                fprintf(stderr, "RELA entry size does not match\n");
                return 1;
            }

            // Load relocation entries from the file
            elf64_rela_entry_t *entries = malloc(section->size);
            section->address = (uint64_t)(size_t) entries;
            fseek(object_file, section->offset, SEEK_SET);
            fread(entries, section->size, 1, object_file);

            // Locate the section we are relocating
            elf64_section_header_t *relocation_section = (elf_section_headers + section->info);
            char *relocation_section_data = (char *) relocation_section->address;

            // Locate the symbol table for this relocation table
            elf64_section_header_t *section_symbol_table = (elf_section_headers + section->link);
            elf64_symbol_t *symbol_table = (elf64_symbol_t *)(section_symbol_table->address);

            // Locate the string table for the symbol table
            elf64_section_header_t *section_string_table = (elf_section_headers + section_symbol_table->link);
            char *string_table = (char *)(section_string_table->address);

            // Relocate all the entries
            for (size_t entry_ind = 0; entry_ind < entry_count; entry_ind++) {
                elf64_rela_entry_t *entry = (entries + entry_ind);

                // Find the symbol for this entry
                elf64_symbol_t *symbol = (symbol_table + entry->symbol);
                char *symbol_name = (string_table + symbol->name_index);

                if (entry->type == ELF_REL_TYPE_64) {
                    // Determine the offset in the section
                    uint64_t *location = (uint64_t *)(relocation_section_data + entry->offset);

                    // Check that the symbol is defined in this file
                    if (symbol->section > 0) {
                        // Print out which symbol is being relocated
                        if (symbol->name_index) {
                            printf("Relocating symbol: %s\n", symbol_name);
                        } else {
                            elf64_section_header_t *shstrtab = (elf_section_headers + elf_header->string_table_index);
                            elf64_section_header_t *section = (elf_section_headers + symbol->section);
                            printf("Relocating symbol: %s%+lld\n", ((char *)shstrtab->address) + section->name_index, entry->addend);
                        }
                        // Calculate the location of the symbol
                        elf64_section_header_t *symbol_section = (elf_section_headers + symbol->section);
                        uint64_t symbol_value = symbol_section->address + symbol->value + entry->addend;

                        // Store the location
                        *location = symbol_value;
                    } else {
                        // The symbol is not defined inside the object file
                        // resolve using other rules
                        if (strcmp("printf", symbol_name) == 0) {
                            *location = (uint64_t)(&printf);
                        } else {
                            fprintf(stderr, "Unknown symbol: %s\n", symbol_name);
                            return 1;
                        }
                    }
                } else {
                    fprintf(stderr, "Unknown relocation type: %d\n", entry->type);
                    return 1;
                }
            }
        }
    }

    printf(">> Correcting memory protection\n");
    for (size_t index = 0; index < section_count; index++) {
        elf64_section_header_t *section = (elf_section_headers + index);

        // Allocated sections are mmaped, but their permissions are incorrect
        if ((section->flags & ELF_FLAG_ALLOC) && section->size > 0) {
            // Calculate the correct permissions
            int prot = PROT_READ;
            if (section->flags & ELF_FLAG_WRITE) prot |= PROT_WRITE;
            if (section->flags & ELF_FLAG_EXEC) prot |= PROT_EXEC;

            // Update the protection on the memory
            mprotect((void *) section->address, section->size, prot);
        }
    }

    // Dump the sections as a table
    elf64_section_header_t *shstrtab = (elf_section_headers + elf_header->string_table_index);
    dump_section_table(elf_section_headers, section_count, (char *) shstrtab->address);

    printf(">> Finding run() function\n");
    void_func_t run_func;
    for (size_t index = 0; index < section_count; index++) {
        elf64_section_header_t *section = (elf_section_headers + index);

        // Look in all symbol tables for the run function
        if (section->type == ELF_SECTION_SYMTAB) {
            elf64_symbol_t *symbol_table = (elf64_symbol_t *) section->address;

            // Find the string table for this symbol table
            elf64_section_header_t *section_string_table = (elf_section_headers + section->link);
            char *string_table = (char *)(section_string_table->address);

            size_t symbol_count = section->size / section->entry_size;
            for (size_t i = 0; i < symbol_count; i++) {
                // Get the symbol from the table
                elf64_symbol_t *symbol = (symbol_table + i);
                char *symbol_name = (string_table + symbol->name_index);
                elf64_section_header_t *run_section = (elf_section_headers + symbol->section);

                // Check if it is the run symbol
                if (strcmp("run", symbol_name) == 0 && ((symbol->info >> 4) & 0xf) == 1 && (run_section->flags & ELF_FLAG_EXEC)) {
                    // Calculate the symbol location
                    run_func = (void_func_t)(run_section->address + symbol->value);
                    break;
                }
            }
        }

        if (run_func) break;
    }

    // Call the run function from the object file
    if (run_func != NULL) {
        printf(">> Running run() function\n\n");
        run_func();
    } else {
        fprintf(stderr, "Unable to locate run()\n");
        return 1;
    }

    return 0;
}