#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MEMORY_SIZE (1 << 27)  // 2^27 addresses (~134M entries)
#define STACK_SIZE 16

// Instruction set (5-bit opcodes)
#define LDA  0x01  // Load accumulator from memory
#define STA  0x02  // Store accumulator to memory
#define LDB  0x03  // Load B register from memory
#define STB  0x04  // Store B register to memory
#define ADD  0x05  // Add B register to accumulator
#define SUB  0x06  // Subtract B register from accumulator
#define JMP  0x07  // Jump to address
#define JZ   0x08  // Jump if zero
#define HLT  0x1F  // Halt execution (max 5-bit opcode)

typedef struct {
    uint32_t *memory;           // 32-bit memory array
    uint32_t accumulator;       // 32-bit accumulator
    uint32_t b_register;        // 32-bit B register
    uint32_t program_counter;   // 32-bit program counter
    uint8_t  stack[STACK_SIZE];
    uint8_t  stack_pointer;
    uint8_t  zero_flag;
    uint8_t  running;
} Computer;

void init_computer(Computer *c) {
    c->memory = malloc(MEMORY_SIZE * sizeof(uint32_t));
    if (!c->memory) { perror("malloc"); exit(EXIT_FAILURE); }
    memset(c->memory, 0, MEMORY_SIZE * sizeof(uint32_t));
    c->accumulator    = 0;
    c->b_register     = 0;
    c->program_counter= 0;
    c->stack_pointer  = 0;
    c->zero_flag      = 0;
    c->running        = 1;
}

void execute_instruction(Computer *c, FILE *out) {
    uint32_t instr   = c->memory[c->program_counter];
    uint8_t  opcode  = (instr >> 27) & 0x1F;        // top 5 bits
    uint32_t operand = instr & 0x07FFFFFF;         // lower 27 bits

    switch (opcode) {
        case LDA:
            c->accumulator = c->memory[operand];
            c->program_counter++;
            fprintf(out, "LDA 0x%08X: Acc = 0x%08X\n", operand, c->accumulator);
            break;

        case STA:
            c->memory[operand] = c->accumulator;
            c->program_counter++;
            fprintf(out, "STA 0x%08X: Mem[0x%08X] = 0x%08X\n",
                    operand, operand, c->accumulator);
            break;

        case LDB:
            c->b_register = c->memory[operand];
            c->program_counter++;
            fprintf(out, "LDB 0x%08X: B = 0x%08X\n", operand, c->b_register);
            break;

        case STB:
            c->memory[operand] = c->b_register;
            c->program_counter++;
            fprintf(out, "STB 0x%08X: Mem[0x%08X] = 0x%08X\n",
                    operand, operand, c->b_register);
            break;

        case ADD:
            c->accumulator += c->b_register;
            c->zero_flag = (c->accumulator == 0);
            c->program_counter++;
            fprintf(out, "ADD: Acc = 0x%08X\n", c->accumulator);
            break;

        case SUB:
            c->accumulator -= c->b_register;
            c->zero_flag = (c->accumulator == 0);
            c->program_counter++;
            fprintf(out, "SUB: Acc = 0x%08X\n", c->accumulator);
            break;

        case JMP:
            c->program_counter = operand;
            fprintf(out, "JMP to 0x%08X\n", operand);
            break;

        case JZ:
            if (c->zero_flag) {
                c->program_counter = operand;
                fprintf(out, "JZ: Jump to 0x%08X (zero)\n", operand);
            } else {
                c->program_counter++;
                fprintf(out, "JZ: No jump\n");
            }
            break;

        case HLT:
            c->running = 0;
            fprintf(out, "HLT: Halt execution\n");
            break;

        default:
            fprintf(out, "Unknown opcode: 0x%02X\n", opcode);
            c->running = 0;
    }
}

void run_computer(Computer *c, FILE *out) {
    while (c->running) {
        execute_instruction(c, out);
    }
}

int main(void) {
    Computer cpu;
    init_computer(&cpu);

    FILE *out = fopen("output.txt", "w");
    if (!out) { perror("fopen"); free(cpu.memory); return EXIT_FAILURE; }

    // Example program
    uint32_t program[] = {
        (LDA << 27) | 0x00000010,
        (STA << 27) | 0x00000020,
        (LDA << 27) | 0x00000011,
        (STA << 27) | 0x00000021,
        (HLT << 27) | 0x00000000
    };
    size_t prog_len = sizeof(program) / sizeof(program[0]);
    memcpy(cpu.memory, program, prog_len * sizeof(uint32_t));

    // Initialize data
    cpu.memory[0x10] = 0x0000000A;
    cpu.memory[0x11] = 0x00000014;

    run_computer(&cpu, out);
    fclose(out);
    free(cpu.memory);
    return EXIT_SUCCESS;
}
