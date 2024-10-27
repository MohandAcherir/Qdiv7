
# MIPS Architecture and Assembly Language

## Table of Contents
1. [Introduction to MIPS Architecture](#introduction-to-mips-architecture)
2. [MIPS Instruction Formats](#mips-instruction-formats)
3. [Registers and Memory in MIPS](#registers-and-memory-in-mips)
4. [Addressing Modes in MIPS](#addressing-modes-in-mips)
5. [Common MIPS Instructions](#common-mips-instructions)
6. [Writing and Running MIPS Assembly Code](#writing-and-running-mips-assembly-code)
7. [Example Programs](#example-programs)
8. [Best Practices in MIPS Assembly](#best-practices-in-mips-assembly)
9. [Additional Resources](#additional-resources)

---

## 1. Introduction to MIPS Architecture

The MIPS (Microprocessor without Interlocked Pipeline Stages) architecture is a RISC (Reduced Instruction Set Computer) design known for its simplicity and efficiency. Developed in the 1980s by MIPS Computer Systems, this architecture is widely used in education, embedded systems, and various computing devices.

MIPS processors use a fixed-length instruction format and operate on registers rather than directly on memory, making it efficient for pipelining and instruction processing.

Key features of MIPS architecture:
- **32 General-purpose registers** (each 32 bits wide).
- **Load/store architecture**: Arithmetic and logical operations are performed on registers.
- **Fixed instruction length**: All instructions are 32 bits.
- **Three instruction formats**: R, I, and J formats.
- **Big Endian memory**: Memory is organized with the most significant byte at the lowest address.

---

## 2. MIPS Instruction Formats

MIPS instructions are represented in three main formats:

1. **R-format (Register)**: Used for arithmetic and logical operations.
   - Fields: `opcode` (6 bits), `rs` (5 bits), `rt` (5 bits), `rd` (5 bits), `shamt` (5 bits), `funct` (6 bits).

   ```assembly
   add $t0, $t1, $t2   # Adds contents of $t1 and $t2, stores result in $t0
   ```

2. **I-format (Immediate)**: Used for data transfer and immediate arithmetic.
   - Fields: `opcode` (6 bits), `rs` (5 bits), `rt` (5 bits), `immediate` (16 bits).

   ```assembly
   addi $t0, $t1, 5    # Adds 5 to the contents of $t1, stores result in $t0
   ```

3. **J-format (Jump)**: Used for jump instructions.
   - Fields: `opcode` (6 bits), `address` (26 bits).

   ```assembly
   j label             # Jumps to the specified label
   ```

---

## 3. Registers and Memory in MIPS

MIPS has 32 registers, each 32 bits wide. Some important registers include:

- **$zero**: Always holds 0.
- **$v0-$v1**: Return values for functions.
- **$a0-$a3**: Arguments for functions.
- **$t0-$t9**: Temporary registers.
- **$s0-$s7**: Saved registers.
- **$sp**: Stack pointer.
- **$ra**: Return address for function calls.

Memory in MIPS is divided into segments:
- **Text segment**: Stores the program code.
- **Data segment**: Stores global and static variables.
- **Stack segment**: Stores temporary data and function calls.

---

## 4. Addressing Modes in MIPS

MIPS uses several addressing modes:
- **Immediate Addressing**: Directly uses a constant (e.g., `addi $t0, $t0, 10`).
- **Register Addressing**: Uses contents of registers (e.g., `add $t0, $t1, $t2`).
- **Base (Displacement) Addressing**: Uses a base address in a register plus an offset (e.g., `lw $t0, 4($s0)`).
- **PC-Relative Addressing**: Used in branching; offset is added to the Program Counter (PC).
- **Pseudo-Direct Addressing**: Used in jump instructions; address is embedded in the instruction.

---

## 5. Common MIPS Instructions

| Instruction | Description                      |
|-------------|----------------------------------|
| `add`       | Addition                         |
| `sub`       | Subtraction                      |
| `and`       | Bitwise AND                      |
| `or`        | Bitwise OR                       |
| `sll`       | Shift Left Logical               |
| `srl`       | Shift Right Logical              |
| `lw`        | Load Word                        |
| `sw`        | Store Word                       |
| `beq`       | Branch if Equal                  |
| `bne`       | Branch if Not Equal              |
| `j`         | Jump                             |

---

## 6. Writing and Running MIPS Assembly Code

To write MIPS code, use a text editor and save it with a `.asm` extension. You can run MIPS assembly using a simulator like **SPIM** or **QtSPIM**.

Example Code:

```assembly
# Program to add two numbers
.data
num1: .word 5
num2: .word 10
result: .word 0

.text
main:
    lw $t0, num1           # Load num1 into $t0
    lw $t1, num2           # Load num2 into $t1
    add $t2, $t0, $t1      # Add $t0 and $t1, store in $t2
    sw $t2, result         # Store result
    li $v0, 10             # Exit
    syscall
```

---

## 7. Example Programs

### Example 1: Loop and Sum Array

```assembly
.data
array: .word 1, 2, 3, 4, 5
sum: .word 0

.text
main:
    li $t0, 0              # Index
    li $t1, 5              # Array length
    li $t2, 0              # Sum

loop:
    beq $t0, $t1, exit     # Exit if index == length
    lw $t3, array($t0)     # Load array[i] into $t3
    add $t2, $t2, $t3      # Add to sum
    addi $t0, $t0, 1       # Increment index
    j loop                 # Repeat loop

exit:
    sw $t2, sum            # Store result in sum
    li $v0, 10             # Exit syscall
    syscall
```

---

# MIPS Code Explanation: Stack Frame and Return Address Management

This document expands on the previous MIPS code explanation with a detailed breakdown of the stack frame setup, management, and restoration, as well as the handling of the return address.

## Stack Frame and Return Address Explanation

In MIPS assembly, the stack frame is used for managing function calls and preserving information such as the return address, temporary values, and arguments.

### Stack Setup and Usage in the `function` Label

```mips
function:
    subu    $sp, $sp, 0x18
    sw      $ra, 0x14($sp)
```

- **`subu $sp, $sp, 0x18`**: Sets up a stack frame by subtracting 24 bytes (0x18 in hexadecimal) from the stack pointer (`$sp`). This reserves space for storing values during the function's execution.
    - In MIPS, the stack grows downward (from higher memory to lower memory addresses).
    - A stack frame size of 24 bytes provides sufficient space for:
      - **16 bytes** for temporary data or local variables.
      - **4 bytes** to store the return address (`$ra`), saved at offset `0x14`.
      - **4 bytes** reserved for alignment.

- **`sw $ra, 0x14($sp)`**: Saves the return address (`$ra`) into the stack at the offset `0x14` from the stack pointer. This ensures that if the function itself calls another function, the original return address will not be lost.

The saved return address in the stack frame allows the program to return correctly even if the function calls another function or requires the `$ra` register for other purposes.

### Syscall Examples Within the Function

In this example, the function makes system calls, which may require temporary use of registers:

1. **First Write System Call**:
    ```mips
    addiu   $v0, $zero, 4000 + 4
    la      $a0, 1
    la      $a1, hello
    la      $a2, hello_len
    syscall
    ```
    - The values in `$a0`, `$a1`, and `$a2` are set to specify parameters for a write system call.
    - Using a stack frame allows these parameters to be loaded and used without overwriting critical registers.

2. **Read System Call**:
    ```mips
    addiu   $v0, $zero, 4000 + 3
    move    $a0, $zero
    move    $a1, $sp
    addiu   $a2, $zero, 0x80
    syscall
    ```
    - This call reads input from the user and stores it at the location pointed to by `$sp` (stack pointer), using the stack frame as temporary storage.

### Stack Frame Cleanup and Return

After the function completes its tasks, it must restore the stack pointer and return address:

```mips
    lw      $ra, 0x14($sp)
    addiu   $sp, $sp, 0x18
    jr      $ra
    nop
```

- **`lw $ra, 0x14($sp)`**: Loads the saved return address from the stack back into `$ra`. This restores the return address, allowing the function to return to the correct instruction in the caller function.
- **`addiu $sp, $sp, 0x18`**: Increments `$sp` by 24 bytes, effectively removing the stack frame and freeing the 24 bytes reserved for this function’s stack frame.
- **`jr $ra`**: Jumps to the return address stored in `$ra`, completing the function and returning to the caller.

### Importance of Stack Frame in Function Calls

Using the stack frame to manage the return address and temporary variables provides multiple benefits:
- **Preserves Register State**: Ensures critical values like the return address are not overwritten during function execution.
- **Allows Re-entrant Code**: The function can safely call other functions or use `$ra` without losing the return address.
- **Keeps Data Organized**: By reserving specific bytes for variables, alignment, and return addresses, the code remains structured and easier to debug.

### Data Section

```mips
.data

hello:          .asciz  "Hello World\nWhat is your name: "
hello_len =     . - hello
hello_start:    .asciz  "Hello "
hello_start_len = . - hello_start
```

- **`.data`**: Begins the data segment, where static data like strings are stored.
- **`hello` and `hello_start`**: Null-terminated strings that the program uses for printing.
- **`hello_len` and `hello_start_len`**: Calculates the lengths of each string for reference in system calls.


## 8. Best Practices in MIPS Assembly

1. **Use comments generously**: Describe what each line or block of code does.
2. **Minimize memory access**: Use registers as much as possible to avoid slow memory operations.
3. **Keep track of register usage**: Avoid overwriting important data in registers accidentally.
4. **Optimize branching**: Minimize the use of branching for efficiency, as branching can disrupt pipelining.

---

## 9. Additional Resources

- **SPIM and QtSPIM Documentation**: [SPIM](http://spimsimulator.sourceforge.net/)
- **MIPS Green Sheet**: A quick reference for MIPS instructions.
- **Books**: *Computer Organization and Design* by Patterson and Hennessy is a great resource for learning MIPS architecture.

---

### Thank you for reading this MIPS Assembly guide! Happy coding!
