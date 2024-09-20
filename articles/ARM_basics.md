
# ARM Stack, Registers, and Function Calls in Assembly

## Table of Contents
1. [Introduction to ARM Architecture](#introduction-to-arm-architecture)
2. [ARM Registers](#arm-registers)
   - [General Purpose Registers](#general-purpose-registers)
   - [Special Purpose Registers](#special-purpose-registers)
3. [The ARM Stack](#the-arm-stack)
   - [The Role of the Stack in ARM](#the-role-of-the-stack-in-arm)
   - [Stack Pointer (SP) Usage](#stack-pointer-sp-usage)
   - [PUSH and POP Instructions](#push-and-pop-instructions)
   - [Example: Stack Operations in Assembly](#example-stack-operations-in-assembly)
4. [ARM Function Calling Conventions](#arm-function-calling-conventions)
   - [The ARM Procedure Call Standard (APCS)](#the-arm-procedure-call-standard-apcs)
   - [Function Call Flow](#function-call-flow)
   - [Prologue and Epilogue](#prologue-and-epilogue)
5. [Example: ARM Function Call Assembly](#example-arm-function-call-assembly)
   - [Calling a Function with More Arguments](#calling-a-function-with-more-arguments)
6. [Conclusion](#conclusion)

---

## Introduction to ARM Architecture

ARM (Advanced RISC Machine) is a reduced instruction set computing (RISC) architecture widely used in embedded systems and mobile devices due to its simplicity and energy efficiency. ARM assembly allows programmers to control the processor's behavior directly using registers and memory.

ARM processors use registers, memory, and a stack to manage function calls and data storage, making it crucial to understand how these elements interact.

---

## ARM Registers

ARM processors have 16 general-purpose registers, labeled `r0` through `r15`. These registers serve different purposes during program execution.

### General Purpose Registers

| **Register** | **Purpose** |
|--------------|-------------|
| `r0 - r3`    | Function arguments and return values. |
| `r4 - r11`   | Callee-saved registers (used for storing local variables, must be preserved by callee). |
| `r12`        | Intra-Procedure Call Scratch Register (IP), used as a temporary workspace. |
| `r13`        | Stack Pointer (SP), points to the top of the stack. |
| `r14`        | Link Register (LR), stores the return address during a function call. |
| `r15`        | Program Counter (PC), holds the address of the next instruction. |

### Special Purpose Registers
- **Program Status Register (PSR):** Stores condition flags (zero, carry, negative, etc.) and control bits.
- **Link Register (LR):** Stores the return address during subroutine calls.
- **Stack Pointer (SP):** Points to the current top of the stack.
- **Program Counter (PC):** Contains the address of the instruction currently being executed.

---

## The ARM Stack

The stack is a section of memory that grows downward (from higher to lower addresses). It is used for storing data that doesn't fit in registers, such as local variables, function parameters, return addresses, and saved register values.

The **Stack Pointer (SP)** (`r13`) keeps track of the top of the stack. In ARM, stack operations are done explicitly using instructions like `PUSH`, `POP`, `STMFD` (Store Multiple Full Descending), and `LDMFD` (Load Multiple Full Descending).

### The Role of the Stack in ARM
The stack is primarily used for:
- Storing local variables when registers are insufficient.
- Passing arguments when more than four are required.
- Saving return addresses and registers during function calls.

### Stack Pointer (SP) Usage
The `SP` is updated by the following operations:
- **Pushing to the stack:** Decreases the `SP` and stores values at the new address.
- **Popping from the stack:** Increases the `SP` and loads values from memory.

### PUSH and POP Instructions
The **PUSH** and **POP** instructions are shorthand for **STMFD** and **LDMFD**, which store and load multiple registers in **Full Descending** mode.

```assembly
PUSH {r0, r1}    ; Store r0 and r1 on the stack
POP {r0, r1}     ; Retrieve r0 and r1 from the stack
```

### Example: Stack Operations in Assembly

Let's look at an example where we use the stack to save and restore registers.

```assembly
PUSH {r4, lr}         ; Save r4 and the link register (LR) onto the stack
MOV  r4, #10          ; Set r4 to 10
; ... perform some operations ...
POP {r4, lr}          ; Restore r4 and LR from the stack
BX   lr               ; Return from the function (branch to the return address in LR)
```

In this example:
- We push `r4` and `LR` onto the stack before modifying `r4`.
- After the operations, we restore `r4` and `LR` and return using the `BX lr` instruction.

---

## ARM Function Calling Conventions

The ARM architecture follows the **ARM Procedure Call Standard (APCS)** or the more modern **ARM EABI (Embedded Application Binary Interface)**. These standards define how functions pass arguments, return values, and manage the stack.

### The ARM Procedure Call Standard (APCS)

Key aspects of the ARM calling convention:
1. **Argument Passing:**
   - The first four arguments are passed in registers `r0` to `r3`.
   - Additional arguments are pushed onto the stack.

2. **Return Values:**
   - The return value is placed in `r0`.

3. **Callee-Saved Registers:**
   - Registers `r4` to `r11` must be preserved by the callee (the function being called).

4. **Link Register (LR):**
   - The return address is stored in the `LR` register (`r14`).

### Function Call Flow

The general flow of a function call in ARM is as follows:

1. **Pass Arguments:**
   - The caller places the first four arguments in `r0` to `r3`. Any additional arguments are pushed onto the stack.
   
2. **Call the Function:**
   - The caller uses the `BL` (Branch with Link) instruction to call the function, which saves the return address in `LR`.

3. **Function Prologue:**
   - The callee (function) typically saves the `LR` and any registers it will use (callee-saved registers) onto the stack.

4. **Function Body:**
   - The callee executes its operations, using `r0` for the return value.

5. **Function Epilogue:**
   - The callee restores the saved registers and returns by branching to the address in `LR`.

### Prologue and Epilogue
- **Prologue:** The part of the function where the callee saves registers and sets up the stack.
- **Epilogue:** The part of the function where the callee restores saved registers and returns.

---

## Example: ARM Function Call Assembly

Here's an example of a function in ARM assembly that adds two numbers.

### Example Function: `add_numbers`

```assembly
    .global add_numbers

add_numbers:
    PUSH {r4, lr}         ; Save r4 and the return address (LR)
    
    ADD  r0, r0, r1       ; r0 = r0 + r1 (the sum is stored in r0)
    
    POP  {r4, lr}         ; Restore r4 and LR
    BX   lr               ; Return to the caller (branch to address in LR)
```

### Example Caller

```assembly
    LDR  r0, =5           ; Load 5 into r0 (first argument)
    LDR  r1, =10          ; Load 10 into r1 (second argument)

    BL   add_numbers      ; Call add_numbers, the result will be in r0
```

### Calling a Function with More Arguments

If a function requires more than four arguments, the additional arguments are passed on the stack.

```assembly
    LDR  r0, =1           ; First argument in r0
    LDR  r1, =2           ; Second argument in r1
    LDR  r2, =3           ; Third argument in r2
    LDR  r3, =4           ; Fourth argument in r3

    LDR  r4, =5           ; Fifth argument
    PUSH {r4}             ; Push fifth argument onto the stack

    BL   some_function    ; Call the function

    ADD  sp, sp, #4       ; Adjust the stack (pop the fifth argument)
```

In this case, the first four arguments are passed in `r0` to `r3`, and the fifth argument is pushed onto the stack.

---

## Conclusion

ARM assembly programming requires a deep understanding of the stack, registers, and function calling conventions. By managing the stack and registers effectively, you can write optimized low-level code. The use of the stack for function calls, the role of registers for arguments and return values, and following the calling convention ensures that function calls and returns are handled correctly.
