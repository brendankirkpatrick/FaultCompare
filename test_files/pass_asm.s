	.arch armv5te
	.fpu softvfp
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 2
	.eabi_attribute 30, 6
	.eabi_attribute 34, 0
	.eabi_attribute 18, 4
	.file	"password_check.c"
	.text
	.section	.rodata
	.align	2
.LC0:
	.ascii	"Enter the password (max %d characters): \000"
	.align	2
.LC1:
	.ascii	"\012\000"
	.align	2
.LC2:
	.ascii	"pass\000"
	.align	2
.LC3:
	.ascii	"no input\000"
	.align	2
.LC4:
	.ascii	"Correct\000"
	.align	2
.LC5:
	.ascii	"Wrong\000"
	.text
	.align	2
	.global	main
	.syntax unified
	.arm
	.type	main, %function
main:
	@ args = 0, pretend = 0, frame = 16
	@ frame_needed = 1, uses_anonymous_args = 0
	push	{r4, fp, lr}
	add	fp, sp, #8
	sub	sp, sp, #20
	ldr	r4, .L8
.LPIC1:
	add	r4, pc, r4
	mov	r1, #10
	ldr	r3, .L8+4
.LPIC0:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
	mov	r3, #0
	strb	r3, [fp, #-13]
	ldr	r3, .L8+8
	ldr	r3, [r4, r3]
	ldr	r2, [r3]
	sub	r3, fp, #24
	mov	r1, #11
	mov	r0, r3
	bl	fgets(PLT)
	mov	r3, r0
	cmp	r3, #0
	beq	.L2
	sub	r3, fp, #24
	mov	r1, #10
	mov	r0, r3
	bl	strchr(PLT)
	mov	r3, r0
	cmp	r3, #0
	bne	.L3
	mov	r3, #0
	strb	r3, [fp, #-13]
	b	.L4
.L3:
	sub	r3, fp, #24
	ldr	r2, .L8+12
.LPIC2:
	add	r2, pc, r2
	mov	r1, r2
	mov	r0, r3
	bl	strcspn(PLT)
	mov	r3, r0
	sub	r3, r3, #12
	add	r3, r3, fp
	mov	r2, #0
	strb	r2, [r3, #-12]
	sub	r3, fp, #24
	ldr	r2, .L8+16
.LPIC3:
	add	r2, pc, r2
	mov	r1, r2
	mov	r0, r3
	bl	strcmp(PLT)
	mov	r3, r0
	cmp	r3, #0
	bne	.L4
	mov	r3, #1
	strb	r3, [fp, #-13]
	b	.L4
.L2:
	ldr	r3, .L8+20
.LPIC4:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
.L4:
	ldrb	r3, [fp, #-13]	@ zero_extendqisi2
	cmp	r3, #0
	beq	.L5
	ldr	r3, .L8+24
.LPIC5:
	add	r3, pc, r3
	mov	r0, r3
	bl	puts(PLT)
	mov	r3, #0
	b	.L7
.L5:
	ldr	r3, .L8+28
.LPIC6:
	add	r3, pc, r3
	mov	r0, r3
	bl	puts(PLT)
	mov	r3, #97
.L7:
	mov	r0, r3
	sub	sp, fp, #8
	@ sp needed
	pop	{r4, fp, pc}
.L9:
	.align	2
.L8:
	.word	_GLOBAL_OFFSET_TABLE_-(.LPIC1+8)
	.word	.LC0-(.LPIC0+8)
	.word	stdin(GOT)
	.word	.LC1-(.LPIC2+8)
	.word	.LC2-(.LPIC3+8)
	.word	.LC3-(.LPIC4+8)
	.word	.LC4-(.LPIC5+8)
	.word	.LC5-(.LPIC6+8)
	.size	main, .-main
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",%progbits
