ENTRY(_start)
SECTIONS
{
	. = 0x40000;
	.text : {
		*(.text)
	}
	.rodata : {
		*(.rodata)
		*(.rodata.*)
	}
	.data : {
		 *(.data)
	}
	.bss : {
		*(.bss)
		*(COMMON)
	}
}
