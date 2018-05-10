#include "stdio.h"
#include "stdlib.h"


#define Elf32_Half short
#define Elf32_Word int
#define Elf32_Addr int
#define Elf32_Off int
#define EI_NIDENT 16

typedef struct {
	unsigned char e_ident[EI_NIDENT];
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_version;
	Elf32_Addr e_entry;	//24
	Elf32_Off e_phoff;	//28
	Elf32_Off e_shoff;	//32
	Elf32_Word e_flags;	//36
	Elf32_Half e_ehsize;//40
	Elf32_Half e_phentsize;	//42
	Elf32_Half e_phnum;	//44
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct {
	Elf32_Word p_type;
	Elf32_Off p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
} Elf32_Phdr;

typedef struct {
	Elf32_Word sh_name;
	Elf32_Word sh_type;
	Elf32_Word sh_flags;
	Elf32_Addr sh_addr;
	Elf32_Off sh_offset;
	Elf32_Word sh_size;
	Elf32_Word sh_link;
	Elf32_Word sh_info;
	Elf32_Word sh_addralign;
	Elf32_Word sh_entsize;
} Elf32_Shdr;

char * string_table;

void handle_ehdr(Elf32_Ehdr ehdr);
void handle_phdr(Elf32_Phdr phdr);
void handle_shdr(Elf32_Shdr shdr);
int main()
{
	Elf32_Ehdr ehdr;
	Elf32_Phdr phdr;
	Elf32_Shdr shdr;
	char filename[25]={0};
	FILE *file;
	int i;
	scanf("%20s",filename);
	file=fopen(filename,"r");
	fread((void *)&ehdr,1,sizeof(ehdr),file);
	handle_ehdr(ehdr);
	fseek(file,ehdr.e_shoff+ehdr.e_shstrndx*sizeof(shdr),0);
	fread((void *)&shdr,1,sizeof(shdr),file);
	printf("string table off:\t0x%lx\n",shdr.sh_offset);
	printf("string table size:\t0x%lx\n",shdr.sh_size);
	string_table=(char *)malloc(shdr.sh_size);
	fseek(file,shdr.sh_offset,0);
	fread((void *)string_table,1,shdr.sh_size,file);
	fseek(file,ehdr.e_phoff,0);
	printf("\nprogram header info :\n");
	printf("offset\t\t\tvaddr\t\t\tlength\t\t\tflags\n");
	for(i=0;i<ehdr.e_phnum;i++)
	{
		fread((void *)&phdr,1,sizeof(phdr),file);
		handle_phdr(phdr);
	}
	fseek(file,ehdr.e_shoff,0);
	printf("\nsection header info :\n");
	printf("name\t\t\ttype\t\t\toffset\t\t\tlength\n");
	for(i=0;i<ehdr.e_shnum;i++)
	{
		fread((void *)&shdr,1,sizeof(shdr),file);
		handle_shdr(shdr);
	}
	return 0;
}

void handle_ehdr(Elf32_Ehdr ehdr)
{
	if(ehdr.e_ident[1]!='E'||ehdr.e_ident[2]!='L'||ehdr.e_ident[3]!='F')
		exit(0);
	printf("ELF\n");
	printf("%dbit\t",ehdr.e_ident[4]*32);
	ehdr.e_ident[5]==1 ? printf("LSB\n"):printf("MSB\n");
	switch(ehdr.e_type)
	{
		case 0:
			printf("It's not valid\n");
			exit(0);
		case 1:
			printf("Relocatable file\n");
			break;
		case 2:
			printf("Executable file\n");
			break;
		case 3:
			printf("Shared object file\n");
			break;
		case 4:
			printf("Core file\n");
			break;
	}
	printf("program entry:\t0x%lx\n",ehdr.e_entry);
	printf("ELF header size:\t%d\n",ehdr.e_ehsize);
	printf("program header off:\t0x%lx\n",ehdr.e_phoff);
	printf("section header off:\t0x%lx\n",ehdr.e_shoff);
	printf("program header entry size:\t%d\n",ehdr.e_phentsize);
	printf("program header entry number:\t%d\n",ehdr.e_phnum);
	printf("section header entry size:\t%d\n",ehdr.e_shentsize);
	printf("section header entry number:\t%d\n",ehdr.e_shnum);
	printf("string table off section header:\t%d\n",ehdr.e_shstrndx);
}

void handle_phdr(Elf32_Phdr phdr)
{
	printf("0x%-10lx\t\t0x%-10lx\t\t0x%-10lx\t\t",phdr.p_offset,phdr.p_vaddr,phdr.p_filesz);
	if(phdr.p_flags&4)
		printf("R");	
	if(phdr.p_flags&2)
		printf("W");
	if(phdr.p_flags&1)
		printf("X");
	printf("\n");	
}

void handle_shdr(Elf32_Shdr shdr)
{
	printf("%-20s\t",string_table+shdr.sh_name);
	switch(shdr.sh_type)
	{
		case 1:
			printf("progbits\t\t");
			break;
		case 2:
		case 11:
			printf("symbol table\t\t");
			break;
		case 3:
			printf("string table\t\t");
			break;
		case 4:
		case 9:
			printf("relocation\t\t");
			break;
		case 5:
			printf("hash symbol table\t\t");
			break;
		case 6:
			printf("dynamic link\t\t");
			break;
		default:
			printf("unkown %-10d\t",shdr.sh_type);
	}
	printf("0x%-10lx\t\t",shdr.sh_offset);
	printf("0x%-10lx\n",shdr.sh_size);
}

