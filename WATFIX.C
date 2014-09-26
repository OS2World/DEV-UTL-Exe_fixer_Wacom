#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "defines.h"

#define READ_BYTE_TO(f, x)  {fread(&tmpbyte, 1, 1, f); x=tmpbyte;}
#define READ_WORD_TO(f, x)  {fread(&tmpword, 2, 1, f); x=tmpword;}
#define READ_DWORD_TO(f, x) {fread(&tmpdword, 4, 1, f); x=tmpdword;}

#pragma pack(1);

/* starts at offset 0x00 */
typedef struct {
    USHORT ID;            // MZ (0x05a4d)
    USHORT file_length;   // modulo 512
    USHORT size_of_file;  // including header
    USHORT reloc_items;   // nro of relocataion table items
    USHORT header_size;   // header size (in paragra.)
    USHORT min_paragra;   // minium paragraphs needed (1 = 16bytes)
    USHORT max_paragra;   // maxium paragraphs desired (1 = 16bytes)
    USHORT stack_place;   // displacement of stack segment in module (in paragra.)
    USHORT SP_reg;        // contents of SP register at entry
    USHORT checksum;      // checksum
    USHORT IP_reg;        // contents of IP register at entry
    USHORT entry_code;    // displacement of entry code module (in paragra.)
    USHORT reloc_offs;    // offset of first relocation item in file (in bytes)
    USHORT ovelay_number; // ovelay number (0 for reident part of program)
} DOS2_EXE_HDR;

/* starts at offset 0x024 */
typedef struct {
    USHORT OEM_Identifier;
    UCHAR  OEM_Info[0x3C-0x26];
    ULONG  LX_header_offset;
} LX_EXE_INTRO_HDR;

/* starts at offset LX_EXE_INTRO_HDR.LX_header_offset */
typedef struct {
    USHORT ID;                               // +0x00: LX (0x0584c)
    UCHAR  byte_ordering;                    // +0x02: 0x00 = Little endian, 0x01 = Big endian
    UCHAR  word_ordering;                    // +0x03: 0x00 = Little endian, 0x01 = Big endian
    ULONG  format_level;                     // +0x04: 0x00 = normal
    USHORT cpu_type;                         // +0x08: 0x01 = 80286, 0x02 = 80386, 0x03 = 80486
    USHORT os_type;                          // +0x0A: 0x00 = unknown, 0x01 = OS/2
    ULONG  mod_version;                      // +0x0C: module version (user definable)
    ULONG  mod_flags;                        // +0x10: module flags
    ULONG  mod_pages;                        // +0x14: number of pages in module
    ULONG  EIP_obj_nro;                      // +0x18: Obj. number of EIP
    ULONG  EIP;                              // +0x1C: EIP (Starting address)
    ULONG  ESP_obj_nro;                      // +0x20: Obj. number of ESP
    ULONG  ESP;                              // +0x24: ESP (Stack address)
    ULONG  page_size;                        // +0x28: Page size in bytes
    ULONG  page_offs_shift;                  // +0x2C: Page offset shift to left (Align)
    ULONG  fixup_size;                       // +0x30: Fixup information size
    ULONG  fixup_checksum;                   // +0x34: Fixup information checksum
    ULONG  loader_size;                      // +0x38: Loader size
    ULONG  loader_checksum;                  // +0x3C: Loader checksum
    ULONG  obj_table_offset;                 // +0x40: Object table offset
    ULONG  obj_entries;                      // +0x44: Number of object table entries
    ULONG  obj_page_table_offs;              // +0x48: Object table page offset
    ULONG  obj_iter_pages_offs;              // +0x4C: Object iterated pages offset
    ULONG  res_table_offset;                 // +0x50: Resource table offset
    ULONG  res_entries;                      // +0x54: Number of resource entries
    ULONG  resident_name_table_offset;       // +0x58: Resident name table offset
    ULONG  entry_table_offset;               // +0x5C: Entry table offset
    ULONG  mod_directives_offset;            // +0x60: Module format directives table offset
    ULONG  mod_directives_entries;           // +0x64: Number of module directives
    ULONG  fixup_page_table_offset;          // +0x68: Fixup page table offset
    ULONG  fixup_record_table_offset;        // +0x6C: Fixup record table offset
    ULONG  import_module_table_offset;       // +0x70: Import module table offset
    ULONG  import_module_entries;            // +0x74: Import module entries
    ULONG  import_proc_table_offset;         // +0x78: Import procedure name table offset
    ULONG  per_page_checksum_table_offset;   // +0x7C: Per-Page checksum table offset
    ULONG  data_pages_offset;                // +0x80: Data pages offset
    ULONG  preload_pages;                    // +0x84: Number of pages to preload
    ULONG  non_resident_name_table_offset;   // +0x88: Non resident name table offset
    ULONG  non_resident_name_table_length;   // +0x8C: Non resident name table length
    ULONG  non_resident_name_table_checksum; // +0x90: Non resident name table checksum
    ULONG  auto_ds_object_number;            // +0x94: unused in 32 bit programs
    ULONG  debug_info_offset;                // +0x98: debug info offset
    ULONG  debug_info_length;                // +0x9C: debug info length
    ULONG  instance_pages_in_preload;        // +0xA0: Number of instance pages in preload section
    ULONG  instance_pages_in_demand;         // +0xA4: Number of instance pages in demand section
    ULONG  heap_size;                        // +0xA8: Heap size
} LX_EXE_HDR;

/****/

typedef struct {
    UCHAR src;
    UCHAR flags;
    UCHAR count;
    USHORT offset;
    USHORT entry;
    USHORT mod_ord;
    USHORT object;
    ULONG obj_offset;
    ULONG imp_ord;
    ULONG proc_name_offs;
    ULONG additive;
} FIXUP_HDR;

#pragma pack();

FIXUP_HDR fixup_hdr;
UCHAR  tmpbyte;
USHORT tmpword;
ULONG  tmpdword;

char   *dlls=NULL;

void clear_fixup_header()
{
    memset(&fixup_hdr, 0, sizeof(FIXUP_HDR));
}

void main(int argc, char *argv[])
{
    DOS2_EXE_HDR      dos2_hdr;
    LX_EXE_INTRO_HDR  lx_intro;
    BOOL              lx_intro_loaded=FALSE;
    LX_EXE_HDR        lx_hdr;
    BOOL              lx_hdr_loaded=FALSE;
    FIXUP_HDR         fixup_hdr;
    FILE             *f;
    int               i;
    ULONG             end_pos, cur_pos, entry_pos;
    BOOL              new_module_flags=FALSE;
    char             *fn;

    if (argc<2)
    {
        printf(BANNER);
        exit(0);
    }
    
    fn=(char *)argv[1];
    
    if ((f=fopen(fn, "r+wb"))==NULL)
    {
        printf("file not found! (%s)\n", fn);
        exit(1);
    }
    fread(&dos2_hdr, sizeof(DOS2_EXE_HDR), 1, f);
    if (dos2_hdr.ID!=MZ_ID)
    {
        printf("not executable file!\n");
        fclose(f);
        exit(1);
    }
    if ((dos2_hdr.header_size*16)==0x0040)
    {
        fseek(f, 0x024, SEEK_SET);
        fread(&lx_intro, sizeof(LX_EXE_INTRO_HDR), 1, f);
        lx_intro_loaded=TRUE;
        if (lx_intro.LX_header_offset!=0)
        {
            fseek(f, lx_intro.LX_header_offset, SEEK_SET);
            fread(&lx_hdr, sizeof(LX_EXE_HDR), 1, f);
            lx_hdr_loaded=TRUE;
        }
    }

    if ((lx_hdr_loaded==FALSE) || (lx_hdr.ID!=LX_ID))
    {
        printf("not valid LX executable!\n");
        fclose(f);
        exit(1);
    }

    dlls=(char *)malloc(lx_hdr.import_module_entries*128);
    if (dlls==NULL)
    {
        printf("not enough memory!\n");
        fclose(f);
        exit(1);
    }
    memset(dlls, 0, lx_hdr.import_module_entries*128);

    /* read import module names */
    fseek(f, lx_hdr.import_module_table_offset+lx_intro.LX_header_offset, SEEK_SET);
    for (i=0; i<lx_hdr.import_module_entries; i++)
    {
        READ_BYTE_TO(f, tmpbyte);
        if (tmpbyte!=0)
        {
            fread(&dlls[i*128], tmpbyte, 1, f);
        }
    }


    /****/
    fseek(f, lx_hdr.fixup_page_table_offset+lx_intro.LX_header_offset, SEEK_SET);
    for (i=0; i<lx_hdr.mod_pages; i++)
        READ_DWORD_TO(f, tmpdword);
    end_pos=tmpdword+lx_hdr.fixup_record_table_offset+lx_intro.LX_header_offset;
    /****/

    printf("searching invalid DLL calls from %s...\n", fn);
    fseek(f, lx_hdr.fixup_record_table_offset+lx_intro.LX_header_offset, SEEK_SET);
    
    while((entry_pos=ftell(f))<end_pos)
    {
        clear_fixup_header();

        // header
        READ_BYTE_TO(f, fixup_hdr.src);
        READ_BYTE_TO(f, fixup_hdr.flags);

        if (fixup_hdr.src & FIXUP_SRC_SOURCE_LIST_FLAG)
        {
            READ_BYTE_TO(f, fixup_hdr.count);
        } else
            READ_WORD_TO(f, fixup_hdr.offset);

        //target

        if ((fixup_hdr.flags&FIXUP_FLAGS_FIXUP_TARGET_TYPE_MASK)==FIXUP_FLAGS_INTERNAL_REFERENCE)
        {
            if (fixup_hdr.flags&FIXUP_FLAGS_16B_OBJ_FLAG)
            {
                READ_WORD_TO(f, fixup_hdr.object);
            } else
                READ_BYTE_TO(f, fixup_hdr.object);
            if ((fixup_hdr.src&FIXUP_SRC_SOURCE_MASK)!=FIXUP_SRC_16B_SEL_FIXUP)
            {
                if (fixup_hdr.flags&FIXUP_FLAGS_32B_TARGET_OFFSET_FLAG)
                {
                    READ_DWORD_TO(f, fixup_hdr.obj_offset);
                } else
                    READ_WORD_TO(f, fixup_hdr.obj_offset);

            }
        }

        if ((fixup_hdr.flags&FIXUP_FLAGS_FIXUP_TARGET_TYPE_MASK)==FIXUP_FLAGS_IMPORTED_REFERENCE_BY_ORD)
        {
            if (fixup_hdr.flags&FIXUP_FLAGS_16B_OBJ_FLAG)
            {
                READ_WORD_TO(f, fixup_hdr.mod_ord);
            } else
                READ_BYTE_TO(f, fixup_hdr.mod_ord);

            if (fixup_hdr.flags&FIXUP_FLAGS_8B_ORD_FLAG)
            {
                READ_BYTE_TO(f, fixup_hdr.imp_ord);
            } else
            {
                if (fixup_hdr.flags&FIXUP_FLAGS_32B_TARGET_OFFSET_FLAG)
                {
                    READ_DWORD_TO(f, fixup_hdr.imp_ord);
                } else
                    READ_WORD_TO(f, fixup_hdr.imp_ord);
            }
            if (((fixup_hdr.src&FIXUP_SRC_FIXUP_TO_ALIAS_FLAG)==0) && ((fixup_hdr.src&FIXUP_SRC_SOURCE_MASK)==FIXUP_SRC_16_16_POINTER_FIXUP))
            {
                cur_pos=ftell(f);
                new_module_flags=TRUE;
                lx_hdr.mod_flags|=MODULE_FLAGS_INTERNAL_FIXUPS_APPLIED;

                fixup_hdr.src|=FIXUP_SRC_FIXUP_TO_ALIAS_FLAG;
                fseek(f, entry_pos, SEEK_SET);
                fwrite(&fixup_hdr.src, 1, 1, f);
                fseek(f, cur_pos, SEEK_SET);

                printf("fixed problem with %s.%d\n",
                       &dlls[(fixup_hdr.mod_ord-1)*128],
                       fixup_hdr.imp_ord);
            }
//            printf("mod_ord: %04x  imp_ord: %08ld  ", fixup_hdr.mod_ord, fixup_hdr.imp_ord);
        }
        
        if ((fixup_hdr.flags&FIXUP_FLAGS_FIXUP_TARGET_TYPE_MASK)==FIXUP_FLAGS_IMPORTED_REFERENCE_BY_NAME)
        {
            if (fixup_hdr.flags&FIXUP_FLAGS_16B_OBJ_FLAG)
            {
                READ_WORD_TO(f, fixup_hdr.mod_ord);
            } else
                READ_BYTE_TO(f, fixup_hdr.mod_ord);

            if (fixup_hdr.flags&FIXUP_FLAGS_32B_TARGET_OFFSET_FLAG)
            {
                READ_DWORD_TO(f, fixup_hdr.proc_name_offs);
            } else
                READ_WORD_TO(f, fixup_hdr.proc_name_offs);

        }

        if ((fixup_hdr.flags&FIXUP_FLAGS_FIXUP_TARGET_TYPE_MASK)==FIXUP_FLAGS_INTERNAL_REFERENCE_VIA_ENTRY)
        {
            if (fixup_hdr.flags&FIXUP_FLAGS_16B_OBJ_FLAG)
            {
                READ_WORD_TO(f, fixup_hdr.mod_ord);
            } else
                READ_BYTE_TO(f, fixup_hdr.mod_ord);

        }


        //additive
        if (fixup_hdr.flags&FIXUP_FLAGS_ADDITIVE_FIXUP_FLAG)
        {
            if (fixup_hdr.flags&FIXUP_FLAGS_32B_ADDITIVE_FIXUP_FLAG)
            {
                READ_DWORD_TO(f, fixup_hdr.additive);
            } else
                READ_WORD_TO(f, fixup_hdr.additive);
        }

        //srcoffs (not yet implemented)
    }

    if (new_module_flags)
    {
        fseek(f, lx_intro.LX_header_offset+0x10, SEEK_SET);
        fwrite(&lx_hdr.mod_flags, 4, 1, f);
        new_module_flags=FALSE;
    } else
    {
        printf("none found!\n");
    }
    
    fclose(f);
    if (dlls!=NULL) free(dlls);
}
