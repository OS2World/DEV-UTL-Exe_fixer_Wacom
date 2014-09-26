#if !defined(__DEFINES_H__)
#define __DEFINES_H__

#define BANNER \
    "WatFix v0.01b - (c) Copyright 1998, Vesa J„„skel„inen\n\n" \
    "" \
    "syntax:\n" \
    "  watfix.exe <filename>\n\n" \
    "" \
    "example:\n" \
    "  watfix.exe bug.exe   searches and corrects incorrect api calls form exe\n"

#define MZ_ID  0x05a4d
#define LX_ID  0x0584c

/* module flags */
#define MODULE_FLAGS_INTERNAL_FIXUPS_APPLIED     0x010

/* fixup record SRC field */
#define FIXUP_SRC_SOURCE_MASK                    0x00F
#define FIXUP_SRC_BYTE_FIXUP                     0x000
#define FIXUP_SRC_16B_SEL_FIXUP                  0x002
#define FIXUP_SRC_16_16_POINTER_FIXUP            0x003
#define FIXUP_SRC_16B_OFFSET_FIXUP               0x005
#define FIXUP_SRC_16_32_POINTER_FIXUP            0x006
#define FIXUP_SRC_32B_OFFSET_FIXUP               0x007
#define FIXUP_SRC_32B_SELF_RELATILE_OFFSET_FIXUP 0x008
#define FIXUP_SRC_FIXUP_TO_ALIAS_FLAG            0x010
#define FIXUP_SRC_SOURCE_LIST_FLAG               0x020

/* fixup record FLAGS field */
#define FIXUP_FLAGS_FIXUP_TARGET_TYPE_MASK       0x003
#define FIXUP_FLAGS_INTERNAL_REFERENCE           0x000
#define FIXUP_FLAGS_IMPORTED_REFERENCE_BY_ORD    0x001
#define FIXUP_FLAGS_IMPORTED_REFERENCE_BY_NAME   0x002
#define FIXUP_FLAGS_INTERNAL_REFERENCE_VIA_ENTRY 0x003
#define FIXUP_FLAGS_ADDITIVE_FIXUP_FLAG          0x004
#define FIXUP_FLAGS_32B_TARGET_OFFSET_FLAG       0x010
#define FIXUP_FLAGS_32B_ADDITIVE_FIXUP_FLAG      0x020
#define FIXUP_FLAGS_16B_OBJ_FLAG                 0x040
#define FIXUP_FLAGS_8B_ORD_FLAG                  0x080

#endif // !__DEFINES_H__