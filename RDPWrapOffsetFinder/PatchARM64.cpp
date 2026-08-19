#include <stdio.h>
#include "aarch64_ic.h"

size_t funcAddrARM64(size_t RVA, size_t base) {
    auto ic = *((uint32_t*)(RVA + base));
    if (!is_arm64_adrp(ic)) return 0;
#ifndef _WIN64
    size_t addr = (ic & 0xFFFFE0) << 9 | (ic & 0x60000000) >> 17;
#else
    size_t addr = ((int64_t)(ic & 0xFFFFE0)) << 40 >> 31 | (ic & 0x60000000) >> 17;
#endif
    auto rd = get_rt_rd(ic);
    ic = *((uint32_t*)(RVA + base + 4));
    if (!is_arm64_ldr64_unsigned(ic) || rd != get_rn(ic)) return 0;
    addr += get_imm12(ic) >> 7;
    return addr + (RVA & ~(size_t)0xFFF);
}

void LocalOnlyPatchARM64(size_t RVA, size_t base, size_t target) {
    size_t length = 256;
    auto IP = RVA + base;
    target += base;

    while (length >= 12) {
        auto ic = *((uint32_t*)IP);
        if (is_arm64_bl(ic) && IP + get_imm26(ic) == target) {
            do {
                IP += 4;
                length -= 4;
                ic = *((uint32_t*)IP);
            } while (length >= 8 && !is_arm64_tbnz(ic));
            target = IP + get_imm14(ic);
            do {
                IP += 4;
                length -= 4;
                ic = *((uint32_t*)IP);
                if (is_arm64_cbz(ic) && IP + get_imm19(ic) == target) {
                    printf("LocalOnlyPatch.arm64=1\n"
                        "LocalOnlyOffset.arm64=%IX\n"
                        "LocalOnlyCode.arm64=B_%d\n", IP - base, get_imm19(ic));
                    return;
                }
            } while (length >= 4);
            break;
        }
        IP += 4;
        length -= 4;
    }
    puts("ERROR: LocalOnlyPatch pattern not found");
}

void DefPolicyPatchARM64(size_t RVA, size_t base) {
    size_t length = 128;
    auto IP = RVA + base;
    uint32_t reg1, reg2, rt;

    while (length >= 4) {
        auto ic = *((uint32_t*)IP);
        if (is_arm64_add64(ic) && get_shift(ic) == 0 && get_imm12(ic) >> 10 == 0x638) {
            reg2 = get_rn(ic);
            rt = get_rt_rd(ic);
            ic = *((uint32_t*)(IP + 4));
            if (!(is_arm64_ldp32(ic) || is_arm64_ldp32_signed(ic)) || get_imm7(ic) || rt != get_rn(ic)) goto out;
            reg1 = get_rt_rd(ic);
            rt = get_rt2(ic);
        }
        else if (is_arm64_ldr32_unsigned(ic) && get_imm12(ic) >> 8 == 0x638) {
            reg1 = get_rt_rd(ic);
            reg2 = get_rn(ic);
            ic = *((uint32_t*)(IP + 4));
            if (!is_arm64_ldr32_unsigned(ic) || get_imm12(ic) >> 8 != 0x63c || reg2 != get_rn(ic)) goto out;
            rt = get_rt_rd(ic);
        }
        else goto out;
        ic = *((uint32_t*)(IP + 8));
        if (!is_arm64_cmp32(ic) || get_imm6(ic) || (rt != get_rn(ic) || reg1 != get_rm(ic)) && (reg1 != get_rn(ic) || rt != get_rm(ic))) goto out;
        ic = *((uint32_t*)(IP + 12));
        if (is_arm64_b_cond(ic)) {
            const char* jmp = "";
            if ((ic & 0xf) == 1)
                const char* jmp = "_b";
            else if (ic & 0xf)
                break;
            printf("DefPolicyPatch.arm64=1\n"
                "DefPolicyOffset.arm64=%IX\n"
                "DefPolicyCode.arm64=CDefPolicy_Query_w%u_x%u%s\n", IP - base, reg1, reg2, jmp);
            return;
        }
    out:
        IP += 4;
        length -= 4;
    }
    puts("ERROR: DefPolicyPatch pattern not found");
}

int SingleUserPatchARM64(size_t RVA, size_t base, size_t target, size_t target2) {
    size_t length = 256;
    auto IP = RVA + base;

    while (length >= 4) {
        auto ic = *((uint32_t*)IP);
#ifdef MEMSET_DIRECT
        if (is_arm64_bl(ic) && IP + get_imm26(ic) - base == target) {
#else
        //if (is_arm64_bl(ic)) printf("%x\n", IP + get_imm26(ic) - base);
        if (is_arm64_bl(ic) && funcAddrARM64(IP + get_imm26(ic) - base, base) == target) {
#endif
            IP += 4;
            length = 128;
            while (length >= 4) {
                ic = *((uint32_t*)IP);
                if (is_arm64_bl(ic) && funcAddrARM64(IP + get_imm26(ic) - base, base) == target2) {
                    printf("SingleUserPatch.arm64=1\n"
                        "SingleUserOffset.arm64=%IX\n"
                        "SingleUserCode.arm64=MovX0_1\n", IP - base);
                    return 1;
                }
                else if (is_arm64_adrp(ic)) {
#ifndef _WIN64
                    size_t addr = (ic & 0xFFFFE0) << 9 | (ic & 0x60000000) >> 17;
#else
                    size_t addr = ((int64_t)(ic & 0xFFFFE0)) << 40 >> 31 | (ic & 0x60000000) >> 17;
#endif
                    uint32_t rd = get_rt_rd(ic);
                    addr += (IP - base) & ~(size_t)0xFFF;
                    IP += 4;
                    ic = *((uint32_t*)IP);
                    if (!is_arm64_add64(ic) || get_shift(ic) || rd != get_rn(ic)) continue;
                    rd = get_rt_rd(ic);
                    if (addr + (get_imm12(ic) >> 10) == target2) {
                        do {
                            IP += 4;
                            length -= 4;
                            ic = *((uint32_t*)IP);
                        } while (length >= 4 && !is_arm64_ldar64(ic) && rd != get_rn(ic));
                        while (length >= 4) {
                            IP += 4;
                            length -= 4;
                            ic = *((uint32_t*)IP);
                            if (is_arm64_blr(ic) && rd != get_rn(ic)) {
                                printf("SingleUserPatch.arm64=1\n"
                                    "SingleUserOffset.arm64=%IX\n"
                                    "SingleUserCode.arm64=MovX0_1\n", IP - base);
                                return 1;
                            }
                        }
                        return 0;
                    }
                }
                IP += 4;
                length -= 4;
            }
            break;
        }
        IP += 4;
        length -= 4;
    }
    return 0;
}
