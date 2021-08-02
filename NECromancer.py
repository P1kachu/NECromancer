from ida_lines import COLOR_INSN, COLOR_MACRO
from ida_idp import CUSTOM_INSN_ITYPE, IDP_Hooks, ph_get_regnames, ph_get_id, PLFM_NEC_V850X
from ida_bytes import get_bytes
from ida_idaapi import plugin_t, PLUGIN_PROC, PLUGIN_HIDE, PLUGIN_SKIP, PLUGIN_KEEP
from ida_ua import o_displ, o_reg, o_imm, dt_dword, OOF_ADDR, o_near
from struct import unpack

###############################################################################
#
#
#   _____ _____ _____
#  |   | |   __|     |___ ___ _____ ___ ___ ___ ___ ___
#  | | | |   __|   --|  _| . |     | .'|   |  _| -_|  _|
#  |_|___|_____|_____|_| |___|_|_|_|__,|_|_|___|___|_|
# ____________________________________________________________________________
#
# NECromancer - a NEC V850X instruction extender plugin for IDA Pro
# -----------------------------------------------------------------
#
# This plugin extends the V850E1 IDA processor module by adding support
# for certain V850E2 instructions on a per need basis. Rather than modifying
# the source code of the V850E1 IDA processor module, this script has been
# developed as an exercise in writing a processor module extension in
# IDAPython, particularly for version 7 of IDA and onwards.
#
###############################################################################

# ----------------------------------------------------------------------------
#
# necromancer: noun | nec*ro*man*cer | a supposed practice of magic involving
# communication with the diseased
#
# history and changelog:
# ----------------------
# 2017.01.31 - initial version
#              support for "divq", "divqu", shl (reg1, reg2, reg3),
#              shr (reg1, reg2, reg3) and "sar" instructions
# 2017.02.01 - support for LD.HU (disp23[reg1], reg3), "feret" and "eiret"
#              instructions
# 2017.02.02 - support for ST.H (reg3, disp23[reg1]) instruction,
#              bugfixes, cleanup
# 2017.02.03 - support for sign extending 23bit displacement values,
#              "sch1l", "sch1r", "caxi" and "fetrap" instructions
# 2017.08.20 - IDA 7 compatibility
# 2017.09.03 - Full IDA 7 compatibility (not requiring compatibility layer)
# 2017.12.03 - Bugfixes (with thanks to https://github.com/Quorth)
# 2018.05.08 - Fixed decoding of fetrap instruction
# 2021.01.19 - [P1kachu] Started adding more instructions to it (amateur)
#
#
# based on V850E2S User's Manual: Architecture, available at:
# https://www.renesas.com/en-eu/doc/products/mpumcu/doc/v850/r01us0037ej0100_v850e2.pdf
#
# ------------------------------------------------------------------------------

__author__ = "Dennis Elser"

DEBUG_PLUGIN = True
DEBUG_P1KACHU = False

NEWINSN_COLOR = COLOR_MACRO if DEBUG_PLUGIN else COLOR_INSN

# from V850 processor module
N850F_USEBRACKETS = 0x01
N850F_OUTSIGNED = 0x02


class NewInstructions:
    (NN_divq,
    NN_divqu,
    NN_sar,
    NN_shl,
    NN_shr,
    NN_feret,
    NN_eiret,
    NN_ld_hu,
    NN_st_h,
    NN_sch1l,
    NN_sch1r,
    NN_caxi,
    NN_fetrap,
    NN_hardcoded_ins_addf_s,
    NN_hardcoded_ins_adf,
    NN_hardcoded_ins_bins,
    NN_hardcoded_ins_cmovf_s,
    NN_hardcoded_ins_cmpf_d,
    NN_hardcoded_ins_cmpf_s,
    NN_hardcoded_ins_cvtf_dw,
    NN_hardcoded_ins_cvtf_wd,
    NN_hardcoded_ins_cvtf_ws,
    NN_hardcoded_ins_di,
    NN_hardcoded_ins_divf_d,
    NN_hardcoded_ins_divf_s,
    NN_hardcoded_ins_dmac_operation,
    NN_hardcoded_ins_ei,
    NN_hardcoded_ins_jarl,
    NN_hardcoded_ins_jarl_lp,
    NN_hardcoded_ins_jr,
    NN_hardcoded_ins_ldsr,
    NN_hardcoded_ins_mac,
    NN_hardcoded_ins_macu,
    NN_hardcoded_ins_mulf_d,
    NN_hardcoded_ins_mulf_s,
    NN_hardcoded_ins_negf_d,
    NN_hardcoded_ins_popsp,
    NN_hardcoded_ins_pushsp,
    NN_hardcoded_ins_sbf,
    NN_hardcoded_ins_stsr,
    NN_hardcoded_ins_subf_d,
    NN_hardcoded_ins_trfsr,
    ) = range(CUSTOM_INSN_ITYPE, CUSTOM_INSN_ITYPE+42)

    lst = {NN_divq:"divq",
           NN_divqu:"divqu",
           NN_sar:"sar",
           NN_shl:"shl",
           NN_shr:"shr",
           NN_feret:"feret",
           NN_eiret:"eiret",
           NN_ld_hu:"ld.hu",
           NN_st_h:"st.h",
           NN_sch1l:"sch1l",
           NN_sch1r:"sch1r",
           NN_caxi:"caxi",
           NN_fetrap:"fetrap",
           NN_hardcoded_ins_addf_s: "hardcoded_ins_addf_s",
           NN_hardcoded_ins_adf: "hardcoded_ins_adf",
           NN_hardcoded_ins_bins: "hardcoded_ins_bins",
           NN_hardcoded_ins_cmovf_s: "hardcoded_ins_cmovf_s",
           NN_hardcoded_ins_cmpf_d: "hardcoded_ins_cmpf_d",
           NN_hardcoded_ins_cmpf_s: "hardcoded_ins_cmpf_s",
           NN_hardcoded_ins_cvtf_dw: "hardcoded_ins_cvtf_dw",
           NN_hardcoded_ins_cvtf_wd: "hardcoded_ins_cvtf_wd",
           NN_hardcoded_ins_cvtf_ws: "hardcoded_ins_cvtf_ws",
           NN_hardcoded_ins_di: "hardcoded_ins_di",
           NN_hardcoded_ins_divf_d: "hardcoded_ins_divf_d",
           NN_hardcoded_ins_divf_s: "hardcoded_ins_divf_s",
           NN_hardcoded_ins_dmac_operation: "hardcoded_ins_dmac_operation",
           NN_hardcoded_ins_ei: "hardcoded_ins_ei",
           NN_hardcoded_ins_jarl: "hardcoded_ins_jarl",
           NN_hardcoded_ins_jarl_lp: "hardcoded_ins_jarl_lp",
           NN_hardcoded_ins_jr:"jr",
           NN_hardcoded_ins_ldsr: "hardcoded_ins_ldsr",
           NN_hardcoded_ins_mac: "hardcoded_ins_mac",
           NN_hardcoded_ins_macu: "hardcoded_ins_macu",
           NN_hardcoded_ins_mulf_d: "hardcoded_ins_mulf_d",
           NN_hardcoded_ins_mulf_s: "hardcoded_ins_mulf_s",
           NN_hardcoded_ins_negf_d: "hardcoded_ins_negf_d",
           NN_hardcoded_ins_popsp: "hardcoded_ins_popsp",
           NN_hardcoded_ins_pushsp: "hardcoded_ins_pushsp",
           NN_hardcoded_ins_stsr: "hardcoded_ins_stsr",
           NN_hardcoded_ins_subf_d: "hardcoded_ins_subf_d",
           NN_hardcoded_ins_trfsr: "hardcoded_ins_trfsr",
           }


#--------------------------------------------------------------------------
class v850_idp_hook_t(IDP_Hooks):
    def __init__(self):
        IDP_Hooks.__init__(self)

    def parse_r1(self, w):
        return w & 0x1F

    def parse_r2(self, w):
        return (w & 0xF800) >> 11

    def parse_r3(self, w):
        return self.parse_r2(w)

    def sign_extend(self, disp, nbits):
        val = disp
        if val & (1 << (nbits-1)):
            val |= ~((1 << nbits)-1)
        return val

    def decode_instruction(self, insn):
        buf = get_bytes(insn.ea, 2)
        hw1 = unpack("<H", buf)[0]
        buf = get_bytes(insn.ea+2, 2)
        hw2 = unpack("<H", buf)[0]

        if hw1 == hw2 == 0xffff:
            # Until now FF FF FF FF would be recognized as JARL so fix that
            # specific case
            return False

        op = (hw1 & 0x7E0) >> 5 # take bit5->bit10

        address = hex(insn.ea).replace("L", "")
        if DEBUG_P1KACHU:
            print("{0}: OP={1} - hw1={2} - hw2={3}".format(address, hex(op), hex(hw1), hex(hw2)))

        # Format I
        if op == 2 and (hw1 >> 11) == 0 and (hw1 & 0x1F) != 0:
            # TODO add vector4 parsing
            insn.itype = NewInstructions.NN_fetrap
            insn.size = 2
            return True

        # Format XIV
        elif op == 0x3D and ((hw1 & 0xFFE0) >> 5) == 0x3D:
            buf = get_bytes(insn.ea+2, 2)
            hw2 = unpack("<H", buf)[0]
            subop = hw2 & 0x1F

            if subop == 0x07: # ld.hu
                insn.itype = NewInstructions.NN_ld_hu

                insn.Op1.type = o_displ
                insn.Op2.type = o_reg


                insn.Op1.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED
                insn.Op1.reg = self.parse_r1(hw1)

                buf = get_bytes(insn.ea+4, 2)
                hw3 = unpack("<H", buf)[0]

                insn.Op1.addr = self.sign_extend(((hw3 << 6) | ((hw2 & 0x7E0) >> 5)) << 1, 23)
                insn.Op1.dtyp = dt_dword
                insn.Op2.reg = self.parse_r2(hw2)
                insn.Op2.dtyp = dt_dword

                insn.size = 6
                return True

            elif subop == 0xD:  # st.h
                insn.itype = NewInstructions.NN_st_h

                insn.Op1.type = o_reg
                insn.Op2.type = o_displ

                insn.Op2.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED
                insn.Op2.reg = self.parse_r1(hw1)

                buf = get_bytes(insn.ea+4, 2)
                hw3 = unpack("<H", buf)[0]

                insn.Op2.addr = self.sign_extend(((hw3 << 6) | ((hw2 & 0x7E0) >> 5)) << 1, 23)
                insn.Op2.dtyp = dt_dword
                insn.Op1.reg = self.parse_r2(hw2)
                insn.Op1.dtyp = dt_dword

                insn.size = 6
                return True

        # Format II
        elif op == 0x15: # sar imm5, reg2
            insn.itype = NewInstructions.NN_sar

            insn.Op1.type = o_imm
            insn.Op2.type = o_reg

            insn.Op1.value = hw1 & 0x1F
            insn.Op2.reg = self.parse_r2(hw1)

            insn.size = 2
            return True

        # Format IX, X, XI
        elif op == 0x3F:
            buf = get_bytes(insn.ea+2, 2)
            hw2 = unpack("<H", buf)[0]
            subop = hw2 & 0x7FF
            if DEBUG_P1KACHU:
                print("    Subop = {0}".format(hex(subop)))
                #print(hex(hw1 & 0x7ff), hex(hw2), hex(subop))
                print("")


            if hw1 & 0x7FF == 0x7E0:
                if hw1 == 0x7E0:
                    if hw2 == 0x14A: # feret
                        insn.itype = NewInstructions.NN_feret
                        insn.size = 4
                        return insn.size
                    elif hw2 == 0x0148: # eiret
                        insn.itype = NewInstructions.NN_eiret
                        insn.size = 4
                        return True

                elif subop == 0x366: # sch1l reg2, reg3
                    insn.itype = NewInstructions.NN_sch1l

                    insn.Op1.type = o_reg
                    insn.Op2.type = o_reg

                    insn.Op1.reg = self.parse_r2(hw1)
                    insn.Op2.reg = self.parse_r3(hw2)

                    insn.size = 4
                    return True

                elif subop == 0x362: # sch1r reg2, reg3
                    insn.itype = NewInstructions.NN_sch1r

                    insn.Op1.type = o_reg
                    insn.Op2.type = o_reg

                    insn.Op1.reg = self.parse_r2(hw1)
                    insn.Op2.reg = self.parse_r3(hw2)

                    insn.size = 4
                    return True

            insn_handled = False

            if subop == hw2 == 0xA0: # sar reg1, reg2
                insn.itype = NewInstructions.NN_sar

                insn.Op1.type = o_reg
                insn.Op2.type = o_reg

                insn.Op1.reg = self.parse_r1(hw1)
                insn.Op2.reg = self.parse_r2(hw1)

                insn.size = 4
                return True

            elif subop == 0xEE: # caxi [reg1], reg2, reg3
                insn.itype = NewInstructions.NN_caxi

                insn.Op1.type = o_displ
                insn.Op1.addr = 0
                insn.Op2.type = o_reg
                insn.Op3.type = o_reg

                insn.Op1.reg = self.parse_r1(hw1)
                insn.Op2.reg = self.parse_r2(hw1)
                insn.Op2.reg = self.parse_r3(hw2)

                insn.size = 4
                return True


            elif subop == 0x2FC:  # divq reg1, reg2, reg3
                insn.itype = NewInstructions.NN_divq
                insn.size = 4
                insn_handled = True

            elif subop == 0x2FE: # divqu reg1, reg2, reg3
                insn.itype = NewInstructions.NN_divqu
                insn.size = 4
                insn_handled = True

            elif subop == 0xA2: # sar reg1, reg2, reg3
                insn.itype = NewInstructions.NN_sar
                insn.size = 4
                insn_handled = True

            elif subop == 0xC2: # shl reg1, reg2, reg3
                insn.itype = NewInstructions.NN_shl
                insn.size = 4
                insn_handled = True

            elif subop == 0x82: # shr reg1, reg2, reg3
                insn.itype = NewInstructions.NN_shr
                insn.size = 4
                insn_handled = True

            # 0b 1001 0000
            # 0b 1101 1000
            # 0b 1011 1010
            # 0b 1001 1000
            # 0b 1101 1100
            elif subop == 0x90 or subop == 0xd8 or subop == 0xba or subop == 0x98 or subop == 0xdc: # bins (P1kachu)
                insn.itype = NewInstructions.NN_hardcoded_ins_bins
                insn.size = 4
                insn_handled = True

            elif subop == 0x160:
                insn.itype = NewInstructions.NN_hardcoded_ins_jarl_lp # jarl lp (P1kachu)
                insn.size = 4
                return True

            elif ((subop >> 4) & 1 and (subop >> 7) & 1):
                if DEBUG_P1KACHU:
                    print("Should be bins")
                insn.itype = NewInstructions.NN_hardcoded_ins_bins
                insn.size = 4
                insn_handled = True

                # hw1=07e0 hw2=0160 di
                # hw1=87e0 hw2=0160 ei
                # hw1=47e1 hw2=0960 pushsp
                # hw1=47e6 hw2=9960 pushsp
                # hw1=67e1 hw2=9060 popsp
                # hw1=67e6 hw2=9960 popsp
                #print("{0}: JARL?PUSHSP? - hw1={1} hw1>>4={2} hw2={3}".format(address, hex(hw1), hex(hw1>>4), hex(hw2)))

                if (hw1 >> 4) == 0x47e:
                    insn.itype = NewInstructions.NN_hardcoded_ins_pushsp
                elif (hw1 >> 4) == 0x67e:
                    insn.itype = NewInstructions.NN_hardcoded_ins_popsp
                elif hw1 == 0x7e0:
                    insn.itype = NewInstructions.NN_hardcoded_ins_di
                elif hw1 == 0x87e0:
                    insn.itype = NewInstructions.NN_hardcoded_ins_ei
                else:
                    insn.itype = NewInstructions.NN_hardcoded_ins_jarl

                insn.size = 4
                #buf = get_bytes(insn.ea+2, 4)
                #hw2 = unpack("<I", buf)[0]
                #insn.Op1.type = o_imm
                #insn.Op1.dtyp = dt_dword
                #insn.Op1.value = hw2
                return True

            elif (subop >> 5) == 0x1f: # macu (P1kachu)
                insn.itype = NewInstructions.NN_hardcoded_ins_macu
                insn.size = 4
                return True

            elif subop == 0x382: # sbf (P1kachu)
                insn.itype = NewInstructions.NN_hardcoded_ins_sbf
                insn.size = 4
                return True

            elif subop == 0x3a2 or subop == 0x3a8: # adf (P1kachu)
                insn.itype = NewInstructions.NN_hardcoded_ins_adf
                insn.size = 4
                return True

            elif subop == 0x40: # stsr (P1kachu)
                insn.itype = NewInstructions.NN_hardcoded_ins_stsr
                insn.size = 4
                return True

            elif subop == 0x20: # ldsr (P1kachu)
                insn.itype = NewInstructions.NN_hardcoded_ins_ldsr
                insn.size = 4
                return True

            elif (subop >> 5) == 0x1e: # mac (P1kachu)
                # 0x3c6: 0b1111000110
                # 0x3c8: 0b1111001000
                # 0x3ca: 0b1111001010
                # 0x3da: 0b1111011100
                # 0x3dc: 0b1111011100
                # ...
                insn.itype = NewInstructions.NN_hardcoded_ins_mac
                insn.size = 4
                return True

            elif subop >> 10: # idk (P1kachu)
                try:
                    s_type_instructions_hardcoded = {

                        # 0x400: 0b10000000000: cmpf.s
                        # 0x420: 0b10000100000: trfsr
                        # 0x442: 0b10001000010: cvtf.ws
                        # 0x460: 0b10001100000: addf.s
                        # 0x464: 0b10001100100: mulf.s
                        # 0x46e: 0b10001101110: divf.s


                        0x0400: NewInstructions.NN_hardcoded_ins_trfsr,
                        0x1430: NewInstructions.NN_hardcoded_ins_cmpf_d,
                        0x2420: NewInstructions.NN_hardcoded_ins_cmpf_s,
                        0x2430: NewInstructions.NN_hardcoded_ins_cmpf_d,
                        0x3420: NewInstructions.NN_hardcoded_ins_cmpf_s,
                        0x3442: NewInstructions.NN_hardcoded_ins_cvtf_ws,
                        0x3464: NewInstructions.NN_hardcoded_ins_mulf_s,
                        0x346e: NewInstructions.NN_hardcoded_ins_divf_s,
                        0x3c42: NewInstructions.NN_hardcoded_ins_cvtf_ws,
                        0x3c64: NewInstructions.NN_hardcoded_ins_mulf_s,
                        0x4400: NewInstructions.NN_hardcoded_ins_cmovf_s,
                        0x4452: NewInstructions.NN_hardcoded_ins_cvtf_wd,
                        0x4458: NewInstructions.NN_hardcoded_ins_negf_d,
                        0x4464: NewInstructions.NN_hardcoded_ins_mulf_s,
                        0x4472: NewInstructions.NN_hardcoded_ins_subf_d,
                        0x4474: NewInstructions.NN_hardcoded_ins_mulf_d,
                        0x447e: NewInstructions.NN_hardcoded_ins_divf_d,
                        0x4c50: NewInstructions.NN_hardcoded_ins_cvtf_dw,
                        0x4c60: NewInstructions.NN_hardcoded_ins_addf_s,
                        0x4c64: NewInstructions.NN_hardcoded_ins_mulf_s,
                        0x5452: NewInstructions.NN_hardcoded_ins_cvtf_wd,
                        0x5474: NewInstructions.NN_hardcoded_ins_mulf_d,
                        0x5c50: NewInstructions.NN_hardcoded_ins_cvtf_dw,
                        0x9450: NewInstructions.NN_hardcoded_ins_cvtf_dw,
                    }

                    insn.itype = s_type_instructions_hardcoded[hw2]
                    insn.size = 4
                    return True
                except Exception as e:
                    if DEBUG_P1KACHU:
                        print("NOT FOUND S INSTRUCTION: ", address, hex(hw2))
                        print(e)
                    pass
            if insn_handled:
                insn.Op1.type = o_reg
                insn.Op2.type = o_reg
                insn.Op3.type = o_reg

                insn.Op1.reg = self.parse_r1(hw1)
                insn.Op2.reg = self.parse_r2(hw1)
                insn.Op3.reg = self.parse_r3(hw2)
                return True

        # Custom P1kachu
        elif op == 0x17:
            if hw1 == 0x2e0: # jr
                insn.itype = NewInstructions.NN_hardcoded_ins_jr
                insn.size = 6

                buf = get_bytes(insn.ea+2, 4)
                hw2 = unpack("<I", buf)[0]
                insn.Op1.type = o_imm
                insn.Op1.dtyp = dt_dword
                insn.Op1.value = hw2 + insn.ea

                #print("    {0}: JR - hw1={2} hw1={2}".format(address, hex(hw1), hex(hw2)))

                return True

            if hw1 == 0x2ff: # jarl xxxxx, lp
                insn.itype = NewInstructions.NN_hardcoded_ins_jarl_lp
                insn.size = 6

                return True

            elif (hw1 == 0x2afc
            or hw1 == 0x52e2):
                pass
            else:
                pass
                #print("    {0}: JARL - OP == 0x17 but not JR (hw1={1})".format(address, hex(hw1)))
            return False

        elif op == 0x3c:
            if hw1 == 0x780:

                # DMAC operation
                if hw2 == 0x00000f: # st.w TL    00000000001111
                    insn.itype = NewInstructions.NN_hardcoded_ins_dmac_operation
                    insn.size = 6
                elif hw2 == 0x33cf: # st.w DM1   11001111001111
                    insn.itype = NewInstructions.NN_hardcoded_ins_dmac_operation
                    insn.size = 6
                elif hw2 == 0x3349: # ld.w DM1   11001101001001
                    insn.itype = NewInstructions.NN_hardcoded_ins_dmac_operation
                    insn.size = 6
                elif hw2 == 0x3309: # ld.w DM0   11001100001001
                    insn.itype = NewInstructions.NN_hardcoded_ins_dmac_operation
                    insn.size = 6

                #print("    {0}: DMAC".format(address))

                if insn.size == 6:
                    return True

        return False

    def ev_ana_insn(self, insn):
        if insn.ea & 1:
            return False

        return self.decode_instruction(insn)

    def ev_out_mnem(self, outctx):
        insntype = outctx.insn.itype
        global NEWINSN_COLOR

        if (insntype >= CUSTOM_INSN_ITYPE) and (insntype in NewInstructions.lst):
            mnem = NewInstructions.lst[insntype]
            outctx.out_tagon(NEWINSN_COLOR)
            outctx.out_line(mnem)
            outctx.out_tagoff(NEWINSN_COLOR)

            # TODO: how can MNEM_width be determined programatically?
            MNEM_WIDTH = 8
            width = max(1, MNEM_WIDTH - len(mnem))
            outctx.out_line(' ' * width)

            return True
        return False

    def ev_emu_insn(self, insn):
        if insn.itype in [NewInstructions.NN_eiret, NewInstructions.NN_feret]:
            return True
        return False

    def ev_out_operand(self, outctx, op):
        insn = outctx.insn
        if insn.itype in [NewInstructions.NN_ld_hu, NewInstructions.NN_st_h]:
            if op.type == o_displ:

                outctx.out_value(op, OOF_ADDR)
                brackets = insn.ops[op.n].specflag1 & N850F_USEBRACKETS
                if brackets:
                    outctx.out_symbol('[')
                outctx.out_register(ph_get_regnames()[op.reg])
                if brackets:
                    outctx.out_symbol(']')
                return True
        return False


#--------------------------------------------------------------------------
class NECromancer_t(plugin_t):
    flags = PLUGIN_PROC | PLUGIN_HIDE
    comment = ""
    wanted_hotkey = ""
    help = "Adds support for additional V850X instructions"
    wanted_name = "NECromancer"

    def __init__(self):
        self.prochook = None

    def init(self):
        if ph_get_id() != PLFM_NEC_V850X:
            return PLUGIN_SKIP

        self.prochook = v850_idp_hook_t()
        self.prochook.hook()
        print "%s intialized." % NECromancer_t.wanted_name
        return PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.prochook:
            self.prochook.unhook()

#--------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return NECromancer_t()
