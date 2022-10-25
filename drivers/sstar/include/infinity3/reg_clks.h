/*
* reg_clks.h- Sigmastar
*
* Copyright (c) [2019~2020] SigmaStar Technology.
*
*
* This software is licensed under the terms of the GNU General Public
* License version 2, as published by the Free Software Foundation, and
* may be copied, distributed, and modified under those terms.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License version 2 for more details.
*
*/
#ifndef __REG_CLKS_H
#define __REG_CLKS_H

/* generated by CLK_DT_GEN_5 */
/* CLK FILENAME: I3\iNfinity3e_Clock_Table_20161111_v0p2.xls */
/* REG FILENAME: I3\20161109\iNfinity3e_reg_CLKGEN.xls, I3\20161109\iNfinity3e_reg_pm_sleep.xls, I3\20161109\iNfinity3e_reg_block.xls */

#define    REG_CKG_BASE                  0x1F207000
#define    REG_SC_GP_CTRL_BASE           0x1F226600
#define    REG_PM_SLEEP_CKG_BASE         0x1F001C00


//====SPECIAL_CKG_REG==============================================
#define    REG_CKG_EMAC_RX_BASE   (REG_SC_GP_CTRL_BASE+0x22*4)
#define    REG_CKG_EMAC_RX_OFFSET (0)

#define    REG_CKG_EMAC_RX_REF_BASE   (REG_SC_GP_CTRL_BASE+0x22*4)
#define    REG_CKG_EMAC_RX_REF_OFFSET (8)

#define    REG_CKG_EMAC_TX_BASE   (REG_SC_GP_CTRL_BASE+0x23*4)
#define    REG_CKG_EMAC_TX_OFFSET (0)

#define    REG_CKG_EMAC_TX_REF_BASE   (REG_SC_GP_CTRL_BASE+0x23*4)
#define    REG_CKG_EMAC_TX_REF_OFFSET (8)

#define    REG_CKG_GOP0_PSRAM_BASE   (REG_SC_GP_CTRL_BASE+0x21*4)
#define    REG_CKG_GOP0_PSRAM_OFFSET (0)

#define    REG_CKG_GOP1_PSRAM_BASE   (REG_SC_GP_CTRL_BASE+0x21*4)
#define    REG_CKG_GOP1_PSRAM_OFFSET (4)

#define    REG_CKG_GOP2_PSRAM_BASE   (REG_SC_GP_CTRL_BASE+0x21*4)
#define    REG_CKG_GOP2_PSRAM_OFFSET (8)

#define    REG_CKG_IMI_BASE   (REG_SC_GP_CTRL_BASE+0x20*4)
#define    REG_CKG_IMI_OFFSET (0)

#define    REG_CKG_NLM_BASE   (REG_SC_GP_CTRL_BASE+0x20*4)
#define    REG_CKG_NLM_OFFSET (8)

#define    REG_NLM_CLK_GATE_RD_BASE   (REG_SC_GP_CTRL_BASE+0x20*4)
#define    REG_NLM_CLK_GATE_RD_OFFSET (13)

#define    REG_NLM_CLK_SEL_RD_BASE   (REG_SC_GP_CTRL_BASE+0x20*4)
#define    REG_NLM_CLK_SEL_RD_OFFSET (12)

#define    REG_SC_SPARE_HI_BASE   (REG_SC_GP_CTRL_BASE+0x31*4)
#define    REG_SC_SPARE_HI_OFFSET (0)

#define    REG_SC_SPARE_LO_BASE   (REG_SC_GP_CTRL_BASE+0x30*4)
#define    REG_SC_SPARE_LO_OFFSET (0)

#define    REG_SC_TEST_IN_SEL_BASE   (REG_SC_GP_CTRL_BASE+0x32*4)
#define    REG_SC_TEST_IN_SEL_OFFSET (0)



//====PM_CKG_REG==============================================
#define    REG_CKG_AV_LNK_BASE   (REG_PM_SLEEP_CKG_BASE+0x24*4)
#define    REG_CKG_AV_LNK_OFFSET (4)

#define    REG_CKG_CEC_BASE   (REG_PM_SLEEP_CKG_BASE+0x23*4)
#define    REG_CKG_CEC_OFFSET (0)

#define    REG_CKG_CEC_RX_BASE   (REG_PM_SLEEP_CKG_BASE+0x26*4)
#define    REG_CKG_CEC_RX_OFFSET (0)

#define    REG_CKG_DDC_BASE   (REG_PM_SLEEP_CKG_BASE+0x21*4)
#define    REG_CKG_DDC_OFFSET (0)

#define    REG_CKG_DVI_RAW0_BASE   (REG_PM_SLEEP_CKG_BASE+0x23*4)
#define    REG_CKG_DVI_RAW0_OFFSET (4)

#define    REG_CKG_DVI_RAW1_BASE   (REG_PM_SLEEP_CKG_BASE+0x23*4)
#define    REG_CKG_DVI_RAW1_OFFSET (8)

#define    REG_CKG_DVI_RAW2_BASE   (REG_PM_SLEEP_CKG_BASE+0x24*4)
#define    REG_CKG_DVI_RAW2_OFFSET (0)

#define    REG_CKG_HOTPLUG_BASE   (REG_PM_SLEEP_CKG_BASE+0x24*4)
#define    REG_CKG_HOTPLUG_OFFSET (12)

#define    REG_CKG_IR_BASE   (REG_PM_SLEEP_CKG_BASE+0x21*4)
#define    REG_CKG_IR_OFFSET (5)

#define    REG_CKG_KREF_BASE   (REG_PM_SLEEP_CKG_BASE+0x23*4)
#define    REG_CKG_KREF_OFFSET (12)

#define    REG_CKG_MCU_PM_BASE   (REG_PM_SLEEP_CKG_BASE+0x20*4)
#define    REG_CKG_MCU_PM_OFFSET (0)

#define    REG_CKG_MIIC_BASE   (REG_PM_SLEEP_CKG_BASE+0x26*4)
#define    REG_CKG_MIIC_OFFSET (12)

#define    REG_CKG_PM_SLEEP_BASE   (REG_PM_SLEEP_CKG_BASE+0x22*4)
#define    REG_CKG_PM_SLEEP_OFFSET (10)

#define    REG_CKG_RTC_BASE   (REG_PM_SLEEP_CKG_BASE+0x22*4)
#define    REG_CKG_RTC_OFFSET (0)

#define    REG_CKG_SAR_BASE   (REG_PM_SLEEP_CKG_BASE+0x22*4)
#define    REG_CKG_SAR_OFFSET (5)

#define    REG_CKG_SCDC_P0_BASE   (REG_PM_SLEEP_CKG_BASE+0x26*4)
#define    REG_CKG_SCDC_P0_OFFSET (4)

#define    REG_CKG_SD_BASE   (REG_PM_SLEEP_CKG_BASE+0x21*4)
#define    REG_CKG_SD_OFFSET (10)

#define    REG_CKG_SPI_PM_BASE   (REG_PM_SLEEP_CKG_BASE+0x20*4)
#define    REG_CKG_SPI_PM_OFFSET (8)



//====NORMAL_CKG_REG==============================================
#define    REG_CKG_123M_2DIGPM_BASE   (REG_CKG_BASE+0x6D*4)
#define    REG_CKG_123M_2DIGPM_OFFSET (4)

#define    REG_CKG_144M_2DIGPM_BASE   (REG_CKG_BASE+0x6D*4)
#define    REG_CKG_144M_2DIGPM_OFFSET (3)

#define    REG_CKG_172M_2DIGPM_BASE   (REG_CKG_BASE+0x6D*4)
#define    REG_CKG_172M_2DIGPM_OFFSET (2)

#define    REG_CKG_216M_2DIGPM_BASE   (REG_CKG_BASE+0x6D*4)
#define    REG_CKG_216M_2DIGPM_OFFSET (1)

#define    REG_CKG_86M_2DIGPM_BASE   (REG_CKG_BASE+0x6D*4)
#define    REG_CKG_86M_2DIGPM_OFFSET (5)

#define    REG_CKG_AESDMA_BASE   (REG_CKG_BASE+0x61*4)
#define    REG_CKG_AESDMA_OFFSET (0)

#define    REG_CKG_BDMA_BASE   (REG_CKG_BASE+0x60*4)
#define    REG_CKG_BDMA_OFFSET (0)

#define    REG_CKG_BIST_BASE   (REG_CKG_BASE+0x02*4)
#define    REG_CKG_BIST_OFFSET (0)

#define    REG_CKG_BIST_PM_BASE   (REG_CKG_BASE+0x02*4)
#define    REG_CKG_BIST_PM_OFFSET (8)

#define    REG_CKG_BIST_SC_GP_BASE   (REG_CKG_BASE+0x03*4)
#define    REG_CKG_BIST_SC_GP_OFFSET (0)

#define    REG_CKG_BIST_VHE_GP_BASE   (REG_CKG_BASE+0x03*4)
#define    REG_CKG_BIST_VHE_GP_OFFSET (8)

#define    REG_CKG_BOOT_BASE   (REG_CKG_BASE+0x08*4)
#define    REG_CKG_BOOT_OFFSET (0)

#define    REG_CKG_CSI_MAC_BASE   (REG_CKG_BASE+0x6C*4)
#define    REG_CKG_CSI_MAC_OFFSET (0)

#define    REG_CKG_DDR_SYN_BASE   (REG_CKG_BASE+0x19*4)
#define    REG_CKG_DDR_SYN_OFFSET (0)

#define    REG_CKG_ECC_BASE   (REG_CKG_BASE+0x44*4)
#define    REG_CKG_ECC_OFFSET (0)

#define    REG_CKG_EMAC_AHB_BASE   (REG_CKG_BASE+0x42*4)
#define    REG_CKG_EMAC_AHB_OFFSET (0)

#define    REG_CKG_FCIE_BASE   (REG_CKG_BASE+0x43*4)
#define    REG_CKG_FCIE_OFFSET (0)

#define    REG_CKG_FCLK1_BASE   (REG_CKG_BASE+0x64*4)
#define    REG_CKG_FCLK1_OFFSET (0)

#define    REG_CKG_FCLK2_BASE   (REG_CKG_BASE+0x65*4)
#define    REG_CKG_FCLK2_OFFSET (0)

#define    REG_CKG_FUART_BASE   (REG_CKG_BASE+0x34*4)
#define    REG_CKG_FUART_OFFSET (0)

#define    REG_CKG_FUART0_SYNTH_IN_BASE   (REG_CKG_BASE+0x34*4)
#define    REG_CKG_FUART0_SYNTH_IN_OFFSET (4)

#define    REG_CKG_GOP_BASE   (REG_CKG_BASE+0x67*4)
#define    REG_CKG_GOP_OFFSET (0)

#define    REG_CKG_HEMCU_216M_BASE   (REG_CKG_BASE+0x6D*4)
#define    REG_CKG_HEMCU_216M_OFFSET (0)

#define    REG_CKG_IDCLK_BASE   (REG_CKG_BASE+0x63*4)
#define    REG_CKG_IDCLK_OFFSET (0)

#define    REG_CKG_ISP_BASE   (REG_CKG_BASE+0x61*4)
#define    REG_CKG_ISP_OFFSET (8)

#define    REG_CKG_IVE_BASE   (REG_CKG_BASE+0x6A*4)
#define    REG_CKG_IVE_OFFSET (8)

#define    REG_CKG_JPE_BASE   (REG_CKG_BASE+0x6A*4)
#define    REG_CKG_JPE_OFFSET (0)

#define    REG_CKG_LIVE_BASE   (REG_CKG_BASE+0x00*4)
#define    REG_CKG_LIVE_OFFSET (8)

#define    REG_CKG_MAC_LPTX_BASE   (REG_CKG_BASE+0x6C*4)
#define    REG_CKG_MAC_LPTX_OFFSET (8)

#define    REG_CKG_MCU_BASE   (REG_CKG_BASE+0x01*4)
#define    REG_CKG_MCU_OFFSET (0)

#define    REG_CKG_MFE_BASE   (REG_CKG_BASE+0x69*4)
#define    REG_CKG_MFE_OFFSET (0)

#define    REG_CKG_MIIC0_BASE   (REG_CKG_BASE+0x37*4)
#define    REG_CKG_MIIC0_OFFSET (0)

#define    REG_CKG_MIIC1_BASE   (REG_CKG_BASE+0x37*4)
#define    REG_CKG_MIIC1_OFFSET (8)

#define    REG_CKG_MIU_BASE   (REG_CKG_BASE+0x17*4)
#define    REG_CKG_MIU_OFFSET (0)

#define    REG_CKG_MIU_BOOT_BASE   (REG_CKG_BASE+0x20*4)
#define    REG_CKG_MIU_BOOT_OFFSET (0)

#define    REG_CKG_MIU_REC_BASE   (REG_CKG_BASE+0x18*4)
#define    REG_CKG_MIU_REC_OFFSET (0)

#define    REG_CKG_MSPI0_BASE   (REG_CKG_BASE+0x33*4)
#define    REG_CKG_MSPI0_OFFSET (0)

#define    REG_CKG_MSPI1_BASE   (REG_CKG_BASE+0x33*4)
#define    REG_CKG_MSPI1_OFFSET (8)

#define    REG_CKG_NS_BASE   (REG_CKG_BASE+0x6B*4)
#define    REG_CKG_NS_OFFSET (0)

#define    REG_CKG_ODCLK_BASE   (REG_CKG_BASE+0x66*4)
#define    REG_CKG_ODCLK_OFFSET (0)

#define    REG_CKG_RIUBRDG_BASE   (REG_CKG_BASE+0x01*4)
#define    REG_CKG_RIUBRDG_OFFSET (8)

#define    REG_CKG_SDIO_BASE   (REG_CKG_BASE+0x45*4)
#define    REG_CKG_SDIO_OFFSET (0)

#define    REG_CKG_SPI_BASE   (REG_CKG_BASE+0x32*4)
#define    REG_CKG_SPI_OFFSET (0)

#define    REG_CKG_SR_BASE   (REG_CKG_BASE+0x62*4)
#define    REG_CKG_SR_OFFSET (0)

#define    REG_CKG_SR_MCLK_BASE   (REG_CKG_BASE+0x62*4)
#define    REG_CKG_SR_MCLK_OFFSET (8)

#define    REG_CKG_TCK_BASE   (REG_CKG_BASE+0x30*4)
#define    REG_CKG_TCK_OFFSET (0)

#define    REG_CKG_UART0_BASE   (REG_CKG_BASE+0x31*4)
#define    REG_CKG_UART0_OFFSET (0)

#define    REG_CKG_UART1_BASE   (REG_CKG_BASE+0x31*4)
#define    REG_CKG_UART1_OFFSET (8)

#define    REG_CKG_VHE_BASE   (REG_CKG_BASE+0x68*4)
#define    REG_CKG_VHE_OFFSET (0)

#define    REG_CKG_XTALI_BASE   (REG_CKG_BASE+0x00*4)
#define    REG_CKG_XTALI_OFFSET (0)

#define    REG_CKG_XTALI_SC_GP_BASE   (REG_CKG_BASE+0x00*4)
#define    REG_CKG_XTALI_SC_GP_OFFSET (4)

#define    REG_CLKGEN0_RESERVED0_BASE   (REG_CKG_BASE+0x7E*4)
#define    REG_CLKGEN0_RESERVED0_OFFSET (0)

#define    REG_CLKGEN0_RESERVED1_BASE   (REG_CKG_BASE+0x7F*4)
#define    REG_CLKGEN0_RESERVED1_OFFSET (0)

#define    REG_MPLL_123_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_MPLL_123_EN_RD_OFFSET (12)

#define    REG_MPLL_123_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_MPLL_123_FORCE_OFF_OFFSET (12)

#define    REG_MPLL_123_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_MPLL_123_FORCE_ON_OFFSET (12)

#define    REG_MPLL_124_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_MPLL_124_EN_RD_OFFSET (13)

#define    REG_MPLL_124_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_MPLL_124_FORCE_OFF_OFFSET (13)

#define    REG_MPLL_124_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_MPLL_124_FORCE_ON_OFFSET (13)

#define    REG_MPLL_144_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_MPLL_144_EN_RD_OFFSET (11)

#define    REG_MPLL_144_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_MPLL_144_FORCE_OFF_OFFSET (11)

#define    REG_MPLL_144_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_MPLL_144_FORCE_ON_OFFSET (11)

#define    REG_MPLL_172_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_MPLL_172_EN_RD_OFFSET (10)

#define    REG_MPLL_172_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_MPLL_172_FORCE_OFF_OFFSET (10)

#define    REG_MPLL_172_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_MPLL_172_FORCE_ON_OFFSET (10)

#define    REG_MPLL_216_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_MPLL_216_EN_RD_OFFSET (9)

#define    REG_MPLL_216_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_MPLL_216_FORCE_OFF_OFFSET (9)

#define    REG_MPLL_216_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_MPLL_216_FORCE_ON_OFFSET (9)

#define    REG_MPLL_288_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_MPLL_288_EN_RD_OFFSET (8)

#define    REG_MPLL_288_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_MPLL_288_FORCE_OFF_OFFSET (8)

#define    REG_MPLL_288_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_MPLL_288_FORCE_ON_OFFSET (8)

#define    REG_MPLL_345_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_MPLL_345_EN_RD_OFFSET (7)

#define    REG_MPLL_345_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_MPLL_345_FORCE_OFF_OFFSET (7)

#define    REG_MPLL_345_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_MPLL_345_FORCE_ON_OFFSET (7)

#define    REG_MPLL_432_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_MPLL_432_EN_RD_OFFSET (6)

#define    REG_MPLL_432_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_MPLL_432_FORCE_OFF_OFFSET (6)

#define    REG_MPLL_432_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_MPLL_432_FORCE_ON_OFFSET (6)

#define    REG_MPLL_86_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_MPLL_86_EN_RD_OFFSET (14)

#define    REG_MPLL_86_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_MPLL_86_FORCE_OFF_OFFSET (14)

#define    REG_MPLL_86_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_MPLL_86_FORCE_ON_OFFSET (14)

#define    REG_PLL_GATER_FORCE_OFF_LOCK_BASE   (REG_CKG_BASE+0x70*4)
#define    REG_PLL_GATER_FORCE_OFF_LOCK_OFFSET (1)

#define    REG_PLL_GATER_FORCE_ON_LOCK_BASE   (REG_CKG_BASE+0x70*4)
#define    REG_PLL_GATER_FORCE_ON_LOCK_OFFSET (0)

#define    REG_PLL_RV1_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_PLL_RV1_FORCE_OFF_OFFSET (15)

#define    REG_PLL_RV1_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_PLL_RV1_FORCE_ON_OFFSET (15)

#define    REG_UART_STNTHESIZER_ENABLE_BASE   (REG_CKG_BASE+0x34*4)
#define    REG_UART_STNTHESIZER_ENABLE_OFFSET (8)

#define    REG_UART_STNTHESIZER_FIX_NF_FREQ_BASE   (REG_CKG_BASE+0x36*4)
#define    REG_UART_STNTHESIZER_FIX_NF_FREQ_OFFSET (0)

#define    REG_UART_STNTHESIZER_SW_RSTZ_BASE   (REG_CKG_BASE+0x34*4)
#define    REG_UART_STNTHESIZER_SW_RSTZ_OFFSET (9)

#define    REG_UPLL_320_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_UPLL_320_EN_RD_OFFSET (1)

#define    REG_UPLL_320_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_UPLL_320_FORCE_OFF_OFFSET (1)

#define    REG_UPLL_320_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_UPLL_320_FORCE_ON_OFFSET (1)

#define    REG_UPLL_384_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_UPLL_384_EN_RD_OFFSET (0)

#define    REG_UPLL_384_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_UPLL_384_FORCE_OFF_OFFSET (0)

#define    REG_UPLL_384_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_UPLL_384_FORCE_ON_OFFSET (0)

#define    REG_UTMI_160_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_UTMI_160_EN_RD_OFFSET (2)

#define    REG_UTMI_160_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_UTMI_160_FORCE_OFF_OFFSET (2)

#define    REG_UTMI_160_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_UTMI_160_FORCE_ON_OFFSET (2)

#define    REG_UTMI_192_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_UTMI_192_EN_RD_OFFSET (3)

#define    REG_UTMI_192_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_UTMI_192_FORCE_OFF_OFFSET (3)

#define    REG_UTMI_192_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_UTMI_192_FORCE_ON_OFFSET (3)

#define    REG_UTMI_240_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_UTMI_240_EN_RD_OFFSET (4)

#define    REG_UTMI_240_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_UTMI_240_FORCE_OFF_OFFSET (4)

#define    REG_UTMI_240_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_UTMI_240_FORCE_ON_OFFSET (4)

#define    REG_UTMI_480_EN_RD_BASE   (REG_CKG_BASE+0x73*4)
#define    REG_UTMI_480_EN_RD_OFFSET (5)

#define    REG_UTMI_480_FORCE_OFF_BASE   (REG_CKG_BASE+0x72*4)
#define    REG_UTMI_480_FORCE_OFF_OFFSET (5)

#define    REG_UTMI_480_FORCE_ON_BASE   (REG_CKG_BASE+0x71*4)
#define    REG_UTMI_480_FORCE_ON_OFFSET (5)


#endif
