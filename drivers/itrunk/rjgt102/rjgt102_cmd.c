/**
 **************************************************************************************
 *                Copyright(c) 2015 Wuhan Runjet, All rights reserved.
 **************************************************************************************
 * @file     rjgt102.c
 * @author   Wuhan Runjet software and test team
 * @date     04-Feb-2015
 * @version  V1.00
 * @brief    Header file for RJGT102 chip.
 **************************************************************************************
 *
 */ 
#include "rjgt102_cmd.h"


/**@brief I2C驱动封装宏定义
 */
#define RJGT102_I2cOpen		       S_Rjgt102I2c->Open
#define RJGT102_I2cClose	       S_Rjgt102I2c->Close
#define RJGT102_I2cReadByte		   S_Rjgt102I2c->ReadByte
#define RJGT102_I2cWriteByte	   S_Rjgt102I2c->WriteByte
#define RJGT102_I2cRead            S_Rjgt102I2c->Read
#define RJGT102_I2cWrite		   S_Rjgt102I2c->Write


/**
 * @brief 静态全局变量定义
 */
static volatile uint32_t S_dwSeed = 0x0230A29F;
static volatile I2C_Driver_t *S_Rjgt102I2c = {0x00};



/**
 ***************************************************************************
 * @brief  产生一个32位的整型随机数
 * @param  无
 * @retval 返回一个32位的整型随机数
 ***************************************************************************
 */
static uint32_t Rand(void)
{
    S_dwSeed = S_dwSeed * 1103515245L + 12345;

    return (uint32_t)(S_dwSeed / 65536L) % 32768L;
}

/**
 ***************************************************************************
 * @brief  产生8个字节的随机数
 * @param  [OUT] pRngBuf  指向存储8字节随机数的数据区
 * @retval 无
 ***************************************************************************
 */
void RJGT102_GenerateRandom(uint8_t *pRngBuf)
{	
    uint32_t RngBuf[2];
    uint8_t  i;
	
    RngBuf[0] = Rand();
    RngBuf[1] = Rand();
    for (i = 0; i < 4; i++)
    {
        pRngBuf[i] = (uint8_t)((RngBuf[0] >> (8 * i)) & 0xFF);
        pRngBuf[i + 4] = (uint8_t)((RngBuf[1] >> (8 * i)) & 0xFF);
    }
}


/**
 ***************************************************************************
 * @brief  获取执行状态
 * @param  无
 * @retval 返回状态值 @ref ExecutionStatus_t
 *         @arg 0x00 -命令正执行中
 *         @arg 0x01 -命令正确执行完成
 *         @arg 0x11 -命令错误执行完成
 *         @arg 0x10 -命令执行非法
 *         @arg 0xFF -命令执行超时
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_GetExecutionStatus(void)
{
    uint8_t ExecutionStatus = 0x00;
    uint32_t TimeOut = CMD_EXECUTION_TIMEOUT;
	
    do
    {
        RJGT102_I2cReadByte(&ExecutionStatus, REG_ES);
        ExecutionStatus &= 0x11;
    } while((!ExecutionStatus) && (--TimeOut));
	
    if (0x00 == TimeOut)
    {
        ExecutionStatus = 0xFF;
    }

    return ((ExecutionStatus_t)ExecutionStatus);
}


/**
 ***************************************************************************
 * @brief  版保芯片I2C驱动注册
 * @param  [IN] pI2cDriver  指向I2C驱动 @ref I2C_Driver_t
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
void RJGT102_I2cDriverRegister(I2C_Driver_t *pI2cDriver)
{
	S_Rjgt102I2c = pI2cDriver;
}


/**
 ***************************************************************************
 * @brief  版保芯片初始化
 * @param  无
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_Init(void)
{
	ExecutionStatus_t ExecutionStatus = ES_ERROR;
	
	RJGT102_I2cOpen();
	
	/*!< 上电后,检查我司版保芯片 */
	if (RJGT102_CheckVersion())
	{
		/*!< 指定读PAGE区数据时，加密输出 */
		ExecutionStatus = RJGT102_ConfigReadPageMode(PAGE_ENCRYPT_OUTPUT);
	}
	
	return ExecutionStatus;
}


/**
 ***************************************************************************
 * @brief  初始化USID用户ID区
 * @param  [IN] pUsidBuf  指向8字节初始化用户ID区数据
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_InitUsid(const uint8_t *pUsidBuf)
{
    uint8_t UsidBuf[8];
	
    memcpy(UsidBuf, pUsidBuf, 8);
	
    RJGT102_I2cWriteByte(CMD_CLEARCMD, REG_MCMD);
    RJGT102_I2cWrite(REG_MEMBUF, UsidBuf, 8);
    RJGT102_I2cWriteByte(CMD_INITUSID, REG_MCMD);
	
    return (RJGT102_GetExecutionStatus());
}

/**
 ***************************************************************************
 * @brief  初始化指定PAGEx(x=0-3)区
 * @param  [IN] PageAddr  指定待初始化PAGEx(x=0-3)的地址
 *         [IN] pPageBuf  指向32字节初始化PAGE区数据
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_InitPage(uint8_t PageAddr, const uint8_t *pPageBuf)
{
    uint8_t PageBuf[32];
	
    memcpy(PageBuf, pPageBuf, 32);
	
    RJGT102_I2cWriteByte(CMD_CLEARCMD, REG_MCMD);
    RJGT102_I2cWrite(REG_MEMBUF, PageBuf, 32);
    RJGT102_I2cWriteByte(PageAddr, REG_TAd);
    RJGT102_I2cWriteByte(CMD_INITPAGE, REG_MCMD);
	
    return (RJGT102_GetExecutionStatus());
}

/**
 ***************************************************************************
 * @brief  初始化KEY密钥区
 * @param  [IN] pKeyBuf  指向8字节初始化KEY区数据
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_InitKey(const uint8_t *pKeyBuf)
{
    uint8_t KeyBuf[8];
	
    memcpy(KeyBuf, pKeyBuf, 8);
	
    RJGT102_I2cWriteByte(CMD_CLEARCMD, REG_MCMD);
    RJGT102_I2cWrite(REG_MEMBUF, KeyBuf, 8);	
    RJGT102_I2cWriteByte(CMD_INITKEY, REG_MCMD);
	
    return (RJGT102_GetExecutionStatus());
}

/**
 ***************************************************************************
 * @brief  主机认证芯片以从芯片获取32字节MAC值
 * @param  [IN]  PageAddr  指定参与MAC计算的PAGEx(x=0-3)的地址
 *         [IN]  pRngBuf   指向参与MAC计算的8字节随机数
 *         [OUT] pMacBuf   指向用来存储32字节消息认证码MAC的数据区
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_AuthenticationDevice(uint8_t PageAddr, const uint8_t *pRngBuf, uint8_t *pMacBuf)
{
    ExecutionStatus_t ExecutionStatus;
    uint8_t RngBuf[8];
	
    memcpy(RngBuf, pRngBuf, 8);
    RJGT102_I2cWriteByte(CMD_CLEARCMD, REG_MCMD);
    RJGT102_I2cWrite(REG_MEMBUF, RngBuf, 8);	
    RJGT102_I2cWriteByte(PageAddr, REG_TAr);
    RJGT102_I2cWriteByte(CMD_AUTHENTICATION, REG_MCMD);

    ExecutionStatus = RJGT102_GetExecutionStatus();
    if (ES_NORMAL == ExecutionStatus)
    {
        RJGT102_I2cRead(REG_MEMBUF, pMacBuf, 32);
    }
	
    return ExecutionStatus;
}

/**
 ***************************************************************************
 * @brief  更新KEY密钥区
 * @param  [IN] PageAddr 指定参与MAC计算的PAGEx(x=0-3)的地址
 *         [IN] pRngBuf  指向参与MAC计算的8字节随机数存储区
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_UpdateKey(uint8_t PageAddr, const uint8_t *pRngBuf)
{
    uint8_t RngBuf[8];
	
    memcpy(RngBuf, pRngBuf, 8);
	
    RJGT102_I2cWriteByte(CMD_CLEARCMD, REG_MCMD);
    RJGT102_I2cWrite(REG_MEMBUF, RngBuf, 8);
    RJGT102_I2cWriteByte(PageAddr, REG_TAr);
    RJGT102_I2cWriteByte(CMD_GENERATEKEY, REG_MCMD);

    return (RJGT102_GetExecutionStatus());
}

/**
 ***************************************************************************
 * @brief  向指定的控制寄存器(地址范围：0xA0~0xAE)写入1字节数据
 * @param  [IN] Addr  	  指定待写入地址
 *         [IN] ByteData  指定待写入的字节数据
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_WriteCtrlReg(uint8_t Addr, uint8_t ByteData)
{
    RJGT102_I2cWriteByte(CMD_CLEARCMD, REG_MCMD);
    RJGT102_I2cWriteByte(ByteData, REG_MEMBUF);
    RJGT102_I2cWriteByte(Addr, REG_TAd);
    RJGT102_I2cWriteByte(CMD_WRITE, REG_MCMD);
	
    return (RJGT102_GetExecutionStatus());
}

/**
 ***************************************************************************
 * @brief  从指定的控制寄存器(地址范围：0xA0-0xAF)读出1字节数据
 * @param  [IN]  Addr 	    指定待读出地址	 
 *         [OUT] pByteData  指向待读出字节数据存储区
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_ReadCtrlReg(uint8_t Addr, uint8_t *pByteData)
{
    ExecutionStatus_t ExecutionStatus;
	
    RJGT102_I2cWriteByte(CMD_CLEARCMD, REG_MCMD);
    RJGT102_I2cWriteByte(Addr, REG_TAd);
    RJGT102_I2cWriteByte(CMD_READ, REG_MCMD);

    ExecutionStatus = RJGT102_GetExecutionStatus();
    if (ES_NORMAL == ExecutionStatus)
    {
        RJGT102_I2cReadByte(pByteData, REG_MEMBUF);
    }
	
    return ExecutionStatus;
}

/**
 ***************************************************************************
 * @brief  向指定的目的PAGEx(x=0-3)认证写入32字节数据
 * @param  [IN] SrcPageAddr  指定参与MAC计算的源PAGE地址	 
 *         [IN] DstPageAddr  指定待写入的目的PAGE地址
 *         [IN] pPageBuf     指向待写入的32字节PAGE数据(注意:数据低8字节作为
 *                           随机数数据,参与MAC计算，软、硬件计算MAC时必须同
 *                           步将它作为当次随机数)
 *         [IN] pMacBuf	     指向待写入的32字节MAC数据(此MAC由软件计算所得，
 *                           写入芯片内部作比较认证，相等方可将数据写入目的
 *                           PAGE区，否则报错)
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_WritePage(uint8_t SrcPageAddr, uint8_t DstPageAddr, const uint8_t *pPageBuf, const uint8_t *pMacBuf)
{
    uint8_t DataBuf[32];
	
    RJGT102_I2cWriteByte(CMD_CLEARCMD, REG_MCMD);
	
    memcpy(DataBuf, pPageBuf, 32);
    RJGT102_I2cWrite(REG_MEMBUF, DataBuf, 32); 
    
    memcpy(DataBuf, pMacBuf, 32);
    RJGT102_I2cWrite(REG_MACBUF, DataBuf, 32);
	
    RJGT102_I2cWriteByte(SrcPageAddr, REG_TAr);
    RJGT102_I2cWriteByte(DstPageAddr, REG_TAd);
    RJGT102_I2cWriteByte(CMD_WRITE, REG_MCMD);
	
    return (RJGT102_GetExecutionStatus());
}

/**
 ***************************************************************************
 * @brief  从指定的目的PAGEx(x=0-3)认证读出数据
 * @param  [IN]  SrcPageAddr  指定参与MAC计算的源PAGE地址 
 *         [IN]  DstPageAddr  指定待读出的目的PAGE地址  
 *         [IN]  pRngBuf      指向参与MAC计算的8字节随机数存储区
 *         [IN]  pMacBuf      指向待写入的32字节MAC数据(此MAC由软件计算所得，
 *                            写入芯片内部作比较认证，相等时才允许从PAGE区读
 *                            出数据，否则报错
 *         [OUT] pPageBuf     指向读出的PAGE数据存储区
 *         [IN]  LenOfPage    指定待读出的数据长度
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_ReadPage(uint8_t SrcPageAddr,
                                   uint8_t DstPageAddr,
                                   const uint8_t *pRngBuf,
                                   const uint8_t *pMacBuf,
                                   uint8_t *pPageBuf,
                                   uint8_t LenOfPage)
{
    ExecutionStatus_t ExecutionStatus;
    uint8_t i;
    uint8_t TmpReg;
    uint8_t DataBuf[32];
	
    RJGT102_I2cWriteByte(CMD_CLEARCMD, REG_MCMD);
	
    memcpy(DataBuf, pRngBuf, 8);
    RJGT102_I2cWrite(REG_MEMBUF, DataBuf, 8);
	
    memcpy(DataBuf, pMacBuf, 32);
    RJGT102_I2cWrite(REG_MACBUF, DataBuf, 32);
	
    RJGT102_I2cWriteByte(SrcPageAddr, REG_TAr);
    RJGT102_I2cWriteByte(DstPageAddr, REG_TAd);
    RJGT102_I2cWriteByte(CMD_READ, REG_MCMD);
	
    ExecutionStatus = RJGT102_GetExecutionStatus();
    if (ES_NORMAL == ExecutionStatus)
    {
        RJGT102_I2cRead(REG_MEMBUF, pPageBuf, LenOfPage);
        ExecutionStatus = RJGT102_ReadCtrlReg(REG_WDGRSTCTRL, &TmpReg);
        if (ES_NORMAL == ExecutionStatus)
        {
            if (0x00 == (TmpReg & SHA_RD_BYPASS))
            {
                for (i = 0; i < LenOfPage; i++)
                {
                    pPageBuf[i] ^= pMacBuf[i]; 
                }
            } 	
        }
    }
	
    return ExecutionStatus;
}

/**
 ***************************************************************************
 * @brief  看门狗初始化
 * @param  [IN] Period          复位周期(范围：0x000000-0xFFFFFF)
 *         [IN] RstSignalWidth  复位有效信号宽度(范围：0x000000-0xFFFFFF)
 *         [IN] RstPolarity     复位信号极性 @ref WDG_RstPolarity_t
 *                              @arg LOW_VALID   复位信号低有效
 *                              @arg HIGH_VALID  复位信号高有效
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_WdogInit(uint32_t Period, uint32_t RstSignalWidth, WDG_RstPolarity_t RstPolarity)
{
    ExecutionStatus_t ExecutionStatus;
    uint8_t RegAddr;
    uint8_t TmpReg;
    uint8_t i;

    for (i = 0; i < 3; i++)
    {		
        TmpReg = (uint8_t)((Period >> 8*i) & 0xFF);
        RegAddr = REG_WDGCNT + i;
        ExecutionStatus = RJGT102_WriteCtrlReg(RegAddr, TmpReg);
        if (ES_NORMAL != ExecutionStatus)
        {
            goto RetExeStatus;
        }
        TmpReg = (uint8_t)((RstSignalWidth >> 8*i) & 0xFF);
        RegAddr = REG_RSTCNT + i;
        ExecutionStatus = RJGT102_WriteCtrlReg(RegAddr, TmpReg);
        if (ES_NORMAL != ExecutionStatus)
        {
            goto RetExeStatus;
        }
    }
	
    ExecutionStatus = RJGT102_ReadCtrlReg(REG_WDGRSTCTRL, &TmpReg);
    if (ES_NORMAL == ExecutionStatus)
    {
        TmpReg &= ~(RST_POLARITY | RST_EN_N);
        if (HIGH_VALID == RstPolarity)
        {
            TmpReg |= RST_POLARITY;
        }
        ExecutionStatus = RJGT102_WriteCtrlReg(REG_WDGRSTCTRL, TmpReg);
    }

RetExeStatus:	
    return ExecutionStatus;
}

/**
 ***************************************************************************
 * @brief  看门狗控制
 * @param  [IN] NewState  看门狗控制状态
 *                        @arg WDG_ENABLE   看门狗启动
 *                        @arg WDG_DISABLE  看门狗停止 
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_WdogCmd(WDG_CtrlState_t NewState)
{
    ExecutionStatus_t ExecutionStatus;
    uint8_t TmpReg;
    uint8_t TmpReg1;

    RJGT102_I2cRead(REG_SYSCTRL, &TmpReg1, 1);
    ExecutionStatus = RJGT102_ReadCtrlReg(REG_WDGRSTCTRL, &TmpReg);
    if (ES_NORMAL == ExecutionStatus)
    {
        TmpReg1 &= ~WDOG_EN_REG; 
        TmpReg &= ~WDOG_EN;
        if (WDG_DISABLE != NewState)
        {	
            TmpReg |= WDOG_EN;
            TmpReg1 |= WDOG_EN_REG;
        }
        ExecutionStatus = RJGT102_WriteCtrlReg(REG_WDGRSTCTRL, TmpReg);
        if (ES_NORMAL == ExecutionStatus)
        {
            RJGT102_I2cWriteByte(TmpReg1, REG_SYSCTRL);
        }
    }
	
    return ExecutionStatus;
}

/**
 ***************************************************************************
 * @brief  看门狗喂狗
 * @param  无
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_WdogFeed(void)
{
    return (RJGT102_WdogCmd(WDG_ENABLE)); 
}

/**
 ***************************************************************************
 * @brief  读取芯片REG_USID用户ID
 * @param  [OUT] pUsidBuf  指向存放8字节用户ID的数据缓冲区
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_ReadUsid(uint8_t *pUsidBuf)
{
    ExecutionStatus_t ExecutionStatus;
	
    RJGT102_I2cWriteByte(CMD_CLEARCMD, REG_MCMD);
    RJGT102_I2cWriteByte(REG_USID, REG_TAd);
    RJGT102_I2cWriteByte(CMD_READ, REG_MCMD);

    ExecutionStatus = RJGT102_GetExecutionStatus();
    if (ES_NORMAL == ExecutionStatus)
    {
        RJGT102_I2cRead(REG_MEMBUF, pUsidBuf, 8);	
    }
	
    return ExecutionStatus;
}

/**
 ***************************************************************************
 * @brief  将指定区域设置保护
 * @param  [IN] Addr  指明待保护区域的地址
 *         @arg PAGExPRO(x=0-3)  PAGEx区设保护
 *         @arg KEYPRO           KEY区设保护
 *         @arg UIDPRO           REG_USID区设保护
 *         @arg PRT_CTRL         控制寄存器区(0xA0~0xA6)设保护
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_SetProtection(uint8_t Addr)
{
    RJGT102_WriteCtrlReg(Addr, REGIONAL_PROTECTION_CODE);
	
    return (RJGT102_GetExecutionStatus());
}

/**
 ***************************************************************************
 * @brief  获取芯片版本号
 * @param  [IN] pVersionBuf  指向存储4字节版本号的缓冲区
 * @retval 无
 ***************************************************************************
 */
void RJGT102_GetVersion(uint8_t *pVersionBuf)
{
    RJGT102_I2cRead(REG_VERSION0, pVersionBuf, 4);
}

/**
 ***************************************************************************
 * @brief  检测是否是我司版保芯片
 * @param  无
 * @retval 返回状态值
 *         @arg 0x00  表示不是或没有找到我司芯片
 *         @arg 0x01  表示是我司芯片
 ***************************************************************************
 */
uint8_t RJGT102_CheckVersion(void)
{
    const uint8_t Version[4] = {0x32, 0x30, 0x84, 0x71};
    uint8_t VersionBuf[4] = {0};

    RJGT102_I2cRead(REG_VERSION0, VersionBuf, 4);
	
    return (!memcmp(VersionBuf, Version, 4));
}

/**
 ***************************************************************************
 * @brief  读PAGE时，输出模式配置
 * @param  [IN] mode @ref PageOutputMode_t
 *         @arg PAGE_ENCRYPT_OUTPUT  读PAGE时，加密输出	
 *         @arg PAGE_DIRECT_OUTPUT   读PAGE时，直接输出
 * @retval 返回状态值 @ref ExecutionStatus_t
 ***************************************************************************
 */
ExecutionStatus_t RJGT102_ConfigReadPageMode(PageOutputMode_t mode)
{	
    ExecutionStatus_t ExecutionStatus;
    uint8_t TmpReg;

    ExecutionStatus = RJGT102_ReadCtrlReg(REG_WDGRSTCTRL, &TmpReg);

    if (ES_NORMAL == ExecutionStatus)
    {
        if (PAGE_ENCRYPT_OUTPUT != mode)
        {
            TmpReg |= SHA_RD_BYPASS;
        }
        else
        {
            TmpReg &= ~SHA_RD_BYPASS;
        }

        ExecutionStatus = RJGT102_WriteCtrlReg(REG_WDGRSTCTRL, TmpReg);	
    }
	
    return ExecutionStatus;
}

