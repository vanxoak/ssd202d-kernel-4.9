/**
 **************************************************************************************
 *                Copyright(c) 2015 Wuhan Runjet, All rights reserved.
 **************************************************************************************
 * @file     rjgt102_security.c
 * @author   Wuhan Runjet software and test team
 * @date     04-Feb-2015
 * @version  V1.00
 * @brief    版保芯片安全访问功能实现
 **************************************************************************************
 *
 */
#include "rjgt102_security.h"


/**
 ***************************************************************************
 * @brief  检测CPU的端模式
 * @param  无
 * @retval 返回值：
 *         @arg 0x00  -小端模式
 *         @arg 0x01  -大端模式
 ***************************************************************************
 */
static uint8_t CheckCpuEndian(void)
{
	uint32_t x = 0x04030201;
	
	return (*(uint8_t*)&x == 0x01) ?(0x00):(0x01);
}


/**
 ***************************************************************************
 * @brief  主控端计算消息认证码MAC
 * @note   将8字节密钥数据、32字节PAGE数据、8字节用户ID数据、8字节随机数、
 *         8字节常数据组成一个64字节消息块进行哈希计算输出32字节MAC
 * @param  [IN]  pSecurityCtx  指向安全上下文变量 @ref SecurityContext_t
 *         [IN]  pRngBuf       指向存放8字节随机数的数据区
 *         [OUT] pMacBuf       指向存储输出的32字节消息认证码MAC数据区
 * @retval 无
 ***************************************************************************
 */
static void MCU_CalculateMac(const SecurityContext_t *pSecurityCtx, const uint8_t *pRngBuf, uint8_t *pMacBuf)
{
    sha256_ctx_t ctx;
	uint8_t EndianMode;
    uint8_t i;
    uint8_t tmp;
    uint8_t MsgBuf[64];
    union convert
    {
        uint8_t byte[64];
        uint32_t word[16];
    } Msg;
    
    const uint8_t ConstData[8] = \
    {							 \
        0x80, 0x00, 0x00, 0x00,  \
        0x00, 0x00, 0x01, 0xB8   \
    };
    
    memcpy(&MsgBuf[0], pSecurityCtx->pKeyBuf, 8);
    memcpy(&MsgBuf[8], pSecurityCtx->pPageBuf, 32);
    memcpy(&MsgBuf[40], pSecurityCtx->pUsidBuf, 8);
    memcpy(&MsgBuf[48], pRngBuf, 8);
    memcpy(&MsgBuf[56], ConstData, 8);

	/*!< 检测CPU端模式 */
    EndianMode = CheckCpuEndian();
	
	/*!< CPU为小端模式 */
	if (0x00 == EndianMode)
	{
		for (i = 0; i < 14; i++)
		{
			Msg.word[15-i]  = (uint32_t)(MsgBuf[i * 4]) 	<< 24;
			Msg.word[15-i] |= (uint32_t)(MsgBuf[i * 4 + 1]) << 16;
			Msg.word[15-i] |= (uint32_t)(MsgBuf[i * 4 + 2]) << 8;
			Msg.word[15-i] |= (uint32_t)(MsgBuf[i * 4 + 3]);	
		}

		/*!< 为了与芯片内部计算结果保持一致，需要按相应顺序填充数据区 */
		Msg.word[1] = 0x00000080;
		Msg.word[0] = 0xB8010000;	
	}
	else
	{
		/*!< CPU为大端模式 */
		for (i = 0; i < 14; i++)
		{
			Msg.word[15-i]  = (uint32_t)(MsgBuf[i * 4 + 3])	<< 24;
			Msg.word[15-i] |= (uint32_t)(MsgBuf[i * 4 + 2]) << 16;
			Msg.word[15-i] |= (uint32_t)(MsgBuf[i * 4 + 1]) << 8;
			Msg.word[15-i] |= (uint32_t)(MsgBuf[i * 4]);	
		}

		/*!< 为了与芯片内部计算结果保持一致，需要按相应顺序填充数据区 */
		Msg.word[1] = 0x80000000;
		Msg.word[0] = 0x000001B8;
	}	
    
    RJGT102_sha256_init(&ctx);
    RJGT102_sha256_update(&ctx, Msg.byte, 64);
    RJGT102_sha256_final(&ctx, pMacBuf);
    
    for (i = 0; i < 16; i++)
    {
        tmp = pMacBuf[i];
        pMacBuf[i] = pMacBuf[31 - i];
        pMacBuf[31 - i] = tmp;
    }
}


/**
 ***************************************************************************
 * @brief  RJGT102安全初始化
 * @param  无
 * @retval 返回状态值：
 *         @arg 0x00  -初始化失败
 *         @arg 0x01  -初始化成功
 ***************************************************************************
 */
uint8_t RJGT102_SecurityInit(void)
{	
    ExecutionStatus_t ExecutionStatus;
    uint8_t IsOK;
	
    ExecutionStatus = RJGT102_Init();
    IsOK = (ES_NORMAL == ExecutionStatus) ? (0x01):(0x00);
	
    return IsOK;
}


/**
 ***************************************************************************
 * @brief  安全认证
 * @param  [IN] pSecurityCtx  指向安全上下文变量 @ref SecurityContext_t
 * @retval 返回状态值：
 *         @arg 0x00  -认证失败
 *         @arg 0x01  -认证成功 
 ***************************************************************************
 */
uint8_t RJGT102_SecurityCertificate(const SecurityContext_t *pSecurityCtx)
{
    ExecutionStatus_t ExecutionStatus;
    uint8_t IsOK = 0x00;
    uint8_t Mac1Buf[32] = {0};
    uint8_t Mac2Buf[32] = {0};
    uint8_t RandomBuf[8] = {0};//{0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
	
    /*!< 产生随机数 */
    RJGT102_GenerateRandom(RandomBuf);
	
    /*!< 芯片计算MAC */
    ExecutionStatus = RJGT102_AuthenticationDevice(pSecurityCtx->SrcPage, RandomBuf, Mac1Buf);

    if (ES_NORMAL == ExecutionStatus)
    {
        /*!< 主控计算MAC */
        MCU_CalculateMac(pSecurityCtx, RandomBuf, Mac2Buf);
        
        if (!memcmp(Mac1Buf, Mac2Buf, 32))
        {
            IsOK = 0x01;
        }
    }
	
    return IsOK;
}


/**
 ***************************************************************************
 * @brief  安全读PAGE区
 * @param  [IN]  pSecurityCtx  指向安全上下文变量 @ref SecurityContext_t
 *         [OUT] pPageBuf      指向读出的PAGE数据存储区
 *         [IN]  Length        指定待读出的数据长度(小于等于32字节)
 * @retval 返回状态值：
 *         @arg 0x00  -安全读失败
 *         @arg 0x01  -安全读成功 
 ***************************************************************************
 */
uint8_t RJGT102_SecurityRead(const SecurityContext_t *pSecurityCtx, uint8_t *pPageBuf, uint8_t Length)
{
    ExecutionStatus_t ExecutionStatus;
    uint8_t IsOK;
    uint8_t RandomBuf[8];
    uint8_t MacBuf[32];
    
    RJGT102_GenerateRandom(RandomBuf);	                                 		
    MCU_CalculateMac(pSecurityCtx , RandomBuf, MacBuf);
    
    ExecutionStatus = RJGT102_ReadPage(pSecurityCtx->SrcPage, pSecurityCtx->DstPage, RandomBuf, MacBuf, pPageBuf, Length);
    IsOK = (ES_NORMAL == ExecutionStatus) ? (0x01):(0x00);
    
    return IsOK;
}


/**
 ***************************************************************************
 * @brief  安全写PAGE区
 * @param  [IN] pSecurityCtx  指向安全上下文变量 @ref SecurityContext_t
 *         [IN] pPageBuf      指向待写入32字节PAGE数据缓冲区
 * @retval 返回状态值：
 *         @arg 0x00  -安全写失败
 *         @arg 0x01  -安全写成功 
 ***************************************************************************
 */
uint8_t RJGT102_SecurityWrite(const SecurityContext_t *pSecurityCtx, const uint8_t *pPageBuf)
{
    ExecutionStatus_t ExecutionStatus;
    uint8_t IsOK;
    uint8_t RandomBuf[8];
    uint8_t MacBuf[32];
    
    memcpy(RandomBuf, pPageBuf, 8);
    MCU_CalculateMac(pSecurityCtx, RandomBuf, MacBuf);
    
    ExecutionStatus = RJGT102_WritePage(pSecurityCtx->SrcPage, pSecurityCtx->DstPage, pPageBuf, MacBuf);
    IsOK = (ES_NORMAL == ExecutionStatus) ? (0x01):(0x00);
    
    return IsOK;
}


/**
 ***************************************************************************
 * @brief  主控与芯片端同步更新密钥
 * @param  [IN]  pSecurityCtx  指向安全上下文变量 @ref SecurityContext_t
 *         [OUT] pNewKeyBuf    指向新密钥缓冲区
 * @retval 返回状态值：
 *         @arg 0x00  -更新密钥失败
 *         @arg 0x01  -更新密钥成功 
 ***************************************************************************
 */
uint8_t RJGT102_SecurityUpdateKey(const SecurityContext_t *pSecurityCtx, uint8_t *pNewKeyBuf)
{
    ExecutionStatus_t ExecutionStatus;
    uint8_t IsOK = 0x00;
    uint8_t Mac1Buf[32];
    uint8_t Mac2Buf[32];
    uint8_t RandomBuf[8];
	
    /*!< 产生随机数 */
    RJGT102_GenerateRandom(RandomBuf);
	
    /*!< 芯片计算MAC */
    ExecutionStatus = RJGT102_AuthenticationDevice(pSecurityCtx->SrcPage, RandomBuf, Mac1Buf);
    if (ES_NORMAL != ExecutionStatus)
    {
        return IsOK; 
    }
	
	/*!< 主控计算MAC */
	MCU_CalculateMac(pSecurityCtx, RandomBuf, Mac2Buf);
	if (memcmp(Mac1Buf, Mac2Buf, 32))
	{
		return IsOK;
	}
	memcpy(pNewKeyBuf, Mac2Buf, 8);
    
    ExecutionStatus = RJGT102_UpdateKey(pSecurityCtx->SrcPage, RandomBuf);
    IsOK = (ES_NORMAL == ExecutionStatus) ? (0x01):(0x00);
    
    return IsOK;
}

