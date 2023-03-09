//RJGT102.c

#include "typedef.h"
#include "rjgt102_cmd.h"
#include "rjgt102_sha256.h"
#include "rjgt102_security.h"

#define ENCRYPT_AUTH     0x100001
#define ENCRYPT_READ     0x100002
#define ENCRYPT_WRITE    0x100003
#define ENCRYPT_INIT_KEY 0x100004
#define ENCRYPT_INIT_UID 0x100005
#define WDG_ON_OFF       0x100006
#define WDG_FEED         0x100007

struct WdgSet {
	uint8_t en;
	uint16_t xms;
};

struct SecurityCertificate {

	uint8_t  key[8];
	uint8_t  password[32];
};

struct SecurityReadWrite{

	uint8_t  key[8];
	uint8_t  usid[8];
	uint8_t  password[32];

	uint8_t  page_id;
	uint8_t  page_data[32];
};

static uint8_t gbUsidBuf[8] =
{0};

static wait_queue_head_t	pro_wait;

static int major;
static struct class *class;
static struct i2c_client *rjgt102_client;
static struct semaphore sema;
static I2C_Driver_t I2cDriver;


/**@brief 全局变量定义区
 *
 *@note  demo演示前，请将下面gbKeyBuf[8]、gbPageBuf[32]的数
 *       据修改成与版保芯片内部KEY、PAGE0区的数据一致
 */

//not required init and close
static void I2C_Init(void){;}
static void I2C_Close(void){;}
static void I2C_ReadByte(uint8_t *pByteData, uint8_t AddrToRead)
{
    i2c_master_send(rjgt102_client, &AddrToRead, 1);
    i2c_master_recv(rjgt102_client, pByteData, 1);
}

static void I2C_WriteByte(uint8_t ByteData, uint8_t AddrToWrite)
{
	uint8_t buffer[] = {AddrToWrite, ByteData};
    i2c_master_send(rjgt102_client, buffer, sizeof(buffer));
}

static void I2C_ReadBuffer(uint8_t AddrToRead, uint8_t *pData, uint16_t Length)
{
	while(Length--)
	{
		I2C_ReadByte(pData, AddrToRead);
		AddrToRead++;
		pData++;
	}
}

static void I2C_WriteBuffer(uint8_t AddrToWrite, uint8_t *pData, uint16_t Length)
{
	while(Length--)
	{
		I2C_WriteByte(*pData, AddrToWrite);
		AddrToWrite++;
		pData++;
	}
}

static long rjgt102_ioctl(struct file *filp,unsigned int cmd, unsigned long argp)
{
	SecurityContext_t SecurityCtx;
	struct SecurityCertificate auth;
	struct SecurityReadWrite info;

	//解析处理用户命令

	switch(cmd)
	{
		case ENCRYPT_AUTH:
			{
				if(copy_from_user(&auth, (u8*)argp, sizeof(struct SecurityCertificate)) != 0)
					return -1;

				SecurityCtx.SrcPage = REG_PAGE0;
				SecurityCtx.DstPage = REG_PAGE1;
				SecurityCtx.pKeyBuf = (uint8_t *)auth.key;
				SecurityCtx.pPageBuf = (uint8_t *)auth.password;
				SecurityCtx.pUsidBuf = (uint8_t *)gbUsidBuf;

				if(!RJGT102_SecurityCertificate(&SecurityCtx))
					return -1;
			}
			break;
		case ENCRYPT_READ:
			{
				if(copy_from_user(&info, (u8*)argp, sizeof(struct SecurityReadWrite)) != 0)
					return -1;

				SecurityCtx.SrcPage = REG_PAGE0;
				SecurityCtx.DstPage = info.page_id == 3 ? REG_PAGE3 : info.page_id == 2 ? REG_PAGE2 : info.page_id == 1 ?REG_PAGE1:REG_PAGE0;
				SecurityCtx.pKeyBuf = (uint8_t *)info.key;
				SecurityCtx.pPageBuf = (uint8_t *)info.password;
				SecurityCtx.pUsidBuf = (uint8_t *)gbUsidBuf;

				if(!RJGT102_SecurityRead(&SecurityCtx, info.page_data, 32))
					return -1;

				if(copy_to_user((u8*)argp, &info, sizeof(struct SecurityReadWrite)) != 0)
					return -1;
			}
			break;
		case ENCRYPT_WRITE:
			{
				if(copy_from_user(&info, (u8*)argp, sizeof(struct SecurityReadWrite)) != 0)
					return -1;

				SecurityCtx.SrcPage = REG_PAGE0;
				SecurityCtx.DstPage = info.page_id == 3 ? REG_PAGE3 : info.page_id == 2 ? REG_PAGE2 : info.page_id == 1 ?REG_PAGE1:REG_PAGE0;
				SecurityCtx.pKeyBuf = (uint8_t *)info.key;
				SecurityCtx.pPageBuf = (uint8_t *)info.password;
				SecurityCtx.pUsidBuf = (uint8_t *)gbUsidBuf;

				if(!RJGT102_SecurityWrite(&SecurityCtx, info.page_data))
					return -1;
			}
			break;
		case ENCRYPT_INIT_KEY:
			if(copy_from_user(&info, (u8*)argp, sizeof(struct SecurityReadWrite)) != 0);
			SecurityCtx.pKeyBuf = (uint8_t *)info.key;
			RJGT102_InitKey(SecurityCtx.pKeyBuf);
			break;
		case ENCRYPT_INIT_UID:
			if(copy_from_user(&info, (u8*)argp, sizeof(struct SecurityReadWrite)) != 0);
			SecurityCtx.pUsidBuf = (uint8_t *)info.usid;
			RJGT102_InitUsid(SecurityCtx.pUsidBuf);
			RJGT102_ReadUsid((uint8_t *)gbUsidBuf);
			break;
#if 0
		case WDG_ON_OFF:
			if(copy_from_user(&wdgset, (u8*)argp, sizeof(struct wdgset)) != 0);
			if(wdgset.en)
				RJGT102_WdogInit(wdgset.xms*4000, 10, 1);

				RJGT102_WdogCmd(wdgset.en?WDG_ENABLE:WDG_DISABLE);
			break;
		case WDG_FEED:
			RJGT102_WdogFeed();
			break;
#endif
		default:
			return -1;
	}

	return 0; //成功返回0，失败返回-1
}

static int rjgt102_open(struct inode *inode, struct file *file)
{
	if(down_trylock(&sema))
		return -EBUSY;

	return 0;
}

static int rjgt102_release(struct inode *inode, struct file *file)
{
	up(&sema);

	return 0;
}


static struct file_operations rjgt102_fops = {
	.owner = THIS_MODULE,
	.open = rjgt102_open,
	.release = rjgt102_release,
	.unlocked_ioctl = rjgt102_ioctl,
};

static int  rjgt102_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	rjgt102_client = client;

	/* 版保芯片I2C驱动注册 */
	I2cDriver.Open      = I2C_Init;
	I2cDriver.Close     = I2C_Close;
	I2cDriver.ReadByte  = I2C_ReadByte;
	I2cDriver.WriteByte = I2C_WriteByte;
	I2cDriver.Read      = I2C_ReadBuffer;
	I2cDriver.Write     = I2C_WriteBuffer;
	RJGT102_I2cDriverRegister(&I2cDriver);

	/* 版保芯片初始化 */
	if(!RJGT102_SecurityInit())
	{
		printk("RJGT102_SecurityInit Error\n");
		return -1;
	}

	if(RJGT102_ReadUsid(gbUsidBuf) != ES_NORMAL)
	{
		printk("RJGT102_ReadUsid Error\n");
		return -1;
	}
	//int i;
	//printk("zlei:usid:\n");
	//for(i=0;i<8;i++){
	//	printk("0x%x ", gbUsidBuf[i]);
	//}
	//printk("\n");
	major = register_chrdev(0, "rjgt102", &rjgt102_fops);
	class = class_create(THIS_MODULE, "rjgt102");
	device_create(class, NULL, MKDEV(major, 0), NULL, "SDR-secure-1");

	return 0;
}

static int  rjgt102_remove(struct i2c_client *client)
{
	device_destroy(class, MKDEV(major, 0));
	class_destroy(class);
	unregister_chrdev(major, "rjgt102");
	return 0;
}

//1.分配 设置i2c_driver
static struct i2c_device_id rjgt102_id_table[] = {
	{"rjgt102", 0},
	{}
};
static const struct of_device_id rjgt102_of_match[] = {
	{ .compatible = "rjgt102", },
	{ },
};
static struct i2c_driver rjgt102_driver = {
	.driver = {
		.name = "rjgt102",
		.of_match_table = of_match_ptr(rjgt102_of_match),
	},
	.probe = rjgt102_probe,
	.remove = rjgt102_remove,
	.id_table = rjgt102_id_table,
};


static int __init rjgt102_drv_init(void)
{
	//注册i2c_driver
	i2c_add_driver(&rjgt102_driver);
	//初始化信号量
	sema_init(&sema, 1);
	init_waitqueue_head(&pro_wait);

	return 0;
}


static void __exit rjgt102_drv_exit(void)
{
	i2c_del_driver(&rjgt102_driver);
}

module_init(rjgt102_drv_init);
module_exit(rjgt102_drv_exit);
MODULE_LICENSE("GPL");

