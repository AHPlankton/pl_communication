
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "cJSON.h"

#define mm2s_ctrl_reg 0x00
#define mm2s_status_reg 0x04
#define mm2s_source_addr_reg 0x18
#define mm2s_length_reg 0x28

#define s2mm_ctrl_reg 0x30
#define s2mm_status_reg 0x34
#define s2mm_dest_addr_reg 0x48
#define s2mm_length_reg 0x58

#define source_address 0x10000000
#define destination_address 0x20000000
//#define transfer_length 8

#define axi_lite_test_addr 0x40000000

unsigned int dma_write(unsigned int* dma_dma_reg_addr, int reg_offset, unsigned int value);
unsigned int dma_read(unsigned int* dma_dma_reg_addr, int reg_offset);
void read_data(void* adress, int byte_length);
void dma_status_read(unsigned int* dma_dma_reg_addr);
int dma_s2mm_idle(unsigned int* dma_dma_reg_addr);
int dma_mm2s_idle(unsigned int* dma_dma_reg_addr);
void load_data(void* adress, int byte_length);

struct addr_cfg{
	unsigned int axi_lite_addr;
	unsigned int mmap_src_addr;
	unsigned int mmap_dst_addr;
    unsigned int transfer_length;
};

#define JSON_KEY_NAME_AXI_LITE_ADDR			"axi_lite_addr"
#define JSON_KEY_NAME_MMAP_SRC_ADDR			"mmap_src_addr"
#define JSON_KEY_NAME_MMAP_DST_ADDR			"mmap_dst_addr"
#define JSON_KEY_NAME_TRANSFER_LENGTH		"transfer_length"

static struct addr_cfg addrCfg = {0};

static int loadCfg()
{
	int ret = 0;
	struct stat st = {0};
	char* cfgBuf = 0;
	int nRead = 0;
	cJSON* jsonCfg = 0;
	cJSON* item = NULL;
	int fd = -1;
	long axi_lite_addr = 0;
	long mmap_src_addr = 0;
	long mmap_dst_addr = 0;
    long transfer_len = 8;

	printf("loading cfg\r\n");

	fd = open("addr_cfg.json", O_RDONLY);

	if(fd <= 0)
	{
		printf("cfg not exist\r\n");
		return ret;
	}

	if(stat("addr_cfg.json", &st) < 0)
		return ret;

	cfgBuf = malloc(st.st_size);
	nRead = read(fd, cfgBuf, st.st_size);
	if(nRead != st.st_size)
	{
		printf("read cfg fail\r\n");
	}

	jsonCfg = cJSON_Parse(cfgBuf);
	if(0 == jsonCfg){
		printf("json parse fail\r\n");
		return ret;
	}

	free(cfgBuf);
	close(fd);

	item = cJSON_GetObjectItem(jsonCfg, JSON_KEY_NAME_AXI_LITE_ADDR);
	if(0 == item || cJSON_String != item->type)
	{
		printf("cfg:axi_lite_addr not found\r\n");
		cJSON_Delete(jsonCfg);
		return ret;
	}

	axi_lite_addr = strtol(item->valuestring, NULL, 16);
	printf("cfg:axi_lite_addr:0x%8x\r\n", axi_lite_addr);
	addrCfg.axi_lite_addr = (unsigned int)axi_lite_addr;

	item = cJSON_GetObjectItem(jsonCfg, JSON_KEY_NAME_MMAP_SRC_ADDR);
	if(0 == item || cJSON_String != item->type)
	{
		printf("cfg:mmap_src_addr not found\r\n");
		cJSON_Delete(jsonCfg);
		return ret;
	}

	mmap_src_addr = strtol(item->valuestring, NULL, 16);
	printf("cfg:mmap_src_addr:0x%8x\r\n", mmap_src_addr);
	addrCfg.mmap_src_addr = (unsigned int)mmap_src_addr;

	item = cJSON_GetObjectItem(jsonCfg, JSON_KEY_NAME_TRANSFER_LENGTH);
	if(0 == item || cJSON_String != item->type)
	{
		printf("cfg:transfer_length not found, setting default:8\r\n");
        addrCfg.transfer_length = transfer_len;
		cJSON_Delete(jsonCfg);
		return ret;
	}

	transfer_len = strtol(item->valuestring, NULL, 10);
	printf("cfg:transfer_length:%d\r\n", transfer_len);
	addrCfg.transfer_length = (unsigned int)transfer_len;

	cJSON_Delete(jsonCfg);
	return 1;
}

int main() {
	int* addrUser = 0;

	if(loadCfg() <= 0)
	{
		printf("load cfg fail\r\n");
		return;
	}

    int dh = open("/dev/mem", O_RDWR | O_SYNC);
    unsigned int* dma_reg_addr = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, addrCfg.axi_lite_addr); // AXI Lite address
    unsigned int* dma_source_addr  = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, addrCfg.mmap_src_addr); // MM2S SOURCE address
    //unsigned int* dma_distination_addr = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, addrCfg.mmap_dst_addr); // S2MM DESTINATION address

	printf("running AXI DMA...\r\n Source address : 0x%x  \t\t Destination address: 0x%x\r\n",addrCfg.mmap_src_addr,addrCfg.mmap_dst_addr);
	printf("mmap_reg_addr:0x%x\r\n", dma_reg_addr);
	printf("mmap_src_addr:0x%x\r\n", dma_source_addr);
	//printf("mmap_dst_addr:0x%x\r\n", dma_distination_addr);

	addrUser = dma_source_addr;

	//load_data(dma_source_addr,transfer_length);
    //reset the channels
    //dma_write(dma_reg_addr, s2mm_ctrl_reg, 4);
    
    //dma_write(dma_reg_addr, s2mm_dest_addr_reg, addrCfg.mmap_dst_addr); // Write destination address

    int iterLen = addrCfg.transfer_length / 4;
    for(int j = 0; j < iterLen; j += 2){
        addrUser[j] = 0x12345678 + j * 4;
        addrUser[j + 1] = addrUser[j] + 4;

        //printf("writing:0x%x, 0x%x\r\n", addrUser[0], addrUser[1]);
    }

	for(int i = 0; i < 1; ++i)
	{
		//dma_write(dma_reg_addr, s2mm_ctrl_reg, 0);
		dma_write(dma_reg_addr, mm2s_ctrl_reg, 4);

		//halt the channels
		//dma_write(dma_reg_addr, s2mm_ctrl_reg, 0);
		dma_write(dma_reg_addr, mm2s_ctrl_reg, 0);


		// set source and destination addresses
		dma_write(dma_reg_addr, mm2s_source_addr_reg, addrCfg.mmap_src_addr); // Write source address

		

		//Mask interrupts
		//dma_write(dma_reg_addr, s2mm_ctrl_reg, 0xf001);
		dma_write(dma_reg_addr, mm2s_ctrl_reg, 0xf001);

		// set transfer length
    	//dma_write(dma_reg_addr, s2mm_length_reg, transfer_length);
    	dma_write(dma_reg_addr, mm2s_length_reg, addrCfg.transfer_length);

		printf("started dma transfer\r\n");
		dma_status_read(dma_reg_addr);


		// wait for idle bit
		dma_mm2s_idle(dma_reg_addr);
		//dma_s2mm_idle(dma_reg_addr);
		printf("dma transfer completed\r\n");
		dma_status_read(dma_reg_addr);
	}
	

    //printf("data at destination address 0x%x: ",dma_distination_addr);
	//read_data(dma_distination_addr, transfer_length);

	printf("\r\n\r\n");
}

unsigned int dma_write(unsigned int* dma_dma_reg_addr, int reg_offset, unsigned int value)
{
    dma_dma_reg_addr[reg_offset>>2] = value;
}

unsigned int dma_read(unsigned int* dma_dma_reg_addr, int reg_offset)
{
    return dma_dma_reg_addr[reg_offset>>2];
}

int dma_mm2s_idle(unsigned int* dma_dma_reg_addr)
{
    unsigned int mm2s_status =  dma_read(dma_dma_reg_addr, mm2s_status_reg);
    while(!(mm2s_status & 0x02) )
	{
        mm2s_status =  dma_read(dma_dma_reg_addr, mm2s_status_reg);
    }
}

int dma_s2mm_idle(unsigned int* dma_dma_reg_addr)
{
    unsigned int s2mm_status = dma_read(dma_dma_reg_addr, s2mm_status_reg);
    while(!(s2mm_status & 0x02)){
        s2mm_status = dma_read(dma_dma_reg_addr, s2mm_status_reg);
    }
}

void dma_status_read(unsigned int* dma_dma_reg_addr)
{
    unsigned int status;
	//status = dma_read(dma_dma_reg_addr, s2mm_status_reg);
    //printf("S2MM status reg:0x%x(offset:0x%x)\n", status, s2mm_status_reg);

    status = dma_read(dma_dma_reg_addr, mm2s_status_reg);
	printf("MM2S status reg:0x%x(offset:0x%x)\n", status, mm2s_status_reg);

}

void read_data(void* adress, int byte_length)
{
    int *addr = adress;
    int reg_offset;
    for (reg_offset = 0; reg_offset < byte_length/4; reg_offset+=4) {
        printf("%x\t", addr[reg_offset]);
    }
    printf("\n");
}
void load_data(void* adress, int byte_length)
{
    int *addr = adress;
    int reg_offset;
    for (reg_offset = 0; reg_offset < byte_length/4; reg_offset+=4) {
		addr[reg_offset]=0x12345678+reg_offset;
        printf("%x\t", addr[reg_offset]);
    }
    printf("\n");
}
