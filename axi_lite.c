
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
#define transfer_length 8

#define axi_lite_test_addr 0x40000000

struct addr_cfg{
	unsigned int axi_lite_addr;
	unsigned int mmap_src_addr;
	unsigned int mmap_dst_addr;
};

#define JSON_KEY_NAME_AXI_LITE_ADDR			"axi_lite_addr"
#define JSON_KEY_NAME_MMAP_SRC_ADDR			"mmap_src_addr"
#define JSON_KEY_NAME_MMAP_DST_ADDR			"mmap_dst_addr"

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

	item = cJSON_GetObjectItem(jsonCfg, JSON_KEY_NAME_MMAP_DST_ADDR);
	if(0 == item || cJSON_String != item->type)
	{
		printf("cfg:axi_lite_addr not found\r\n");
		cJSON_Delete(jsonCfg);
		return ret;
	}

	mmap_dst_addr = strtol(item->valuestring, NULL, 16);
	printf("cfg:mmap_dst_addr:0x%8x\r\n", mmap_dst_addr);
	addrCfg.mmap_dst_addr = (unsigned int)mmap_dst_addr;

	cJSON_Delete(jsonCfg);
	return 1;
}

int main() {
	int* addrUser = 0;

	//if(loadCfg() <= 0)
    if(0)
	{
		printf("load cfg fail\r\n");
		return 1;
	}

    int dh = open("/dev/mem", O_RDWR | O_SYNC);
    unsigned int* axi_lite_test_reg_addr  = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, axi_lite_test_addr); // MM2S SOURCE address
    //unsigned int* axi_lite_test_reg_addr  = (int*)malloc(32);
    //unsigned int* dma_distination_addr = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, addrCfg.mmap_dst_addr); // S2MM DESTINATION address

    printf("mmap_axi_lite_test_reg_addr:0x%x\r\n", axi_lite_test_reg_addr);

    if(axi_lite_test_reg_addr <= 0){
        printf("mmap fail\r\n");
        return 1;
    }

    int i = 0;
    while(1){
        printf("waiting for input...(i, t, q)\r\n");
        char c = getchar();
        int quit = 0;

        switch (c)
        {
        case 'i':
            axi_lite_test_reg_addr[0] = 0;
            axi_lite_test_reg_addr[1] = 0;
            axi_lite_test_reg_addr[2] = 0;
            axi_lite_test_reg_addr[3] = 0;
            printf("init addr\r\n");
            break;

        case 't':
            axi_lite_test_reg_addr[0] = 0x12344321 + i;
            axi_lite_test_reg_addr[1] = 0x12345432 + i;
            axi_lite_test_reg_addr[2] = 0x12346543 + i;
            axi_lite_test_reg_addr[3] = 0x98765432 + i;
            ++i;
            printf("writing [0]:0x%x, [1]:0x%x, [2]:0x%x, [3]:0x%x\r\n",
            axi_lite_test_reg_addr[0], axi_lite_test_reg_addr[1],
            axi_lite_test_reg_addr[2], axi_lite_test_reg_addr[3]);
            break;

        case 'q':
            quit = 1;
            printf("quit\r\n");
            break;

        default:
            break;
        }

        if(quit)
            break;
        
        sleep(1);
    }

    //free(axi_lite_test_reg_addr);
	printf("\r\n\r\n");
    return 0;
}
