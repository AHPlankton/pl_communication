
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

unsigned int dma_write(unsigned int* dma_dma_reg_addr, int reg_offset, unsigned int value);
unsigned int dma_read(unsigned int* dma_dma_reg_addr, int reg_offset);
void read_data(void* adress, int byte_length);
void dma_status_read(unsigned int* dma_dma_reg_addr);
int dma_s2mm_idle(unsigned int* dma_dma_reg_addr);
int dma_mm2s_idle(unsigned int* dma_dma_reg_addr);
int load_data(void* adress, char* matData, int matSize);
void send(unsigned int* dma_reg_addr, unsigned int length);
void logSendData(int* addr, int length, int printWidth);
void sendLoop(unsigned int* dma_reg_addr, unsigned int length);

struct addr_cfg{
	unsigned int axi_lite_addr;
	unsigned int mmap_src_addr;
	unsigned int mmap_dst_addr;
};

#define JSON_KEY_NAME_AXI_LITE_ADDR			"axi_lite_addr"
#define JSON_KEY_NAME_MMAP_SRC_ADDR			"mmap_src_addr"
#define JSON_KEY_NAME_MMAP_DST_ADDR			"mmap_dst_addr"

static struct addr_cfg addrCfg = {0};
static char* matList = 0;

static int loadMat()
{
    struct stat st = {0};
    int nRead = 0;
    int fd = -1;
    char* fileContent = 0;
    int i, j;
    int countCtrl = 0;
    int matSize = 0;

    printf("loading mat\r\n");

    fd = open("mat.txt", O_RDONLY);

    if(fd <= 0)
    {
        printf("mat not exist\r\n");
        return 0;
    }

    if(stat("mat.txt", &st) < 0)
        return 0;

    fileContent = malloc(st.st_size);
    nRead = read(fd, fileContent, st.st_size);
    if(nRead != st.st_size)
    {
        printf("read mat fail\r\n");
        return 0;
    }
    else
    {
        printf("read %d bytes from mat.txt\r\n", nRead);
    }

    for(i = 0; i < nRead; ++i){
        if('0' != fileContent[i] && '1' != fileContent[i]){
            ++countCtrl;
        }
    }

    matSize = nRead - countCtrl;
    matList = malloc(matSize);

    for(i = 0, j = 0; i < nRead; ++i){
        if('0' == fileContent[i] || '1' == fileContent[i]){
            matList[j] = fileContent[i];
            ++j;
        }
    }

    free(fileContent);
    close(fd);
    return matSize;
}

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
    int matSize = 0;
    int packetSize = 0;

	if(loadCfg() <= 0)
	{
		printf("load cfg fail\r\n");
		return 1;
	}

    matSize = loadMat();
    if(matSize <= 0)
    {
        return 1;
    }

    int dh = open("/dev/mem", O_RDWR | O_SYNC);
    unsigned int* axi_lite_test_reg_addr  = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, axi_lite_test_addr); // MM2S SOURCE address
    //unsigned int* axi_lite_test_reg_addr  = (int*)malloc(32);
    //unsigned int* dma_distination_addr = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, addrCfg.mmap_dst_addr); // S2MM DESTINATION address

    printf("mmap_axi_lite_test_reg_addr:0x%x\r\n", axi_lite_test_reg_addr);

    unsigned int* dma_reg_addr = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, addrCfg.axi_lite_addr); // AXI Lite address
    unsigned int* dma_source_addr  = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, addrCfg.mmap_src_addr); // MM2S SOURCE address
    //unsigned int* dma_distination_addr = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, addrCfg.mmap_dst_addr); // S2MM DESTINATION address

	printf("running AXI DMA...\r\n Source address : 0x%x  \t\t Destination address: 0x%x\r\n",addrCfg.mmap_src_addr,addrCfg.mmap_dst_addr);
	printf("mmap_reg_addr:0x%x\r\n", dma_reg_addr);
	printf("mmap_src_addr:0x%x\r\n", dma_source_addr);
	//printf("mmap_dst_addr:0x%x\r\n", dma_distination_addr);

	addrUser = dma_source_addr;

    if(axi_lite_test_reg_addr <= 0){
        printf("mmap fail\r\n");
        return 1;
    }

    int i = 0;
    int v = 0x0;
    printf("waiting for input...(i, t, q, v, l, p)\r\n");
    while(1){
        int quit = 0;
        char c = getchar();

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

        case 'v':
            axi_lite_test_reg_addr[0] = 0;
            printf("writing [0]:0x%x\r\n", 0);
            break;

        case 'w':
            axi_lite_test_reg_addr[0] = 1;
            printf("writing [0]:0x%x\r\n", 1);
            break;
        
        case 'r':
            printf("reading [0]:0x%x, [1]:0x%x, [2]:0x%x, [3]:0x%x\r\n",
            axi_lite_test_reg_addr[0], axi_lite_test_reg_addr[1],
            axi_lite_test_reg_addr[2], axi_lite_test_reg_addr[3]);
            break;

        case 'q':
            quit = 1;
            printf("quit\r\n");
            break;

        case 'l':
            packetSize = load_data(addrUser, matList, matSize);
            break;

        case 'p':
            send(dma_reg_addr, packetSize);
            break;

        case 'c':
            axi_lite_test_reg_addr[0] = 0;
            sendLoop(dma_reg_addr, packetSize);
            axi_lite_test_reg_addr[0] = 1;
            break;

        default:
            //printf("unknown command:0x%x\r\n", c);
            continue;
            break;
        }

        if(quit)
            break;
        
        sleep(1);
        printf("waiting for input...(i, t, q, v, l, p)\r\n");
    }

    //free(axi_lite_test_reg_addr);
	printf("\r\n\r\n");
    return 0;
}

void sendLoop(unsigned int* dma_reg_addr, unsigned int length)
{
    int i = 20;

    while (i)
    {
        send(dma_reg_addr, length);
        usleep(20 * 1000);
        --i;
    }
    
}

void send(unsigned int* dma_reg_addr, unsigned int length)
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
    dma_write(dma_reg_addr, mm2s_length_reg, length);

    printf("started dma transfer, length:%d bytes\r\n", length);
    dma_status_read(dma_reg_addr);


    // wait for idle bit
    dma_mm2s_idle(dma_reg_addr);
    //dma_s2mm_idle(dma_reg_addr);
    printf("dma transfer completed\r\n");
    dma_status_read(dma_reg_addr);
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
int load_data(void* adress, char* matData, int matSize)
{
    int *addr = adress;
    int i, j;
    int columnHeight = 24;
    int addrIdx = 0;
    int matIdx = 0;
    int packetCount = 0;
    int byteCount = 0;

    packetCount = matSize / columnHeight;
    if(matSize % columnHeight != 0){
        printf("warning, column not aligned\r\n");
        ++packetCount;
    } else{
        printf("Ready for packing %d packets\r\n", packetCount);
    }

    for(i = 0; i < packetCount; ++i){
        unsigned char sig = 0;
        unsigned char size = columnHeight;

        addr[addrIdx] = 0;
        addr[addrIdx + 1] = 0;
        if(0 == i){
            sig = 1;
        }
        else if(packetCount - 1 == i){
            sig = 3;
        }
        else{
            sig = 2;
        }

        addr[addrIdx] = (sig << 22) | (size << 16);

        for(j = 0; j < columnHeight; ++j){
            if(matIdx >= matSize){
                printf("error, ending\r\n");
                break;
            }

            char inkValue = 0;
            if('0' == matData[matIdx])
                inkValue = 0;
            else
                inkValue = 1;
            
            ++matIdx;
            addr[addrIdx + 1] |= inkValue << (columnHeight - j - 1);
        }

        addrIdx += 2;

    }

    byteCount = packetCount * 8;
    printf("packet finish, idx:%d, size:%d\r\n", addrIdx, byteCount);

    logSendData(addr, byteCount / 4, 10);

    return byteCount;
}

void logSendData(int* addr, int count, int printWidth)
{
    int i, j;

    if(0 == printWidth)
        printWidth = 1;

    printf("data start from 0x%x, count:%d\r\n", addr, count);
    for(i = 0; i < count; ++i){
        printf("[%03d]0x%08x, ", i, addr[i]);
        if((i + 1) % printWidth == 0){
            printf("\r\n");
        }
    }

    printf("\r\ndata end\r\n");
    printf("extra data:\r\n");
    for(j = 0; j < printWidth; ++j){
        printf("[%03d]0x%08x, ", i + j, addr[count + j]);
    }
}
