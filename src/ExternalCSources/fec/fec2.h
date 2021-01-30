#ifndef FEC_2_H
#define FEC_2_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fec_parms *fec_code_t;
typedef unsigned char gf;

/*
 * create a new encoder, returning a descriptor. This contains k,n and
 * the encoding matrix.
 * n is the number of data blocks + fec blocks (matrix height)
 * k is just the data blocks (matrix width)
 */
void fec_init(void);

void fec_encode(unsigned int blockSize,
                const gf **data_blocks,
                unsigned int nrDataBlocks,
                gf **fec_blocks,
                unsigned int nrFecBlocks);

/** Documentation comes from https://github.com/DroneBridge/DroneBridge/blob/55eec5fad91a6faaaf6ac1fdd350d4db21a0435f/video/fec.c
* @param blockSize Size of packets
* @param data_blocks pointer to list of data packets
* @param nr_data_blocks number of data packets
* @param fec_blocks pointer to list of FEC packets
* @param fec_block_nos Indices of FEC packets that shall repair erased data packets in data packet list [array]
* @param erased_blocks Indices of erased data packets in FEC packet data list [array]
* @param nr_fec_blocks Number of FEC blocks used to repair data packets
*/
void fec_decode(unsigned int blockSize,
                gf **data_blocks,
                unsigned int nr_data_blocks,
                gf **fec_blocks,
                unsigned int *fec_block_nos,
                unsigned int *erased_blocks,
                unsigned short nr_fec_blocks  /* how many blocks per stripe */);

void fec_print(fec_code_t code, int width);

void fec_license(void);

#ifdef __cplusplus
}
#endif

#endif //FEC_2_H

