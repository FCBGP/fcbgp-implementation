/********************************************************************************
 * File Name:    nftutils.h
 * Author:       basilguo@163.com
 * Created Time: 2023-12-19 09:34:37
 * Description:  nft filter chain rule
 ********************************************************************************/

#ifndef NFTUTILS_H
#define NFTUTILS_H

enum
{
    FC_NFT_FILTER_CHAIN_START,
    FC_NFT_FILTER_CHAIN_INPUT = 0,
    FC_NFT_FILTER_CHAIN_FORWARD,
    FC_NFT_FILTER_CHAIN_OUTPUT,
    FC_NFT_FILTER_CHAIN_END,
};

// extern const char g_fc_nft_chains[FC_NFT_FILTER_CHAIN_END][20];
const char g_fc_nft_chains[FC_NFT_FILTER_CHAIN_END][20] = {"input", "forward",
                                                           "output"};

#endif // NFTUTILS_H
