// Copyright (c) 2009-2010 Satoshi Nakamoto
// 
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);
unsigned int static DarkGravityWave(const CBlockIndex* pindexLast, const Consensus::Params& params); 
unsigned int static DarkGravityWave2(const CBlockIndex* pindexLast, const Consensus::Params& params); 
unsigned int static DarkGravityWave3(const CBlockIndex* pindexLast, const Consensus::Params& params);
unsigned int static DarkGravityWave4(const CBlockIndex* pindexLast, const Consensus::Params& params);
unsigned int static DarkGravityWave5(const CBlockIndex* pindexLast, const Consensus::Params& params);


/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);

#endif // BITCOIN_POW_H
