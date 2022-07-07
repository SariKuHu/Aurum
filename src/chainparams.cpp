// Copyright (c) 2010 Satoshi Nakamoto
// 
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}


static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Aurum Crypto Gold (ACG)";
    const CScript genesisOutputScript = CScript() << ParseHex("04b7e53591afdfa175cb01c76b89addad097231fa543e706833e593960f15335b57c58887bf48b9713c406141a7c43f80b4bc73043c72e612f1e970182e3533106") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 5; // not used anymore
        consensus.BIP16Exception = uint256S("0x00000000096a33a29ab9620fad99fb18bb22ac751c12cbac5a4ac6c9ea0e1cbd");
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x00000000096a33a29ab9620fad99fb18bb22ac751c12cbac5a4ac6c9ea0e1cbd");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0; 
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 7 * 60;
        consensus.nPowTargetSpacing = 7 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 180;
        consensus.nMinerConfirmationWindow = 240;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000b166a6db72b4977");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000002b31d941c6fd380764e801fb40d8ac58e4f5ea0861bde774fc2627");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xb8;
        pchMessageStart[1] = 0xd1;
        pchMessageStart[2] = 0xc6;
        pchMessageStart[3] = 0xf2;
        nDefaultPort = 9889;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1656116051, 1029703737, 0x1d00ffff, 1, 1 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000000096a33a29ab9620fad99fb18bb22ac751c12cbac5a4ac6c9ea0e1cbd"));
        assert(genesis.hashMerkleRoot == uint256S("0xe517831cdb66db46637054f76fea6c47ee33b5f0a7a9e41cbb59faad0cdffc87"));


        vSeeds.emplace_back("node01.aurumcrypto.gold");
        vSeeds.emplace_back("node02.aurumcrypto.gold");
        vSeeds.emplace_back("node03.aurumcrypto.gold");
        vSeeds.emplace_back("node04.aurumcrypto.gold");
        vSeeds.emplace_back("45.32.74.196");
        vSeeds.emplace_back("65.20.77.146");
        vSeeds.emplace_back("95.179.212.35");
        vSeeds.emplace_back("149.28.169.149");


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,83);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,23);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,176);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "aurum";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;

        checkpointData = {
            {
                { 0, uint256S("0x00000000096a33a29ab9620fad99fb18bb22ac751c12cbac5a4ac6c9ea0e1cbd")},
                { 1, uint256S("0x000592a565d6bbd1a554ff0a7a139f14e26c7128975b64033764f256b050bd76")},
                { 16, uint256S("0x000a9aa3ddf4db17924edbb21d50cce3fc126a56ccb3d3012bdf2356d0dd6be0")},
                { 50, uint256S("0x000095d56f5f9b9998b65857ab0303692ad67bc94d0e3fdad8004edfb0fe2653")},
                { 102, uint256S("0x000003825d26096e510b31bde4449680b996d86a4184ab06a4eaaead39e46d59")},
                { 500, uint256S("0x0000000000013eea67315278410cece832243adf354cbf18c737c91ed1409eea")},
                { 1000, uint256S("0x0000000000014c6472db447928a9b417a15e46a395e9becf0a3d3168ddcd713f")},
                { 1550, uint256S("0x00000000002b31d941c6fd380764e801fb40d8ac58e4f5ea0861bde774fc2627")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats
            /* nTime    */ 1657165876,
            /* nTxCount */ 1848,
            /* dTxRate  */ 0.001777275114109141,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 0;
        consensus.BIP16Exception = uint256S("0x00000000096a33a29ab9620fad99fb18bb22ac751c12cbac5a4ac6c9ea0e1cbd");
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x00000000096a33a29ab9620fad99fb18bb22ac751c12cbac5a4ac6c9ea0e1cbd");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 1 * 60;
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 180;
        consensus.nMinerConfirmationWindow = 240;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000100010001");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000096a33a29ab9620fad99fb18bb22ac751c12cbac5a4ac6c9ea0e1cbd");

        pchMessageStart[0] = 0xb5;
        pchMessageStart[1] = 0xe1;
        pchMessageStart[2] = 0xc9;
        pchMessageStart[3] = 0xb4;
        nDefaultPort = 19889;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 15;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1656116051, 1029703737, 0x1d00ffff, 1, 1 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000000096a33a29ab9620fad99fb18bb22ac751c12cbac5a4ac6c9ea0e1cbd"));
        assert(genesis.hashMerkleRoot == uint256S("0xe517831cdb66db46637054f76fea6c47ee33b5f0a7a9e41cbb59faad0cdffc87"));

        //vFixedSeeds.clear();
        //vSeeds.clear();

        vSeeds.emplace_back("node01.aurumcrypto.gold");
        vSeeds.emplace_back("node02.aurumcrypto.gold");
        vSeeds.emplace_back("node03.aurumcrypto.gold");
        vSeeds.emplace_back("node04.aurumcrypto.gold");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,127);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,65);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,138);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x07, 0x45, 0x83, 0xCE};
        base58Prefixes[EXT_SECRET_KEY] = {0x07, 0x45, 0x87, 0x99};

        bech32_hrp = "taurum";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;


        checkpointData = {
            {
                {0, uint256S("0x00000000096a33a29ab9620fad99fb18bb22ac751c12cbac5a4ac6c9ea0e1cbd")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats
            /* nTime    */ 1656116051,
            /* nTxCount */ 0,
            /* dTxRate  */ 0,
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 0;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 0; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 0; // BIP66 activated on regtest (Used in functional tests)
        consensus.CSVHeight = 0; // CSV activated on regtest (Used in rpc activation tests)
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 1 * 60;
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000200020");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x06bc61eb7f0aae093ad27adf67f78860f0d410b03e38208b49a4215979476be9");

        pchMessageStart[0] = 0xf4;
        pchMessageStart[1] = 0xd2;
        pchMessageStart[2] = 0xb8;
        pchMessageStart[3] = 0xe0;
        nDefaultPort = 29889;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(1656115555, 1, 0x207fffff, 1, 1 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x06bc61eb7f0aae093ad27adf67f78860f0d410b03e38208b49a4215979476be9"));
        assert(genesis.hashMerkleRoot == uint256S("0xe517831cdb66db46637054f76fea6c47ee33b5f0a7a9e41cbb59faad0cdffc87"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;

        checkpointData = {
            {
                {0, uint256S("0x06bc61eb7f0aae093ad27adf67f78860f0d410b03e38208b49a4215979476be9")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,122);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,119);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "raurum";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (gArgs.IsArgSet("-segwitheight")) {
        int64_t height = gArgs.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
