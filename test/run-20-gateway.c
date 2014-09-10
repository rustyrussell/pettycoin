int pettycoin_gateway_main(int argc, char *argv[]);
#define main pettycoin_gateway_main
#define TESTING
#include <ccan/tal/tal.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
struct thash;

static char *ask_process(const tal_t *ctx,
			      const char *name,
			      const char *arg1,
			      const char *arg2,
			      const char *arg3,
			      const char *arg4,
			      const char *arg5);

static int read_gateway_txs(struct thash *thash)
{
	return open("/dev/null", O_RDWR);
}

static const tal_t *top_ctx;

#define grab_file fake_grab_file

#undef sleep
static unsigned int sleeps;

static void fake_sleep(int seconds);
#define sleep fake_sleep

#include "../pettycoin-gateway.c"
#undef main
#include "../json.c"
#include "../hex.c"
#include "../base58.c"
#include <ccan/array_size/array_size.h>

/* As seen on bitcoind! */
static const char *listtxs_response[] = {
 	"    {\n"
	"        \"account\" : \"gateway\",\n"
	"        \"address\" : \"mnwYn3mP11dWvJUbyraBqYBkx8TgWSLgVn\",\n"
	"        \"category\" : \"receive\",\n"
	"        \"amount\" : 0.12340000,\n"
	"        \"confirmations\" : %u,\n"
	"        \"blockhash\" : \"00000000c2d8eace66677070d87bd5eeefba4b861d957d6e3d5843a3fad8ea39\",\n"
	"        \"blockindex\" : 74,\n"
	"        \"blocktime\" : 1407411460,\n"
	"        \"txid\" : \"22ef372217dca7d4c8fc0eb1a1201db96ae8919989918501c199f0db8f1008eb\",\n"
	"        \"walletconflicts\" : [\n"
	"        ],\n"
	"        \"time\" : 1407408263,\n"
	"        \"timereceived\" : 1407408263\n"
	"    },\n",
	"    {\n"
	"        \"account\" : \"gateway\",\n"
	"        \"address\" : \"mnwYn3mP11dWvJUbyraBqYBkx8TgWSLgVn\",\n"
	"        \"category\" : \"receive\",\n"
	"        \"amount\" : 0.01000000,\n"
	"        \"confirmations\" : %u,\n"
	"        \"blockhash\" : \"00000000d264e262ee5d23d0a8dd42f7e0ed2103dcde3440de450e734c58aab3\",\n"
	"        \"blockindex\" : 4,\n"
	"        \"blocktime\" : 1409746236,\n"
	"        \"txid\" : \"784ec506e308b070272a5a98cdcbdc7fc96d8355ddcdc7ea8a7f7d85dc95e25b\",\n"
	"        \"walletconflicts\" : [\n"
	"        ],\n"
	"        \"time\" : 1409745292,\n"
	"        \"timereceived\" : 1409745292\n"
	"    },\n",
	"    {\n"
	"        \"account\" : \"gateway\",\n"
	"        \"address\" : \"mnwYn3mP11dWvJUbyraBqYBkx8TgWSLgVn\",\n"
	"        \"category\" : \"receive\",\n"
	"        \"amount\" : 20.00000000,\n"
	"        \"confirmations\" : %u,\n"
	"        \"blockhash\" : \"000000007cd4fedeaef48e5bbd8e857b1fd7814d1620cf534c2ceaeb21e6cd92\",\n"
	"        \"blockindex\" : 2,\n"
	"        \"blocktime\" : 1409749898,\n"
	"        \"txid\" : \"28cb1254ad475eef81dbe1dad4dc519bc28441f080cbbe59d911038b5589ca2f\",\n"
	"        \"walletconflicts\" : [\n"
	"        ],\n"
	"        \"time\" : 1409746626,\n"
	"        \"timereceived\" : 1409746626\n"
	"    },\n",
	"    {\n"
	"        \"account\" : \"gateway\",\n"
	"        \"address\" : \"mnwYn3mP11dWvJUbyraBqYBkx8TgWSLgVn\",\n"
	"        \"category\" : \"receive\",\n"
	"        \"amount\" : 0.01200000,\n"
	"        \"confirmations\" : %u,\n"
	"        \"txid\" : \"8d3ad477d0be3786947927a4f8321f8a1358a5989a8ec9293138a072a530a7ac\",\n"
	"        \"walletconflicts\" : [\n"
	"        ],\n"
	"        \"time\" : 1409804379,\n"
	"        \"timereceived\" : 1409804379\n"
	"    }\n"
};

static const char *getrawtxs_response[] = {
	"{\n"
	"    \"hex\" : \"0100000001d0c7d22b067ae89eea8cf0d0c4b457b8ac5e8d98353cf2a31de9b18450847e42000000006b483045022100cef9c0db9217ce6d8a156e1d5dd175942e10b1e12691f10042cc559fa0e0b6b102206f21091657f1b3468776f0704b42667455c0bf3953c335c6b9b9598946b7838f01210375c0c2569958d8ee45fb95b71bb7c62a83439e786a78bf2e06b8842acafe9b34ffffffff0220667301000000001976a914a56a354a96da38505a5cf73a8111a345fe8da64888ac204bbc00000000001976a914516fa5f385da57cd5034fc5cf4aa1c34762f4b8188ac00000000\",\n"
	"    \"txid\" : \"22ef372217dca7d4c8fc0eb1a1201db96ae8919989918501c199f0db8f1008eb\",\n"
	"    \"version\" : 1,\n"
	"    \"locktime\" : 0,\n"
	"    \"vin\" : [\n"
	"        {\n"
	"            \"txid\" : \"427e845084b1e91da3f23c35988d5eacb857b4c4d0f08cea9ee87a062bd2c7d0\",\n"
	"            \"vout\" : 0,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3045022100cef9c0db9217ce6d8a156e1d5dd175942e10b1e12691f10042cc559fa0e0b6b102206f21091657f1b3468776f0704b42667455c0bf3953c335c6b9b9598946b7838f01 0375c0c2569958d8ee45fb95b71bb7c62a83439e786a78bf2e06b8842acafe9b34\",\n"
	"                \"hex\" : \"483045022100cef9c0db9217ce6d8a156e1d5dd175942e10b1e12691f10042cc559fa0e0b6b102206f21091657f1b3468776f0704b42667455c0bf3953c335c6b9b9598946b7838f01210375c0c2569958d8ee45fb95b71bb7c62a83439e786a78bf2e06b8842acafe9b34\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        }\n"
	"    ],\n"
	"    \"vout\" : [\n"
	"        {\n"
	"            \"value\" : 0.24340000,\n"
	"            \"n\" : 0,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 a56a354a96da38505a5cf73a8111a345fe8da648 OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a914a56a354a96da38505a5cf73a8111a345fe8da64888ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"mvbb2BLUhhCBttHN856eQbZSqWRXyG7Z91\"\n"
	"                ]\n"
	"            }\n"
	"        },\n"
	"        {\n"
	"            \"value\" : 0.12340000,\n"
	"            \"n\" : 1,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 516fa5f385da57cd5034fc5cf4aa1c34762f4b81 OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a914516fa5f385da57cd5034fc5cf4aa1c34762f4b8188ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"mnwYn3mP11dWvJUbyraBqYBkx8TgWSLgVn\"\n"
	"                ]\n"
	"            }\n"
	"        }\n"
	"    ],\n"
	"    \"blockhash\" : \"00000000c2d8eace66677070d87bd5eeefba4b861d957d6e3d5843a3fad8ea39\",\n"
	"    \"confirmations\" : 6665,\n"
	"    \"time\" : 1407411460,\n"
	"    \"blocktime\" : 1407411460\n"
	"}\n",
	"{\n"
	"    \"hex\" : \"0100000001cca98ada2bf54c4d4f265ec4835a454f8c3d8f99405e1e970eab44102e723558000000006a47304402202ae150ae61bdd58aca8e43be733978dee6105d97349ccd39631715218405aca9022033ea99be1761d5442eed663ce46d61fcfaf28978d1eaafb5a3f0b7363028e557012103c751f7b2879bd77f46d28474a46424b7f5d46541f4bd6f4da0b9a9489c599886ffffffff0240b12f02000000001976a9149ed926da784d43926803beb9116cbd682521cbb588ac804f1200000000001976a914174584706a570cad6dc5b08d58798558ff5727e188ac00000000\",\n"
	"    \"txid\" : \"427e845084b1e91da3f23c35988d5eacb857b4c4d0f08cea9ee87a062bd2c7d0\",\n"
	"    \"version\" : 1,\n"
	"    \"locktime\" : 0,\n"
	"    \"vin\" : [\n"
	"        {\n"
	"            \"txid\" : \"5835722e1044ab0e971e5e40998f3d8c4f455a83c45e264f4d4cf52bda8aa9cc\",\n"
	"            \"vout\" : 0,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"304402202ae150ae61bdd58aca8e43be733978dee6105d97349ccd39631715218405aca9022033ea99be1761d5442eed663ce46d61fcfaf28978d1eaafb5a3f0b7363028e55701 03c751f7b2879bd77f46d28474a46424b7f5d46541f4bd6f4da0b9a9489c599886\",\n"
	"                \"hex\" : \"47304402202ae150ae61bdd58aca8e43be733978dee6105d97349ccd39631715218405aca9022033ea99be1761d5442eed663ce46d61fcfaf28978d1eaafb5a3f0b7363028e557012103c751f7b2879bd77f46d28474a46424b7f5d46541f4bd6f4da0b9a9489c599886\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        }\n"
	"    ],\n"
	"    \"vout\" : [\n"
	"        {\n"
	"            \"value\" : 0.36680000,\n"
	"            \"n\" : 0,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 9ed926da784d43926803beb9116cbd682521cbb5 OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a9149ed926da784d43926803beb9116cbd682521cbb588ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"muzsCLFmS1A2ppe8V4Gxro89a4UvZZzgMn\"\n"
	"                ]\n"
	"            }\n"
	"        },\n"
	"        {\n"
	"            \"value\" : 0.01200000,\n"
	"            \"n\" : 1,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 174584706a570cad6dc5b08d58798558ff5727e1 OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a914174584706a570cad6dc5b08d58798558ff5727e188ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"mhe17cf9VGsZH6G6DhsGTQre9LM53qMXDs\"\n"
	"                ]\n"
	"            }\n"
	"        }\n"
	"    ],\n"
	"    \"blockhash\" : \"0000000067ef662cc1805752341636c20aabb49e9f5e5f85c96d35b6f880d362\",\n"
	"    \"confirmations\" : 8369,\n"
	"    \"time\" : 1406514281,\n"
	"    \"blocktime\" : 1406514281\n"
	"}\n",
	"{\n"
	"    \"hex\" : \"0100000001c6cbc2579808e292a6724b47f802710e0778a4a37ffe58ad867374233fcf19b9010000006b483045022100830984ea3332a8e3b4aeaa9c7b594b565a587649b1f9b1e18c19cecf24a3d606022031b43a47b704d084a8b6d48f1596927a6c1ce02cbb108fcee36baa14f4259e2a01210210945591e0b310e33f1633f0dd8f9f345ea058b3a3a29bb895a835026229b2a4ffffffff0140420f00000000001976a914516fa5f385da57cd5034fc5cf4aa1c34762f4b8188ac00000000\",\n"
	"    \"txid\" : \"784ec506e308b070272a5a98cdcbdc7fc96d8355ddcdc7ea8a7f7d85dc95e25b\",\n"
	"    \"version\" : 1,\n"
	"    \"locktime\" : 0,\n"
	"    \"vin\" : [\n"
	"        {\n"
	"            \"txid\" : \"b919cf3f23747386ad58fe7fa3a478070e7102f8474b72a692e2089857c2cbc6\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3045022100830984ea3332a8e3b4aeaa9c7b594b565a587649b1f9b1e18c19cecf24a3d606022031b43a47b704d084a8b6d48f1596927a6c1ce02cbb108fcee36baa14f4259e2a01 0210945591e0b310e33f1633f0dd8f9f345ea058b3a3a29bb895a835026229b2a4\",\n"
	"                \"hex\" : \"483045022100830984ea3332a8e3b4aeaa9c7b594b565a587649b1f9b1e18c19cecf24a3d606022031b43a47b704d084a8b6d48f1596927a6c1ce02cbb108fcee36baa14f4259e2a01210210945591e0b310e33f1633f0dd8f9f345ea058b3a3a29bb895a835026229b2a4\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        }\n"
	"    ],\n"
	"    \"vout\" : [\n"
	"        {\n"
	"            \"value\" : 0.01000000,\n"
	"            \"n\" : 0,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 516fa5f385da57cd5034fc5cf4aa1c34762f4b81 OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a914516fa5f385da57cd5034fc5cf4aa1c34762f4b8188ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"mnwYn3mP11dWvJUbyraBqYBkx8TgWSLgVn\"\n"
	"                ]\n"
	"            }\n"
	"        }\n"
	"    ],\n"
	"    \"blockhash\" : \"00000000d264e262ee5d23d0a8dd42f7e0ed2103dcde3440de450e734c58aab3\",\n"
	"    \"confirmations\" : 699,\n"
	"    \"time\" : 1409746236,\n"
	"    \"blocktime\" : 1409746236\n"
	"}\n",
	"{\n"
	"    \"hex\" : \"0100000001a011912aa82066f60c4050b25f203ea37d18ecf1a6ca1f216d144a93870c4be8010000006a47304402205e56244080cb06432a13f4d0d82d69e619cc3373f4c5f39bf9332bdea98f0fe50220637b4411bddbe9b465222df27a393b1a648419807919ad05c424ca461223dedf012102828f3058a1ac2aab4d22e09e25659dab370b61aa6a61513ab2bc1f3da062f376ffffffff02c0175302000000001976a91443b03e7d0c5e576d7e78ed635473ea7fbd13ce9b88ac40420f00000000001976a914a0a8e6b415ba3168741b9b56328910dabf002af988ac00000000\",\n"
	"    \"txid\" : \"b919cf3f23747386ad58fe7fa3a478070e7102f8474b72a692e2089857c2cbc6\",\n"
	"    \"version\" : 1,\n"
	"    \"locktime\" : 0,\n"
	"    \"vin\" : [\n"
	"        {\n"
	"            \"txid\" : \"e84b0c87934a146d211fcaa6f1ec187da33e205fb250400cf66620a82a9111a0\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"304402205e56244080cb06432a13f4d0d82d69e619cc3373f4c5f39bf9332bdea98f0fe50220637b4411bddbe9b465222df27a393b1a648419807919ad05c424ca461223dedf01 02828f3058a1ac2aab4d22e09e25659dab370b61aa6a61513ab2bc1f3da062f376\",\n"
	"                \"hex\" : \"47304402205e56244080cb06432a13f4d0d82d69e619cc3373f4c5f39bf9332bdea98f0fe50220637b4411bddbe9b465222df27a393b1a648419807919ad05c424ca461223dedf012102828f3058a1ac2aab4d22e09e25659dab370b61aa6a61513ab2bc1f3da062f376\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        }\n"
	"    ],\n"
	"    \"vout\" : [\n"
	"        {\n"
	"            \"value\" : 0.39000000,\n"
	"            \"n\" : 0,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 43b03e7d0c5e576d7e78ed635473ea7fbd13ce9b OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a91443b03e7d0c5e576d7e78ed635473ea7fbd13ce9b88ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"mmgrhZVoEg2EeMV4b9QC6G7du4fXAWPA7C\"\n"
	"                ]\n"
	"            }\n"
	"        },\n"
	"        {\n"
	"            \"value\" : 0.01000000,\n"
	"            \"n\" : 1,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 a0a8e6b415ba3168741b9b56328910dabf002af9 OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a914a0a8e6b415ba3168741b9b56328910dabf002af988ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"mvASkCxYqjMh3JK5VV52CrTWTwhe2T875G\"\n"
	"                ]\n"
	"            }\n"
	"        }\n"
	"    ],\n"
	"    \"blockhash\" : \"0000000027a8e0cdc4c2e469baec6c3b276abbe748a0d3a73c0b97137c5127ea\",\n"
	"    \"confirmations\" : 8421,\n"
	"    \"time\" : 1406461142,\n"
	"    \"blocktime\" : 1406461142\n"
	"}\n",
	"{\n"
	"    \"hex\" : \"0100000011e62bed4735c612f785e9b702b37e30e8bd3bb64b0bd93f15bb8858c3e3351b4e000000006a473044022060e18f828750c006dd4bd3e84c86fd3763f3bf4bb58f19f0294fd46019d911e7022052ac91577ad96c8b110b25e5dca64750e5182d34c90e992feb8a09abfe3763bb0121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469ffffffff0680815ed1ef702e0de3b7aa809a0c46794d1f6f905fb879065126538229b443010000006a473044022020d5e1019a7995506de4a959da169b03b7cae25766c9580a721759696c14f57a0220299e365bc995b36760c97dc0c5f1d6cca1432bb9e6b4bca852f790d359d277a30121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469ffffffffcc2037a13610d1ac71c6664529da0f73263f4fc2520603ba7b62aebc12e068d9010000006b48304502210083ced1660d0c92c69d7c4cdb960f9e7c364e0d63ac0f37dc57e723a505331ed302205ff50bf4914f523f8996dfa3de02ef0be6fd5a63744335089fe0850ceb8803ce0121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469ffffffff29e248e9812dc73b29726197535797d6134cf855e53c3f71b8ece3bba4ea4146010000006a4730440220787c6938859ce37d2dbad4acf6eb4f7443812fdf81a83ebb8e94da449097772c02203fc449da6df4115af6d07ac397a7d8af02f6efc15955a60789f425cdd4dc98c10121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469ffffffffd8af8673263312904a2431a940d75a8cb2e7e3ae86d70057a529f92beced2c13000000006b483045022100af36e7c85920177b785cfedc836afcc33a6eb7ccd5712468b54263212bb9dc000220009da3374fcd7d1275a60a2187c169b132ab1686c35c4dee8d353801e3eb2b9c0121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469ffffffff2f4b05c541eca5ddcd86b4fa3e2b2ae8917b6c3e6f7488fad91072d8cf5bb49e010000006b483045022100bf97b1cefafc6648212b53353d075e3a9f80981759e75f29db869a3fe639b0e10220091bef3f7e50ad3274ce7afb4d22e63d05f22edb2b02226c8b124077097ce447012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1bffffffffd3e0c93b75c15bf4a3dadfcfafc5ea291cf3634bb610c4273e04a85aa7aca817010000006a47304402207bef2eaefe08674799fe1293b99437d49c651f55076df5d345c30cc60bb6ff1f0220587297206b642c2ceeef9a71885fba3349c9bcb0689f54580e28e714d9fbf18e012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1bffffffff77029a900e25b12a42934243db8cd8acf8d46b32259f07a2ea2e7a6e4de5adf3000000006a473044022004c016d2e4b5be9e8b78c4cb240df36f965cabc7b5c3542d51babcf52001ff1502201ebe62d8085293c4d886b3942ff204ceec26c3d28ded1dcf0c1bb6386374acd30121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469ffffffffdf5a9b6d128146a7bd2c9231e39ce9b5aeb9badfeee3dbb7a38ccf7b321c1cc8000000006a47304402203b294e096b036549cda67ad46eb32e693edb00ab4c4dead8e783b51fefc5190602204285833fee58b76b845c702897eecf1e494e0b163efcd89efe1d38a69dc36330012103d385c745983cdadd104fb30ca22913447a14ef2086484860009f9f6afce64b19ffffffff16d8434fa773da34e83c194785ac0e4e87171bdcf666031cc276761362a0b9ff000000006b4830450221008393d2be9050dddcee88846d3e21134075d3ec3b7c7ee14ddad34c6128c46d3a02203d86dfa2aa6666287ab9dd939144e324812c985cf78e194f05943f682afa1b28012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1bffffffffc0bff3328542f9a223d9ae5221714821b4374dc4a938e94ad6ce417406aacab6010000006a473044022050b4156da94fb45f5459a04731dce1c060c639568a60e79329430fc20928e96d0220219a95e43fda8ae52ff2fd48fa916894a4e3e1c2e4e1c10ff68baac90b882b0c012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1bffffffff0329cce902b9165d9e85121e011422fbf3ebb1f52fd7d47a3ca8dd11f83f77f1000000006a473044022051118853476e8e5532ebbbcb77e8dd15f1f04011fa5cd9a194379b4982bc0ca602207701274aff6d01d6156ca7f06f6e588e17005b3d4f1b652c5ccfdaae6ddb4499012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1bffffffffd81285f65e6a7025c7d485a810d1572f25aab42cfcc3ca6a771641513a7e2e1d000000006b483045022100f1dd719738ef296e03a52ad6e80fb7ca423e9ed44c2284ec2a56085da58aaee102203619f0a6a4ee91ae497370fac65133311ecfad2db8d7a53ce1e976220041bd9a0121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469fffffffff60213d6daf2876fd84f5baef5c5789a43b46636019ef1aa3643a207309bafa5010000006b483045022100b3a04decf6a8cf0870d4dd0b86702fb8a0da2a149fd4226c62b3f7fd1a35ceb902203c8ce05a4d08dc1369e2223338e4035554f841a4f27041455aed743d9c32b8e1012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1bffffffffb0803075c542d4922b385253e3c44b2e87eb2f59e1ed77b990707af4811a4978000000006b483045022100d56f4224214fe2749d056cf29ed0294ff2eb5eaaf4adb743771a232762bf7612022066bffe7fd2cd45154f62ea6a5073ccee08b1af1d15fd9ff7ab3af6efaa5202b10121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469ffffffffd815c59a446e7d745bbeed33bcc72a3c6c7de72338030f5809fa094a8c0c1ba3010000006b483045022100ad1cbd2bdb331c193ecef8a194de2e93b8b05f22cebe8567c56759454d74634b022054cc38bc3a69d6d55c40d36bbb10b508cf5808374cb18750f213a42cd580f9c90121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469ffffffff01af862ddffc8d3909880cc7cc8cdcf5b4b416ddf04df44d9a79ced69dce5c0f010000006b483045022100920e0f95502adf1f2ab359bead73903a8da2284c2903fa572cb48b8b9ef9894302207b62f5966a5f0bebba0d8d77a6e8932762631e3c53662b328df3178327bcd1b1012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1bffffffff0200943577000000001976a914516fa5f385da57cd5034fc5cf4aa1c34762f4b8188ac80de0f00000000001976a9149cdf8ae5761a9a4e9e725a2a070e2648942a6bef88ac00000000\",\n"
	"    \"txid\" : \"28cb1254ad475eef81dbe1dad4dc519bc28441f080cbbe59d911038b5589ca2f\",\n"
	"    \"version\" : 1,\n"
	"    \"locktime\" : 0,\n"
	"    \"vin\" : [\n"
	"        {\n"
	"            \"txid\" : \"4e1b35e3c35888bb153fd90b4bb63bbde8307eb302b7e985f712c63547ed2be6\",\n"
	"            \"vout\" : 0,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3044022060e18f828750c006dd4bd3e84c86fd3763f3bf4bb58f19f0294fd46019d911e7022052ac91577ad96c8b110b25e5dca64750e5182d34c90e992feb8a09abfe3763bb01 039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\",\n"
	"                \"hex\" : \"473044022060e18f828750c006dd4bd3e84c86fd3763f3bf4bb58f19f0294fd46019d911e7022052ac91577ad96c8b110b25e5dca64750e5182d34c90e992feb8a09abfe3763bb0121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"43b429825326510679b85f906f1f4d79460c9a80aab7e30d2e70efd15e818006\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3044022020d5e1019a7995506de4a959da169b03b7cae25766c9580a721759696c14f57a0220299e365bc995b36760c97dc0c5f1d6cca1432bb9e6b4bca852f790d359d277a301 039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\",\n"
	"                \"hex\" : \"473044022020d5e1019a7995506de4a959da169b03b7cae25766c9580a721759696c14f57a0220299e365bc995b36760c97dc0c5f1d6cca1432bb9e6b4bca852f790d359d277a30121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"d968e012bcae627bba030652c24f3f26730fda294566c671acd11036a13720cc\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"304502210083ced1660d0c92c69d7c4cdb960f9e7c364e0d63ac0f37dc57e723a505331ed302205ff50bf4914f523f8996dfa3de02ef0be6fd5a63744335089fe0850ceb8803ce01 039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\",\n"
	"                \"hex\" : \"48304502210083ced1660d0c92c69d7c4cdb960f9e7c364e0d63ac0f37dc57e723a505331ed302205ff50bf4914f523f8996dfa3de02ef0be6fd5a63744335089fe0850ceb8803ce0121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"4641eaa4bbe3ecb8713f3ce555f84c13d6975753976172293bc72d81e948e229\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"30440220787c6938859ce37d2dbad4acf6eb4f7443812fdf81a83ebb8e94da449097772c02203fc449da6df4115af6d07ac397a7d8af02f6efc15955a60789f425cdd4dc98c101 039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\",\n"
	"                \"hex\" : \"4730440220787c6938859ce37d2dbad4acf6eb4f7443812fdf81a83ebb8e94da449097772c02203fc449da6df4115af6d07ac397a7d8af02f6efc15955a60789f425cdd4dc98c10121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"132cedec2bf929a55700d786aee3e7b28c5ad740a931244a901233267386afd8\",\n"
	"            \"vout\" : 0,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3045022100af36e7c85920177b785cfedc836afcc33a6eb7ccd5712468b54263212bb9dc000220009da3374fcd7d1275a60a2187c169b132ab1686c35c4dee8d353801e3eb2b9c01 039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\",\n"
	"                \"hex\" : \"483045022100af36e7c85920177b785cfedc836afcc33a6eb7ccd5712468b54263212bb9dc000220009da3374fcd7d1275a60a2187c169b132ab1686c35c4dee8d353801e3eb2b9c0121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"9eb45bcfd87210d9fa88746f3e6c7b91e82a2b3efab486cddda5ec41c5054b2f\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3045022100bf97b1cefafc6648212b53353d075e3a9f80981759e75f29db869a3fe639b0e10220091bef3f7e50ad3274ce7afb4d22e63d05f22edb2b02226c8b124077097ce44701 03b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\",\n"
	"                \"hex\" : \"483045022100bf97b1cefafc6648212b53353d075e3a9f80981759e75f29db869a3fe639b0e10220091bef3f7e50ad3274ce7afb4d22e63d05f22edb2b02226c8b124077097ce447012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"17a8aca75aa8043e27c410b64b63f31c29eac5afcfdfdaa3f45bc1753bc9e0d3\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"304402207bef2eaefe08674799fe1293b99437d49c651f55076df5d345c30cc60bb6ff1f0220587297206b642c2ceeef9a71885fba3349c9bcb0689f54580e28e714d9fbf18e01 03b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\",\n"
	"                \"hex\" : \"47304402207bef2eaefe08674799fe1293b99437d49c651f55076df5d345c30cc60bb6ff1f0220587297206b642c2ceeef9a71885fba3349c9bcb0689f54580e28e714d9fbf18e012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"f3ade54d6e7a2eeaa2079f25326bd4f8acd88cdb434293422ab1250e909a0277\",\n"
	"            \"vout\" : 0,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3044022004c016d2e4b5be9e8b78c4cb240df36f965cabc7b5c3542d51babcf52001ff1502201ebe62d8085293c4d886b3942ff204ceec26c3d28ded1dcf0c1bb6386374acd301 039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\",\n"
	"                \"hex\" : \"473044022004c016d2e4b5be9e8b78c4cb240df36f965cabc7b5c3542d51babcf52001ff1502201ebe62d8085293c4d886b3942ff204ceec26c3d28ded1dcf0c1bb6386374acd30121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"c81c1c327bcf8ca3b7dbe3eedfbab9aeb5e99ce331922cbda74681126d9b5adf\",\n"
	"            \"vout\" : 0,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"304402203b294e096b036549cda67ad46eb32e693edb00ab4c4dead8e783b51fefc5190602204285833fee58b76b845c702897eecf1e494e0b163efcd89efe1d38a69dc3633001 03d385c745983cdadd104fb30ca22913447a14ef2086484860009f9f6afce64b19\",\n"
	"                \"hex\" : \"47304402203b294e096b036549cda67ad46eb32e693edb00ab4c4dead8e783b51fefc5190602204285833fee58b76b845c702897eecf1e494e0b163efcd89efe1d38a69dc36330012103d385c745983cdadd104fb30ca22913447a14ef2086484860009f9f6afce64b19\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"ffb9a062137676c21c0366f6dc1b17874e0eac8547193ce834da73a74f43d816\",\n"
	"            \"vout\" : 0,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"30450221008393d2be9050dddcee88846d3e21134075d3ec3b7c7ee14ddad34c6128c46d3a02203d86dfa2aa6666287ab9dd939144e324812c985cf78e194f05943f682afa1b2801 03b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\",\n"
	"                \"hex\" : \"4830450221008393d2be9050dddcee88846d3e21134075d3ec3b7c7ee14ddad34c6128c46d3a02203d86dfa2aa6666287ab9dd939144e324812c985cf78e194f05943f682afa1b28012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"b6caaa067441ced64ae938a9c44d37b42148712152aed923a2f9428532f3bfc0\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3044022050b4156da94fb45f5459a04731dce1c060c639568a60e79329430fc20928e96d0220219a95e43fda8ae52ff2fd48fa916894a4e3e1c2e4e1c10ff68baac90b882b0c01 03b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\",\n"
	"                \"hex\" : \"473044022050b4156da94fb45f5459a04731dce1c060c639568a60e79329430fc20928e96d0220219a95e43fda8ae52ff2fd48fa916894a4e3e1c2e4e1c10ff68baac90b882b0c012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"f1773ff811dda83c7ad4d72ff5b1ebf3fb2214011e12859e5d16b902e9cc2903\",\n"
	"            \"vout\" : 0,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3044022051118853476e8e5532ebbbcb77e8dd15f1f04011fa5cd9a194379b4982bc0ca602207701274aff6d01d6156ca7f06f6e588e17005b3d4f1b652c5ccfdaae6ddb449901 03b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\",\n"
	"                \"hex\" : \"473044022051118853476e8e5532ebbbcb77e8dd15f1f04011fa5cd9a194379b4982bc0ca602207701274aff6d01d6156ca7f06f6e588e17005b3d4f1b652c5ccfdaae6ddb4499012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"1d2e7e3a514116776acac3fc2cb4aa252f57d110a885d4c725706a5ef68512d8\",\n"
	"            \"vout\" : 0,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3045022100f1dd719738ef296e03a52ad6e80fb7ca423e9ed44c2284ec2a56085da58aaee102203619f0a6a4ee91ae497370fac65133311ecfad2db8d7a53ce1e976220041bd9a01 039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\",\n"
	"                \"hex\" : \"483045022100f1dd719738ef296e03a52ad6e80fb7ca423e9ed44c2284ec2a56085da58aaee102203619f0a6a4ee91ae497370fac65133311ecfad2db8d7a53ce1e976220041bd9a0121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"a5af9b3007a24336aaf19e013666b4439a78c5f5ae5b4fd86f87f2dad61302f6\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3045022100b3a04decf6a8cf0870d4dd0b86702fb8a0da2a149fd4226c62b3f7fd1a35ceb902203c8ce05a4d08dc1369e2223338e4035554f841a4f27041455aed743d9c32b8e101 03b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\",\n"
	"                \"hex\" : \"483045022100b3a04decf6a8cf0870d4dd0b86702fb8a0da2a149fd4226c62b3f7fd1a35ceb902203c8ce05a4d08dc1369e2223338e4035554f841a4f27041455aed743d9c32b8e1012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"78491a81f47a7090b977ede1592feb872e4bc4e35352382b92d442c5753080b0\",\n"
	"            \"vout\" : 0,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3045022100d56f4224214fe2749d056cf29ed0294ff2eb5eaaf4adb743771a232762bf7612022066bffe7fd2cd45154f62ea6a5073ccee08b1af1d15fd9ff7ab3af6efaa5202b101 039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\",\n"
	"                \"hex\" : \"483045022100d56f4224214fe2749d056cf29ed0294ff2eb5eaaf4adb743771a232762bf7612022066bffe7fd2cd45154f62ea6a5073ccee08b1af1d15fd9ff7ab3af6efaa5202b10121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"a31b0c8c4a09fa09580f033823e77d6c3c2ac7bc33edbe5b747d6e449ac515d8\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3045022100ad1cbd2bdb331c193ecef8a194de2e93b8b05f22cebe8567c56759454d74634b022054cc38bc3a69d6d55c40d36bbb10b508cf5808374cb18750f213a42cd580f9c901 039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\",\n"
	"                \"hex\" : \"483045022100ad1cbd2bdb331c193ecef8a194de2e93b8b05f22cebe8567c56759454d74634b022054cc38bc3a69d6d55c40d36bbb10b508cf5808374cb18750f213a42cd580f9c90121039352960180f7bb829d52c321ef4f7e2cb71229352a994840c62701ac9f59e469\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        },\n"
	"        {\n"
	"            \"txid\" : \"0f5cce9dd6ce799a4df44df0dd16b4b4f5dc8cccc70c8809398dfcdf2d86af01\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"3045022100920e0f95502adf1f2ab359bead73903a8da2284c2903fa572cb48b8b9ef9894302207b62f5966a5f0bebba0d8d77a6e8932762631e3c53662b328df3178327bcd1b101 03b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\",\n"
	"                \"hex\" : \"483045022100920e0f95502adf1f2ab359bead73903a8da2284c2903fa572cb48b8b9ef9894302207b62f5966a5f0bebba0d8d77a6e8932762631e3c53662b328df3178327bcd1b1012103b8087f250f5c12eea3ddb3d8defa4854223d9e19d06f4ea93b63dcad14920a1b\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        }\n"
	"    ],\n"
	"    \"vout\" : [\n"
	"        {\n"
	"            \"value\" : 20.00000000,\n"
	"            \"n\" : 0,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 516fa5f385da57cd5034fc5cf4aa1c34762f4b81 OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a914516fa5f385da57cd5034fc5cf4aa1c34762f4b8188ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"mnwYn3mP11dWvJUbyraBqYBkx8TgWSLgVn\"\n"
	"                ]\n"
	"            }\n"
	"        },\n"
	"        {\n"
	"            \"value\" : 0.01040000,\n"
	"            \"n\" : 1,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 9cdf8ae5761a9a4e9e725a2a070e2648942a6bef OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a9149cdf8ae5761a9a4e9e725a2a070e2648942a6bef88ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"mupRVzKuFyxWRhqWGSrMXHXRT7JQF7WB5s\"\n"
	"                ]\n"
	"            }\n"
	"        }\n"
	"    ],\n"
	"    \"blockhash\" : \"000000007cd4fedeaef48e5bbd8e857b1fd7814d1620cf534c2ceaeb21e6cd92\",\n"
	"    \"confirmations\" : 697,\n"
	"    \"time\" : 1409749898,\n"
	"    \"blocktime\" : 1409749898\n"
	"}\n",
	"{\n"
	"    \"hex\" : \"010000000103d9852fbd07ba229f5c6b7742a1ae65ae73fff6732e162a3c002636b5209f10000000006b4830450221009fac74f67eaa9db0c9f407a828e0f128d8700196ac05d24630889612285ad1f20220604d98a02b7de8e9e2731198c54c640d4fd52ef2209ef6c8653cdfc5a615d25f012103ae43f8a14627d5d3609ef9242724915b2e917971dc1ec31bcbf7471914328ce6ffffffff02a07ad307000000001976a914cd1545e21c1cbe0e8b0e908df5de76f35b6bdbe488ac82a35151080000001976a9143fa5e24c72d46f8056d2f500b530c9d4e363920388ac00000000\",\n"
	"    \"txid\" : \"4e1b35e3c35888bb153fd90b4bb63bbde8307eb302b7e985f712c63547ed2be6\",\n"
	"    \"version\" : 1,\n"
	"    \"locktime\" : 0,\n"
	"    \"vin\" : [\n"
	"        {\n"
	"            \"txid\" : \"109f20b53626003c2a162e73f6ff73ae65aea142776b5c9f22ba07bd2f85d903\",\n"
	"            \"vout\" : 0,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"30450221009fac74f67eaa9db0c9f407a828e0f128d8700196ac05d24630889612285ad1f20220604d98a02b7de8e9e2731198c54c640d4fd52ef2209ef6c8653cdfc5a615d25f01 03ae43f8a14627d5d3609ef9242724915b2e917971dc1ec31bcbf7471914328ce6\",\n"
	"                \"hex\" : \"4830450221009fac74f67eaa9db0c9f407a828e0f128d8700196ac05d24630889612285ad1f20220604d98a02b7de8e9e2731198c54c640d4fd52ef2209ef6c8653cdfc5a615d25f012103ae43f8a14627d5d3609ef9242724915b2e917971dc1ec31bcbf7471914328ce6\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        }\n"
	"    ],\n"
	"    \"vout\" : [\n"
	"        {\n"
	"            \"value\" : 1.31300000,\n"
	"            \"n\" : 0,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 cd1545e21c1cbe0e8b0e908df5de76f35b6bdbe4 OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a914cd1545e21c1cbe0e8b0e908df5de76f35b6bdbe488ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"mzDLJTAWGVuZwwofZLXBxa676gHNU8QtHs\"\n"
	"                ]\n"
	"            }\n"
	"        },\n"
	"        {\n"
	"            \"value\" : 357.24043138,\n"
	"            \"n\" : 1,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 3fa5e24c72d46f8056d2f500b530c9d4e3639203 OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a9143fa5e24c72d46f8056d2f500b530c9d4e363920388ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"mmKVaxeZzud9Yn2nvc55v2ivPYhMDjZYaC\"\n"
	"                ]\n"
	"            }\n"
	"        }\n"
	"    ],\n"
	"    \"blockhash\" : \"000000007765c59ae39a3f1e25fef8245a653c723f03214ea4b7299b14d7b1ec\",\n"
	"    \"confirmations\" : 5395,\n"
	"    \"time\" : 1407812255,\n"
	"    \"blocktime\" : 1407812255\n"
	"}\n",
	"{\n"
	"    \"hex\" : \"0100000001d0c7d22b067ae89eea8cf0d0c4b457b8ac5e8d98353cf2a31de9b18450847e42010000006a47304402207bfc1088b4a81e79d09c9a56862f595833ca572552e624f77f6e52d5d9d89d630220257d71f7137883e24f60297c41a1aa754a5647ea83767834c9bc809e4f42eba601210276052e810bea68bfea763140276d5023f2a24dfe8dae872e88fbe08ecf9d8f41ffffffff01804f1200000000001976a914516fa5f385da57cd5034fc5cf4aa1c34762f4b8188ac00000000\",\n"
	"    \"txid\" : \"8d3ad477d0be3786947927a4f8321f8a1358a5989a8ec9293138a072a530a7ac\",\n"
	"    \"version\" : 1,\n"
	"    \"locktime\" : 0,\n"
	"    \"vin\" : [\n"
	"        {\n"
	"            \"txid\" : \"427e845084b1e91da3f23c35988d5eacb857b4c4d0f08cea9ee87a062bd2c7d0\",\n"
	"            \"vout\" : 1,\n"
	"            \"scriptSig\" : {\n"
	"                \"asm\" : \"304402207bfc1088b4a81e79d09c9a56862f595833ca572552e624f77f6e52d5d9d89d630220257d71f7137883e24f60297c41a1aa754a5647ea83767834c9bc809e4f42eba601 0276052e810bea68bfea763140276d5023f2a24dfe8dae872e88fbe08ecf9d8f41\",\n"
	"                \"hex\" : \"47304402207bfc1088b4a81e79d09c9a56862f595833ca572552e624f77f6e52d5d9d89d630220257d71f7137883e24f60297c41a1aa754a5647ea83767834c9bc809e4f42eba601210276052e810bea68bfea763140276d5023f2a24dfe8dae872e88fbe08ecf9d8f41\"\n"
	"            },\n"
	"            \"sequence\" : 4294967295\n"
	"        }\n"
	"    ],\n"
	"    \"vout\" : [\n"
	"        {\n"
	"            \"value\" : 0.01200000,\n"
	"            \"n\" : 0,\n"
	"            \"scriptPubKey\" : {\n"
	"                \"asm\" : \"OP_DUP OP_HASH160 516fa5f385da57cd5034fc5cf4aa1c34762f4b81 OP_EQUALVERIFY OP_CHECKSIG\",\n"
	"                \"hex\" : \"76a914516fa5f385da57cd5034fc5cf4aa1c34762f4b8188ac\",\n"
	"                \"reqSigs\" : 1,\n"
	"                \"type\" : \"pubkeyhash\",\n"
	"                \"addresses\" : [\n"
	"                    \"mnwYn3mP11dWvJUbyraBqYBkx8TgWSLgVn\"\n"
	"                ]\n"
	"            }\n"
	"        }\n"
	"    ],\n"
	"    \"blockhash\" : \"000000006eb0dc66b9dcb593496fdc723ff6f981deda35d0287e6b6ce5caf1c0\",\n"
	"    \"confirmations\" : 590,\n"
	"    \"time\" : 1409805325,\n"
	"    \"blocktime\" : 1409805325\n"
	"}\n"

};

struct expected_payment {
	const char *address;
	u32 satoshis;
	bool complete;
};

static struct expected_payment payments[] = {
	{ "P-muzsCLFmS1A2ppe8V4Gxro89a4UvZZzgMn",   12340000, false },
	{ "P-mvASkCxYqjMh3JK5VV52CrTWTwhe2T875G",    1000000, false },
	/* Refund payment to bitcoin */
	{ "mzDLJTAWGVuZwwofZLXBxa676gHNU8QtHs", 2000000000 - 1000, false },
	{ "P-mhe17cf9VGsZH6G6DhsGTQre9LM53qMXDs",    1200000, false }
};
	
static bool mark_off_payment(const char *addr, u64 satoshis)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(payments); i++) {
		if (streq(addr, payments[i].address)) {
			assert(!payments[i].complete);
			assert(satoshis == payments[i].satoshis);
			payments[i].complete = true;
			return true;
		}
	}
	return false;
}

static void fake_sleep(int seconds)
{
	unsigned int i;

	assert(seconds == 5);
	sleeps++;
	assert(sleeps < 100);

	for (i = 0; i < ARRAY_SIZE(payments); i++) {
		if (!payments[i].complete)
			return;
	}

	/* We're done! */
	tal_free(top_ctx);
	opt_free_table();
	exit(0);
}

static const char getinfo_response[] =
	"{\n"
	"    \"version\" : 90201,\n"
	"    \"protocolversion\" : 70002,\n"
	"    \"walletversion\" : 60000,\n"
	"    \"balance\" : 0.25440000,\n"
	"    \"blocks\" : 279418,\n"
	"    \"timeoffset\" : 0,\n"
	"    \"connections\" : 0,\n"
	"    \"proxy\" : \"\",\n"
	"    \"difficulty\" : 1.00000000,\n"
	"    \"testnet\" : true,\n"
	"    \"keypoololdest\" : 1386823067,\n"
	"    \"keypoolsize\" : 101,\n"
	"    \"paytxfee\" : 0.00001000,\n"
	"    \"relayfee\" : 0.00001000,\n"
	"    \"errors\" : \"\"\n"
	"}\n";

static char *ask_process(const tal_t *ctx,
			 const char *name,
			 const char *arg1,
			 const char *arg2,
			 const char *arg3,
			 const char *arg4,
			 const char *arg5)
{
	char *response = tal_strdup(ctx, "");

	if (streq(name, "bitcoind")) {
		assert(streq(arg1, "-testnet"));
		if (streq(arg2, "listtransactions")) {
			unsigned int i, num, skip;

			assert(streq(arg3, "gateway"));
			num = atoi(arg4 ? arg4 : "10");
			assert(num);
			skip = atoi(arg5 ? arg5 : "0");

			json_array_start(&response, NULL);
			/* Like bitcoind, list oldest first. */
			for (i = skip; i < skip+num; i++) {
				unsigned int confs;

				if (i >= ARRAY_SIZE(listtxs_response))
					break;
				/* We only show one the first time. */
				if (i > sleeps)
					break;
				/* First one is 16 confs, then 4, 1, then 0,
				 * plus one each time you ask. */
				confs = (1 << ((ARRAY_SIZE(listtxs_response)
						- i) * 2)) + sleeps;

				tal_append_fmt(&response, listtxs_response[i],
					       confs);
			}
			json_array_end(&response);
			return response;
		} else if (streq(arg2, "getrawtransaction")) {
			unsigned int i;

			/* We only do verbose mode */
			assert(streq(arg4, "1"));
			assert(arg5 == NULL);

			/* Search through responses for this txid */
			for (i = 0; i < ARRAY_SIZE(getrawtxs_response); i++) {
				const char *p;
				p = strstr(getrawtxs_response[i],
					   "    \"txid\" : \"");
				if (strstarts(p + strlen("    \"txid\" : \""),
					      arg3))
					return tal_strdup(ctx,
							  getrawtxs_response[i]);
			}
		} else if (streq(arg2, "getinfo")) {
			return tal_strdup(ctx, getinfo_response);
		} else if (streq(arg2, "sendtoaddress")) {
			if (mark_off_payment(arg3,
					     amount_in_satoshis(arg4,
								strlen(arg4))))
				return tal_strdup(ctx, "some-new-bitcoin-txid");
		}
	} else if (streq(name, "pettycoin-tx")) {
		assert(streq(arg1, "--no-fee"));
		assert(streq(arg2, "from-gateway"));
		assert(streq(arg3, "FAKE-gateway-privkey"));

		if (mark_off_payment(arg4, atol(arg5)))
			return tal_fmt(ctx, "raw-transaction-%s", arg4);
	} else if (streq(name, "pettycoin-query")) {
		assert(streq(arg1, "sendrawtransaction"));
		assert(strstarts(arg2, "raw-transaction-"));
		assert(arg3 == NULL);
		assert(arg4 == NULL);
		assert(arg5 == NULL);
		return tal_fmt(ctx, "txid for %s", arg2);
	}

	printf("ask_process: name=%s arg1=%s arg2=%s arg3=%s arg4=%s arg5=%s",
	       name, arg1, arg2, arg3, arg4, arg5);
	return NULL;
}

void *fake_grab_file(const void *ctx, const char *filename)
{
	top_ctx = ctx;

	if (streq(filename, "gateway-privkey"))
		return "FAKE-gateway-privkey";
	abort();
}


void pettycoin_dir_register_opts(const tal_t *ctx,
				 char **pettycoin_dir, char **rpc_filename)
{
	*pettycoin_dir = tal_strdup(ctx, ".");
	*rpc_filename = tal_strdup(ctx, "-");
}

int main(int argc, char *argv[])
{
	return pettycoin_gateway_main(argc, argv);
}
