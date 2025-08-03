#define KEY_TOGGLE VK_END
#define KEY_INCREASE VK_UP
#define KEY_INCREASE_SMALL VK_RIGHT
#define KEY_DECREASE VK_DOWN
#define KEY_DECREASE_SMALL VK_LEFT
#define FPS_TARGET 120
#define DEFAULT_DEVICE 8 
#define CONFIG_FILENAME (L"hoyofps_config.ini")
#define IsKeyPressed(nVirtKey)    ((GetKeyState(nVirtKey) & (1<<(sizeof(SHORT)*8-1))) != 0)

#include <iostream>
#include <vector>
#include <string>
#include <locale.h>
#include <intrin.h>
#include "NTSYSAPI.h"

#include <Windows.h>
#include <TlHelp32.h>

#include "fastmemcp.h"
#include "inireader.h"


#ifndef _WIN64
#error you must build in Win x64
#endif

using namespace std;


wstring HKSRGamePath{};
wstring GenGamePath{};
wstring GamePath{};
uint32_t FpsValue = FPS_TARGET;
uint32_t Tar_Device = DEFAULT_DEVICE;
uint32_t Target_set_60 = 1000;
uint32_t Target_set_30 = 60;
bool isGenshin = 1;
bool Use_mobile_UI = 0;
bool _main_state = 1;
bool Process_endstate = 0;
bool ErrorMsg_EN = 1;
bool isHook = 0;
bool is_old_version = 0;
bool isAntimiss = 1;
bool AutoExit = 0;
HWND _console_HWND = 0;
BYTE ConfigPriorityClass = 1;
uint32_t GamePriorityClass = NORMAL_PRIORITY_CLASS;


//simple encrypt to avoid antivirus detection
const DECLSPEC_ALIGN(32) uint64_t _PE_MEM_LOADER[] = {
 0xC985480574D28548, 0xCCCCCCC3C0313675, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0x48000001B9158D4C, 0xCB1082F74BB815B8, 0x4902314902874948, 0xC9314DC0314D12F7,
 0x0204874B08408D4D, 0x78F881490204314B, 0xCCFD74EB75000012, 0xCCCCCCCCCCCCCCCC,
 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0xCCCCCCCCCCCCCCCC, 0x001615894898CCCC, 0xCCCCCCCC4CEB0000, 0xCCCCCCCCCCCCCCCC,
 0x0000000000000000, 0x0000000000000000, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0x894868EC83485653, 0x894800000030B8CB, 0x2024440148202444, 0x4CD23120244C8D48,
 0x000937E82824448D, 0x8B487275C0854800, 0xFF86058948282444, 0x007EE8D98948FFFF,
 0x8B4C65C689480000, 0xB848000000602514, 0x466C617574726956, 0x20528B4D18528B4D,
 0x00528B4D00528B4D, 0x24448948204A8B49, 0x656572382444C730, 0xE8483024548D4800,
 0x74C085480000033C, 0xF74828244C8B4814, 0x8000B841D23148D1, 0xF0894890D0FF0000,
 0xCCC35B5E68C48348, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0xFFD86C355FF510AA, 0xFF5E088D638C73E6, 0x99A783C59A8F3FE6, 0x5EEF8CB19EC806A7,
 0x9A6CC44E6137F867, 0xDDE7818D3E68B92F, 0x22187E72FFAFF17F, 0x2716960ADBDB7837,
 0xE793DEFA50937837, 0x6CDB23BCDDDB6942, 0x2D93E73F95A34D36, 0x65C7A0B4D0601269,
 0x2DAF84E85928C5E2, 0x61EFA08CD0640B69, 0x61E9A764E84067E0, 0x52ACB30B5F4F22E0,
 0xE5A3F2139ACC6B04, 0x8298B77575CF26D8, 0xE4FED11313F055DE, 0xE4FED11313744AD1,
 0xA57EDD9E5BB7FDDE, 0xBD0A1D1B4B7AB955, 0x7D81590F862E3214, 0xAA8211034B62B955,
 0xAA8214BBA3ACBA1D, 0xACDD2FFAC56F457B, 0xF3F662244E238B09, 0xF342C51D0B48FF39,
 0x43CD4E58693CFF39, 0x7A88805B253CFF39, 0xFF8CC1D0646F8B18, 0xB28429532C24FFD8,
 0x7201C182642CBE55, 0x721ECE52EF688E21, 0x14DC795DFFDF8160, 0x55CD0C57C3D369A1,
 0x55CD03A82152602A, 0x54D102E43756ED62, 0x553B81AD35966E2B, 0x567785ECBED7B85E,
 0xDF3F28999FEEFD96, 0xEF1B5C10D39ED9FA, 0xE01B5C104739E0BF, 0x5790191047399F3B,
 0x12661A5C47399FAB, 0x127915333335F992, 0xEDB7167B3F7B72D3, 0x053C5E84C086F9C6,
 0x7BB71FE4B4467C8E, 0xFE491CACB2CD3D9E, 0xB64F1027FAF2495E, 0x843BD9A2B2F455D3,
 0xCC3C327305FB50AA, 0x4774E3704DF90627, 0xC23CE3704CB3EEEA, 0x8A3CE370A637E12A,
 0x0974E4F9EE3F22A9, 0xC0F1ACF265772A6E, 0xF9B4B834E63EE41B, 0x9E8FFD52724BE87D,
 0xD670CC5999249B7B, 0xD670CC9170D954F8, 0x567C41D9B46E5BB9, 0x567C41D9797AD6F1,
 0x1F83BE2686BB11B9, 0x94C79A6C0DFFC4BA, 0x1F868595CCBECCF8, 0x3F6606972D3D8D39,
 0xC846C6142FFC0E78, 0x9ACDE6142FFC2A3A, 0xDE40AEDC6AF36E36, 0x9AC9E60A69BB0E12,
 0xFCC9E609E0532E36, 0xFAAEDD4C8697D177, 0xFAAE0DCB0DD64F05, 0x7FE615FB515D0705,
 0xFAAE1670197B73DE, 0xFAAE526F1665071E, 0x77EF9CE45EA5345B, 0x7FAC17AC8E5A350B,
 0x0A6C92E48601B843, 0x7EAC17CCC18AF9A4, 0x366A148401B9BC85, 0xE69515D48CF8720E,
 0x0D539E9C828CB28B, 0xF2AC6160424BFA94, 0x0963E228BD7AEC7F, 0xE19C2BABF5AC6737,
 0x1915633BF5AC645B, 0x6D9E2F4BD1C0EF13, 0x21F60B175A88DF37, 0x059A805B1AACBBBC,
 0x86D2F87F6E27F384, 0x4A1E3B203166BB40, 0x86D2F7ECFDAA778C, 0x4A1E3B203166BB40,
 0x1D486E00153A3208, 0x1DA4EF48427B6649, 0x96E805C30A7B664B, 0x978581CCC3FE2E82,
 0xF3018E1E46B62E82, 0xF301D453FEB62E83, 0xF30082D6F1B717E5, 0xA308BE57CDF69CE5,
 0xA309F8D2C2F69CA0, 0xA30970DA667DD8A0, 0xA23CF4D582F89DA0, 0xA2B0FC5109BC9DA0,
 0x5D83DD6584F69DA0, 0x5D83DC15A07214E4, 0xDCCB23EA5F8DABA5, 0xF7D154EA5F72545F,
 0xF3525BFE31494431, 0xF01A47B8BA494430, 0xF01AFC51125DCFF1, 0x229FB94944D68BF1,
 0xABD3B949444A0FFE, 0x2097B94945322B52, 0xC994F4692BB96F8D, 0x40D888112A53ECCC,
 0x26BE88112BD3C878, 0x26BE88112B57D777, 0xF77B035D314B5A34, 0xF43203C07DC01BCF,
 0x925465A6BCEB5706, 0x925465A6BC6F4809, 0x83E26AAEB8D94748, 0x8796AA2AB990CA00,
 0x81E5681055E4083A, 0x87937FFBAAB7857E, 0xC9187010ABEC083A, 0x001B3911F1614D1E,
 0xDA207C48CDD6425A, 0xDBA058FC469AE424, 0xDAD07C78CDDEE424, 0xDBA858D44692E424,
 0x9CDB4CAA7DD6E424, 0x179A8DA934CAA2AF, 0x20EE5F2CBCDE2960, 0x20EE8FAEB30A1221,
 0x2F3EB48EB7875121, 0xEDB5F08EB78795A2, 0xE2F42805FE4696EF, 0x729239713EC29659,
 0x73D18F7E1AB6B865, 0x4020FABE9E75472D, 0x4022B29A02FE0FED, 0x4022B09AC67F47ED,
 0x837FEEC59A3E18AC, 0x02373EEED3ED93E4, 0x4AEF4DEED3ECB31E, 0xDAF9393C56A47495,
 0xAE30BD3C5A127BD4, 0x6ECFF51C5E5EF3D8, 0x2242BDF72C9CC890, 0xDD62B98BA4DCE8B4,
 0x1DE9F5745B26CBA1, 0x1C9275D62FE64EE9, 0x13BF00D77C6B06CA, 0x97BDC3543469557C,
 0x1AF51316B97721AE, 0xA4FA0061B04B20F5, 0x29E9B66E0F77AD37, 0x5C3B321633FA4548,
 0xB4F3B95FE4990DAA, 0x4B0CD9B61B66F07E, 0x1DE518B552A47B81, 0xD129D4799E5B847E,
 0x1DE518B5529748B2, 0xD129D4799E5B847E, 0x85A09C61BA1F0D32, 0x0EE8A48D39571D16,
 0x4A2FEC72C6AE8613, 0xBD66EC72C6AECE37, 0xF4759872C6A131F7, 0x753C678D36A1D176,
 0x31B52B8D36B1D1B6, 0x15F1EC5DC1F98192, 0x597CA05DC1F985BA, 0x697C8079853ED59E,
 0x3DF1C8B9B67BD59E, 0x25A137B93D339DBA, 0xA6E9F78A3A4A5D3F, 0xEECDB301728965FB,
 0x22017FC24A4DE6B3, 0xEECDB30E86812A7F, 0x024EFB16A2C5A333, 0xFDB10236A74EEB7B,
 0x0DB1E0B7EF976037, 0x0DB1D093AB509FC8, 0x4589F4C722189FC8, 0x0959038F123CD345,
 0x2D0D8EC7721897C8, 0x0949058F6293DBF0, 0xC10C0AC7A2169380, 0x0A8743E7865A1AC8,
 0x4243C0AFBE08E589, 0x8E8F0C6372C4294A, 0x620C44735690A002, 0x9DF3BCB3531BE83A,
 0x9DF3BC93775F2F72, 0xB9B731DFA7A86772, 0xF1B7315FA7112652, 0x0EB7BA17EF3572DF,
 0xC27482D36C7D528F, 0x0EB84E1FA0B19E43, 0xC27482D36C7D528F, 0x0EB84E1FA0B19E43,
 0x79B7B69CE970150B, 0x79B7B69C696F1A1C, 0x8B3CFE65E2274C4B, 0x4863A0C111EFC702,
 0x4790BAB63117444B, 0x45C4D5B973E44E24, 0x4A8626B00CEBBDD4, 0x864AEA73FCEAE9AB,
 0xCA80D13BFEE664E5, 0x488F1800B72F22EA, 0x4AE017F3B72F2226, 0x0310159FD82060D5,
 0x851F159FD8A09854, 0xCCD69ED3D8A098C4, 0x85C6775091AF7947, 0x44C53A81BAE6B06C,
 0x32C53A813A1E3125, 0x32C53A81BA013E56, 0x60AA3572B06E31A5, 0x6F591528DF61C2B5,
 0x09506A27B951A0DA, 0x502F6541A900DFD5, 0x5FDC5520D60FB9F5, 0x0F8E3A2F254FF39A,
 0x6081C94F7F20FC69, 0x06C1803070468C0B, 0x5FBE8F562017F304, 0xDEF6FF375F189564,
 0x1C77B7375F1815A5, 0x9C9F367E5F181525, 0x9C1FCEFF16181525, 0x935743B2826B1525,
 0xEC580141728A966C, 0x05587E4E817A9700, 0xC994B2827E8569FC, 0x05587E4EB249A530,
 0x0611AF65FA5BB53F, 0x85595F74BE4BBAF7, 0x44AF4F9C3D02AA1E, 0xC7E78617711ADE11,
 0xC3F789DF61152EF0, 0x027CC5D6701A6FE1, 0xC3350D5D3DDA44AD, 0x283424524CAE4344,
 0x4E5242342AC82552, 0x4E5242342A4C3A5D, 0x415B6B3B3A0D1352, 0x50177B34CA1C5742,
 0x50177BB4239D1FA2, 0x305E52BB53DC36AD, 0x7C4E5DEB429826A2, 0x3D675222BDD166B3,
 0x79775D62F4F869E3, 0x76574C2EE4F759F2, 0x79770507EBC718DB, 0x687B1508FBD65CCB,
 0xEB320549D2D9F2BE, 0x23B94888FAD68D5E, 0x45DF52FCFE3F4C17, 0x45DF52FCFEBB5318,
 0x4ACFBB7FB6BA4217, 0xBABA7280FFAB4607, 0xABB571F4F04BC54E, 0x6779BD37F15ACA5E,
 0xABB571FB3D960692, 0x6779BD37F15ACA5E, 0xABB571FB3D960692, 0x6779BD37F15ACA5E,
 0xEA30EA61A4864112, 0xEA31DA8D25CEF979, 0xA2542A066CCF7279, 0x291C3247E7877AF2,
 0x51977A466CCF5ABA, 0x5642FE49934A129A, 0x2EC1B6491802129A, 0x2EC1B18E9C0D12BA,
 0x3EB238C394569BF3, 0x4B60BD191FA0A8B6, 0xEBFA2C8F9718E0F0, 0xD3DE6002DF937A68,
 0x9BDCD23AFBD7F320, 0x0B4A5EB7615E5398, 0xAEA21E9325D71B09, 0x96864A1E6DD71B0E,
 0x590D025649A39242, 0x99884AA9B65A41AA, 0xD190C1E166A544DE, 0x4D005272D82EF566,
 0xC4486A5694A3BDF8, 0x4FF02255269B99BC, 0x076EA8DEAB0D3026, 0xB5FD1096EB2974AF,
 0x3CB5221066B9E635, 0x3CB525408EF1C271, 0x483D6178AAA54F39, 0xB14389B721ED001D,
 0xF955FD77A4A5FFE2, 0x1500703FBCD02467, 0x150077675418AF2F, 0xD502CF6C201957AC,
 0x5D4746245FF257AC, 0xC7DDCB9DD443EFE4, 0xC6BDEF215D0F794D, 0x8E85CB65D447794D,
 0x0315732DEC6335C0, 0xBC5CE99F7FFDD346, 0x2EC65B0CE17758CB, 0x628E7F48683F5B79,
 0x6288A8A0281B27F0, 0xEACC90847C966FF0, 0xEF245F0F34DD4B84, 0xF9509F8A7C22B47D,
 0xACDDD7B309F93135, 0xACDB085BC17279C5, 0xAF63242FC08AFAC5, 0xCF4798A48C8AFA05,
 0x9F63042FC48AFA04, 0xC747B0A4888AFA05, 0xC6777425C08AFA04, 0x4F3FB7789ED5FA04,
 0xD5923CC9269D6A41, 0xF1EEB585B034F1DF, 0x7CA68DA1F4BDB99F, 0xFA2B1D19BC859DD3,
 0xB228AF9305A70E24, 0xB22EE07B4D834AAD, 0x3A6AD85F190E02AD, 0x478217D4514526D9,
 0x51F6D75119BAD921, 0x047B9F4A6C615C69, 0x047DC8A2A4EA1491, 0x00C5C6D6A5129791,
 0xFF3A39A54C129751, 0x748B81EDEC571E19, 0xF9C31D7767C793B6, 0xC1E759FE2FFFB7FA,
 0x4C71F07597B7B448, 0x6835793D04293EC3, 0xE5A5EBA7B6917683, 0xAD81AF2EFE3E9F05,
 0xF90CE72EFE3B44ED, 0xB142C35A767F7CC9, 0xF9BD3CA27F97B342, 0x8C66B9EA69E373C7,
 0x44EDF1163C6E3BDC, 0x451572163C6BD834, 0xAC1572D63AD3D640, 0x0450FB9EC52C28BF,
 0x95CA742E4E9D90F7, 0xDDAA5062C3D51D58, 0x65E252D0A3F159D1, 0xC75D485C2F6BC541,
 0xC22BA0340B2F4C09, 0x864B846086674C09, 0x6E840F28EB433881, 0x1A448A6014BCCF25,
 0x970C9115CF398733, 0x927279DD44718366, 0x2A7C0DDCBCF28366, 0xD5829735BCF2436E,
 0x643ADF8DF97B0B91, 0x2C8059136AE1B01A, 0x9E981C9A22F9FD97, 0x15128000A541B595,
 0xFD32C589EDD02503, 0xE56748C1EDD02017, 0x0DA8C389C5A5A95B, 0x026846C13A5A5E1F,
 0x47E10EC13A5E869B, 0x441C8BCEE1DBCE43, 0x0491C7DCA950CE43, 0x8591382356B14F51,
 0xC9864C2395B440A8, 0x36A344631EBC0025, 0x3660416C23BCFFDA, 0x73EB416C27237AD5,
 0x158D014863AA3239, 0x158D0148632E2D36, 0x1EC521AAA2661C39, 0x193AC02B6AED54FB,
 0x1A73C4CAABA554FB, 0x1A8C3B358EA4DF33, 0x7C554E354DA1D00E, 0x7C554E354D25CF01,
 0x771D6ED78C6DFE0E, 0x70E28D5654E6B6CC, 0x73AB89B595AEB6CC, 0x8C54765714BD3D14,
 0xF954B5521B47BC14, 0xD170F195CAB0F4C3, 0xF53C78DDCAB0F4C7, 0x787448F9863DB8FF,
 0x30500C3ECE059CB3, 0x78903F7B31FA634C, 0x7890BF7B01DE278B, 0x0C19F323258AAAC3,
 0x3C19D307614DF2E7, 0xB919D30270A5F2E7, 0xF1E62CFF142DFD27, 0xF15EA1B74C09B9AC,
 0x7A12993E0409B9BC, 0x5A1259BF4D519DF8, 0xDB5A31CAC4159DF8, 0x975A31EAC425B994,
 0x561200E5A401FD1D, 0x861948365349DDFF, 0x562A0046770D50B7, 0x1EE08B0E9748DDFF,
 0x95AC4285DB68343E, 0xD97EB5C4115B78EF, 0xEA3B7C731E1AB0DC, 0xFAD3BD3BDF91F90D,
 0xBE1404721EA2B86B, 0xB150FB8DE15DBC4F, 0x71E6F44CD21564F9, 0x75053505F2D5E7B1,
 0x3BDD3648F63526F9, 0xCCBBF4FFF92D2274, 0x0D88BCF7A1A46BA4, 0x0805F4A7B1E4ACE5,
 0x1C82B81FF9341AEA, 0x1C0BF1A6B16443CE, 0x344B37E7B2A6C086, 0xE4487EE350678845,
 0xAC4C9F229AD18704, 0x6C67DE12DB5C4D07, 0x24739E9B9A44A584, 0x293BBE7B5B0C670F,
 0x317B37327F08A047, 0x3C33F61136CA2B0F, 0x1C737F5832EE6FC8, 0xE3735BFCBFA6D780,
 0x5B3B6BBD36EE287F, 0x5B3B699D124AA537, 0xDC73D1D52A0B2C7F, 0x553B5A9DBE43087B,
 0xDE7352F5060B483A, 0x9632DBBD8543487A, 0x1B7A1F36CD13F032, 0xD86ADB668CD4D496,
 0x21EA632E8E5D9C5A, 0xA8A24702091563A5, 0xA04EC44AB15D6BE7, 0xB00C4D029559E2AF,
 0x4EEC69A618115AE7, 0xF6A471E49159A518, 0xFEE4FCACB9D095E7, 0xEEEB44E499921CAF,
 0x67A360A0889D2CEF, 0x27B36F8830D504AD, 0x17F1E6C074C40BED, 0x47B1F6CF4CE0B3A5,
 0xFFF9CE8DC5A8A2AA, 0xF0998E9DCAE086EE, 0xB8DD37D48AA20FA6, 0x3594FB186B5DDE51,
 0xE563B24821D4925A, 0x622BEA6C65C52A12, 0xDA63A22EEC8D2A52, 0x16AF6EE22041E69E,
 0xAEFED4AA38026FD7, 0x27B76DE2C7FD9028, 0x6C3E20EA8474DD3B, 0x2FB76DCAD7FD942B,
 0x6C3E24FA9C74D903, 0x2FB769BACFFD903B, 0x6C3E20EA8474DD73, 0x38B3688AD7FD942B,
 0xB5FF00C95EB0F40F, 0xF48F4B401380D04B, 0xB70602401380F0F2, 0x3C0443C9FFC57B8A,
 0xBF4CCB84768D8BCF, 0x430940863704AB0E, 0x63C8C3CEA7492246, 0xEA803B8B2C4B63CF,
 0xAB091B4AAF03CB82, 0x8F4D920253464080, 0xC2C4DA6A16CB08C0, 0x4B8CE24E5A464060,
 0x4B8CE036B2666424, 0xB4731AFD3A69A4A1, 0xF1FE528D1E2D8CAE, 0xD1FE62A95AEAC4C6,
 0xDECE46EDD7A6C4C6, 0x9F9662B95AEEC3D7, 0xD2BE6DB95AEEC16E, 0xC3B1559D166389EE,
 0xCC9171D99F2B99A1, 0xC3B136C890BBDC89, 0xCC8179D99F1B91A1, 0xC3C13EC890ABD489,
 0xCC9171D99F6B99A1, 0x24F136C890BBDC89, 0xACFEF64D90BBDE85, 0x88BA7D056F4424DA,
 0xBBBCF44DBFB36C82, 0xFE700BB245FE8542, 0xFE74239601394571, 0xB21407DA8C754571,
 0x96408A92BC5131F8, 0xB640EAB6F89679C8, 0x8640CA92BC5179C8, 0xD3BF35DA311879C8,
 0x2C45275F3ED8FC40, 0xA109177B7253B4BF, 0xA10915C2333390FB, 0x2C4125E667BED8FB,
 0x2DC86DE667BD307A, 0x65379219987CF732, 0x4173BA16A858B3B9, 0x0973BA15405DFBC9,
 0x0673AB1A7079BF40, 0x0963E30B7FF9F268, 0x0643A31A7069B740, 0x0973EB0B7FC9FA68,
 0x0633AB1A7079BF40, 0x0963E30B7FB9F268, 0x4103A31A7069B740, 0x6127E7933801F2CD,
 0xF1A2E853BDA9A732, 0xC186ACD8F55658CB, 0x01B5AA51BD86AF83, 0xC16B12AE427FD16A,
 0x7994ED5736960FC7, 0x49506C1FF6960EF2, 0x85933141A9960EF3, 0x495FFD8D655AC23F,
 0x8BE9F29A11A500BF, 0x8BA9ED95D0A18DF7, 0x0B51AD1898B17ABF, 0x43931B176CC4857D,
 0x8052179A2405918A, 0x4C9EDB56E8C95D46, 0xC9D61ADDA41BD60A, 0x42D61ADD1D9FD9C3,
 0x49A3A20C96D3E4C2, 0x49A21A0E1FD7A549, 0xF0BA6EE72314A549, 0x847B5581231480B6,
 0xBF1D55819B5C39B8, 0x071D558112D93679, 0x071D453812D93678, 0x071D453892C63978,
 0xCD3609F0198BE8F3, 0xB98ED87B55B269B2, 0x6805947969332BF4, 0xEB15E07B65BE654C,
 0x9D3518F8A541758D, 0x1EF6E7075ABECD5A, 0x95B7E603D1F8C99B, 0x7C662E8811D38D4B,
 0x3DB7058811D38CF3, 0x79BF208CE7DBF572, 0xF27C2205A219B17D, 0x04745B84E3F360AD,
 0xC5F78BC1ECFB45A9, 0xC5F78A792DD00955, 0x06E503383DD34855, 0xCA29CFF4F1108866,
 0xDA7844B8F961772E, 0xDFF50CFCF928FC66, 0x1B7E44ACF928FC0A, 0xE481BD2CDD8C7142,
 0xEC6D3E64F9A0F60A, 0xC8C9B32CDDA47F42, 0xE04083D3225B81A2, 0xD00093DC2A1B0CEA,
 0x90109CF40E5F1DE5, 0x801FA4D04A4E12A5, 0x8F5780945B4142E5, 0xD773C485542102F5,
 0x06848CC1546185BD, 0xCA48400D98AD6442, 0x06848CC15461A88E, 0xCA48400D98AD6442,
 0x35B7B00DBC09E90A, 0xCA48400D98AD6442, 0xCA48612DBC09E90A, 0x4100F565980D6E42,
 0xC248F5251345662A, 0x0E8439E9DF8676EE, 0xC248F525134ABA22, 0x0E8439E9DF8676EE,
 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC
};

const DECLSPEC_ALIGN(32) BYTE _shellcode_Const[] = {
    0x00, 0x00, 0x00, 0x00,                              //uint32_t unlocker_pid                        _shellcode_[0]
    0x20, 0x90, 0x8C, 0x68,                              //uint32_t timestamp                           _shellcode_[4]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t unlocker_FpsValue_addr              _shellcode_[8]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t Ptr_il2cpp_fps                      _shellcode_[0x10]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t Ptr_Engine_fps                      _shellcode_[0x18]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t hksr_ui_ptr \ Hooked_funcstruct     _shellcode_[0x20]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t hksr_ui_type \ verfiy_func_ptr      _shellcode_[0x28]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t Ptr_Function_link                   _shellcode_[0x30]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t Ptr_struct_NtAPI                    _shellcode_[0x38]
    //Xmmseg org_part        _shellcode_[0x40]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    //Xmmseg hookedpart      _shellcode_[0x50]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t API_MessageBoxA           _shellcode_[0x60]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t API_CloseHandle           _shellcode_[0x68]
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3                                               
	0x55,                                                //push rbp
	0x53,                                                //push rbx
	0x56,                                                //push rsi
    0x57,                                                //push rdi
	0x41, 0x57,                                          //push r15
	0x48, 0x83, 0xEC, 0x70,                              //sub rsp, 0x70
	0x48, 0x8D, 0x6C, 0x24, 0x20,                        //lea rbp, qword [rsp+0x40] 
    0x89,0xCA,                                           //mov edx, ecx
    0xB9, 0xFF, 0xFF, 0x1F, 0x00,                        //mov ecx,1FFFFF
    0x66, 0xE8, 0xF4, 0x02, 0x00, 0x00,                  //call API_OpenProcess
    0x85, 0xC0,                                          //test eax, eax
    0x74, 0x64,                                          //jz return
    0x2E, 0x41, 0x89, 0xC7,                              //mov r15d, eax
    0x44, 0x48, 0x8B, 0x3D, 0x5C, 0xFF, 0xFF, 0xFF,      //mov rdi, qword[unlocker_FpsValue_addr]
    0x4D, 0x31, 0xF6,                                    //xor r14, r14 
    0xBB, 0xF4, 0x01, 0x00, 0x00,                        //mov ebx, 0x1F4        (500ms)
    0x44, 0x48, 0x8D, 0x35, 0x04, 0x00, 0x00, 0x00,      //lea rsi, qword:[Read_tar_fps]
    0x89, 0x5C, 0x24, 0x28,                              //mov dword:[RSP+0x28], ebx
    //Read_tar_fps                                       
    0x4C, 0x8D, 0x44, 0x24, 0x28,                        //lea r8, qword:[RSP+0x28]        
    0x4C, 0x89, 0x74, 0x24, 0x20,                        //mov qword ptr ss:[rsp+20],r14
    0x41, 0xB9, 0x04, 0x00, 0x00, 0x00,                  //mov r9d, 0x4  
    0x48, 0x89, 0xFA,                                    //mov rdx, rdi  
    0x44, 0x89, 0xF9,                                    //mov ecx, esi  
    0x48, 0xE8, 0x34, 0x03, 0x00, 0x00,                  //call API_ReadProcessmem
    0x85, 0xC0,                                          //test eax, eax     
    0x75, 0x10,                                          //jnz continue   
    //read fail                                          
    0x48, 0x83, 0xC6, 0x30,                              //add r15, 0x30         //控制循环范围
	0x44, 0x89, 0xF9,                                    //mov ecx, r15d
    0xE8, 0x74, 0x00, 0x00, 0x00,                        //call Show Errormsg and CloseHandle 
	0x0F, 0x1F, 0x40, 0x00,                              //nop
    //continue                                           
    0x8B, 0x4C, 0x24, 0x28,                              //mov ecx, qword:[RSP+0x28]      
    0x48, 0xE8, 0x16, 0x00, 0x00, 0x00,                  //call Sync_auto
    0x89, 0xD9,                                          //mov ecx, ebx
    0x48, 0xE8, 0x4E, 0x03, 0x00, 0x00,                  //call API_Sleep
    0xFF, 0xE6,                                          //jmp rsi
    //return                                             
    0x48, 0x83, 0xC4, 0x70,                              //add rsp, 0x70
	0x41, 0x5F,                                          //pop r15
	0x5F,                                                //pop rdi
	0x5E,                                                //pop rsi
	0x5B,                                                //pop rbx
	0x5D,                                                //pop rbp
	0xC3, 											     //ret
	//int3
    0xCC,       
    //int3                                               
    0x44, 0x48, 0x8B, 0x05, 0xF8, 0xFE, 0xFF, 0xFF,      //mov  rax, qword ptr ds:[il2cpp_fps]
    0x48, 0x85, 0xC0,                                    //test rax, rax
    0x74, 0x1B,                                          //jz Write
    //read_game_set                                      
    0x2E, 0x8B, 0x00,                                    //mov eax, qword ptr ss:[rax]
    0x83, 0xF8, 0x1E,                                    //cmp eax, 0x1E 
    0x74, 0x0D,                                          //je set 60
    0x83, 0xF8, 0x2D,                                    //cmp eax, 0x2D
    0x74, 0x0E,                                          //je Sync_unlocker
    0x2E, 0xB9, 0xE8, 0x03, 0x00, 0x00,                  //mov ecx, 0x3E8                    
    0xEB, 0x06,                                          //jmp Write
    0x2E, 0xB9, 0x3C, 0x00, 0x00, 0x00,                  //mov ecx, 0x3C              
    //Write                                              
    0x44, 0x48, 0x8B, 0x05, 0xD8, 0xFE, 0xFF, 0xFF,      //mov rax, qword ptr ds:[engine_fps]
    0x89, 0x08,                                          //mov dword ptr ds:[rax], ecx  
    0x44, 0x48, 0x8B, 0x05, 0xE6, 0xFE, 0xFF, 0xFF,      //mov rax, qword ptr ds:[Ptr_Function_link]
    0x48, 0x85, 0xC0,                                    //test rax, rax 
    0x75, 0x01,                                          //jnz callproc
    0xC3,                                                //ret
    0xFF, 0xE0,                                          //jmp rax
    //int3  
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,      
    //int3    
	0x48, 0x83, 0xEC, 0x68, 							        //sub rsp, 0x68                   
	0xFF, 0x15, 0xFE, 0xFE, 0xFF, 0xFF, 			            //call [API_closehandle]
	0x31, 0xC9,										            //xor ecx, ecx
	0x3E, 0x48, 0x8D, 0x54, 0x24, 0x20,                         //lea rdx, [rsp+0x20]             
	0x4C, 0x8D, 0x42, 0x10, 							        //lea r8, [rsp+0x10]              
	0x48, 0xB8, 0x53, 0x79, 0x6E, 0x63, 0x20, 0x66, 0x61, 0x69, //mov rax, 'Sync fai'      
	0x48, 0xC7, 0x42, 0x08, 0x6C, 0x65, 0x64, 0x21,             //mov qword ptr [rdx+8], 'led!'   
	0x48, 0x89, 0x42, 0x00,                                     //mov qword ptr [rdx], rax        
	0x41, 0xC7, 0x00, 0x45, 0x72, 0x72, 0x6F,                   //mov dword ptr [r8], 'Error'     
	0x66, 0x41, 0xC7, 0x40, 0x04, 0x72, 0x00,                   //mov word ptr [r8+4], '!'        
	0x41, 0xB9, 0x10, 0x00, 0x00, 0x00, 		                //mov r9d, 0x10 (MB_OK)
	0xFF, 0x15, 0xBA, 0xFE, 0xFF, 0xFF, 			            //call [API_MessageBoxA]          
	0x48, 0x83, 0xC4, 0x68,                                     //add rsp, 0x68
	0xC3, 											            //ret
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3 
    0x40, 0x53,                                                 //push rbx                     //entry
	0x48, 0x83, 0xEC, 0x60, 							        //sub rsp, 0x60
	0x4C, 0x48, 0x8D, 0x1D, 0x42, 0xFE, 0xFF, 0xFF, 	        //lea rbx, [code_block]
	0x48, 0x8D, 0x4B, 0x38, 							        //lea rcx, [rbx+0x38]//ntapi_struct
	0xC7, 0x01, 0x60, 0x00, 0x00, 0x00,                         //mov dword ptr [rcx], 0x60
	0x31, 0xD2,                                                 //xor edx, edx
	0x49, 0x89, 0xC8, 								            //mov r8, rcx
	0xE8, 0x3E, 0x04, 0x00, 0x00, 					            //call Init_NtAPI
    0x85, 0xC0, 							        			//test eax, eax
	0x75, 0x1C, 							        			//jnz exit
    0x48, 0x89, 0xD9,   					                    //mov rcx, rbx
	0xBA, 0x00, 0x10, 0x00, 0x00,   		                    //mov edx, 0x1000
	0x41, 0xB8, 0x20, 0x00, 0x00, 0x00, 				        //mov r8d, 0x20
	0x44, 0xE8, 0x46, 0x01, 0x00, 0x00, 				        //call API_VirtualProtect
    0x8B, 0x0B,                  			                    //mov ecx, [rbx]
	0xE8, 0x8F, 0xFE, 0xFF, 0xFF, 					            //call main_sync_start
    0x90,
	0x48, 0x83, 0xC4, 0x60, 							        //add rsp, 0x60
    0x5B,                                                       //pop rbx
	0xC3, 												        //ret
	//int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3
	0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,                    //push r15,r14,r13,r12                 //hooked_func VA + 0x200
	0x53, 0x55, 0x56, 0x57,                                            //push rbx,rbp,rsi,rdi   
    0x48, 0x83, 0xEC, 0x68,                                            //sub rsp, 0x68
    0x44, 0x48, 0x8B, 0x35, 0x08, 0xFE, 0xFF, 0xFF,                    //mov rsi, [Hooked_funcstruct]
    0x40, 0x48, 0x8B, 0x1D, 0x08, 0xFE, 0xFF, 0xFF,                    //mov rbx, [verfiy_func_ptr]
    0x48, 0x8D, 0xAC, 0x24, 0x28, 0x00, 0x00, 0x00,                    //lea rbp, [rsp + 0x28]
    0x48, 0x89, 0x4D, 0x08,                                            //mov [rbp + 8], rcx
	0x48, 0x89, 0x55, 0x10,							                   //mov [rbp + 0x10], rdx  
	0x4C, 0x89, 0x45, 0x18, 						                   //mov [rbp + 0x18], r8
	0x4C, 0x89, 0x4D, 0x20, 						                   //mov [rbp + 0x20], r9
	0x4C, 0x48, 0x8D, 0x3D, 0xD0, 0x00, 0x00, 0x00,                    //lea rdi, [mem_protect_RXW]
	0x4D, 0x31, 0xE4, 								                   //xor r12, r12
    0x66,0x66,0x66,0x66,0x66,0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00,  //nop
	0x4E, 0x8D, 0x2C, 0x26, 							               //lea r13, [rsi + r12]
	0x49, 0x8B, 0x4D, 0x00, 							               //mov rcx, [r13]
	0x49, 0x89, 0xCE, 								                   //mov r14, rcx
	0x48, 0x85, 0xC9, 								                   //test rcx, rcx
	0x74, 0x18, 										               //jz break
	0xFF, 0xD7, 									                   //call rdi
	0x85, 0xC0, 										               //test eax, eax
	0x74, 0x0C, 										               //jz skip
	0xF3, 0x41, 0x0F, 0x6F, 0x45, 0x20, 				               //movdqu xmm0, [r13 + 0x20]
	0xF3, 0x41, 0x0F, 0x7F, 0x46, 0x00, 				               //movdqu [r14], xmm0
	0x49, 0x83, 0xC4, 0x30, 							               //add r12, 0x30
	0xEB, 0xD8, 										               //jmp continue
	0x48, 0x89, 0xD9, 								                   //mov rcx, rbx
	0xE8, 0x90, 0x00, 0x00, 0x00,   			                       //call mem_protect_RXW
	0x48, 0x8B, 0x4D, 0x08, 						                   //mov rcx, [rbp + 8]
	0x48, 0x8B, 0x55, 0x10, 						                   //mov rdx, [rbp + 0x10]
	0x4C, 0x8B, 0x45, 0x18,     		                               //mov r8, [rbp + 0x18]
	0x4C, 0x8B, 0x4D, 0x20,     	                                   //mov r9, [rbp + 0x20]
	0xF3, 0x0F, 0x6F, 0x05, 0xA8, 0xFD, 0xFF, 0xFF,	                   //movdqu xmm0, [org_pattern]
	0xF3, 0x0F, 0x7F, 0x03, 							               //movdqu [rbx], xmm0
	0xFF, 0xD3, 										               //call rbx
	0x49, 0x97, 										               //xchg r15, rax
	0xF3, 0x0F, 0x6F, 0x05, 0xA8, 0xFD, 0xFF, 0xFF, 				   //movdqu xmm0, [Hooked_pattern]
	0xF3, 0x0F, 0x7F, 0x03, 							               //movdqu [rbx], xmm0
    0x4C, 0x48, 0x8D, 0x3D, 0x6C, 0x00, 0x00, 0x00,                    //lea rdi, [mem_protect_RX]
    0x4D, 0x31, 0xE4, 								                   //xor r12, r12
    0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,		       //nop
    0x4E, 0x8D, 0x2C, 0x26, 							               //lea r13, [rsi + r12]
    0x49, 0x8B, 0x4D, 0x00, 							               //mov rcx, [r13]
    0x49, 0x89, 0xCE, 								                   //mov r14, rcx
    0x48, 0x85, 0xC9, 								                   //test rcx, rcx
    0x74, 0x14, 										               //jz break
    0xF3, 0x41, 0x0F, 0x6F, 0x45, 0x10, 				               //movdqu xmm0, [r13 + 0x10]
    0xF3, 0x41, 0x0F, 0x7F, 0x46, 0x00, 				               //movdqu [r14], xmm0
    0xFF, 0xD7, 									                   //call rdi
    0x49, 0x83, 0xC4, 0x30, 							               //add r12, 0x30
    0xEB, 0xDC, 										               //jmp continue
	0x48, 0x89, 0xD9, 								                   //mov rcx, rbx
	0x48, 0xFF, 0xD7,             			                           //call rdi
	0x49, 0x97, 										               //xchg r15, rax
	0x48, 0x83, 0xC4, 0x68, 							               //add rsp, 0x68
	0x5F, 0x5E, 0x5D, 0x5B,                                            //pop rdi, rsi, rbp, rbx,
    0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F,	                   //pop r15,r14,r13,r12
    0xC3,                                                              //ret
	//int3
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 
    //int3
    0x41, 0xB8, 0x40, 0x00, 0x00, 0x00,    //Protect_RXW
    0xBA, 0x00, 0x20, 0x00, 0x00, 
    0xE9, 0x10, 0x00, 0x00, 0x00, 
	0x41, 0xB8, 0x20, 0x00, 0x00, 0x00,    //Protect_RX
    0xBA, 0x00, 0x20, 0x00, 0x00, 
    0xE9, 0x00, 0x00, 0x00, 0x00, 
    //Virtualprotect
	0x48, 0x89, 0x54, 0x24, 0x18, 
    0x48, 0x83, 0xEC, 0x48, 
    0x4C, 0x8B, 0x15, 0xF8, 0xFC, 0xFF, 0xFF,
    0x49, 0xF7, 0xD2, 
    0xC7, 0x44, 0x24, 0x70, 0x00, 0x00, 0x00, 0x00, 
    0x45, 0x89, 0xC1, 
    0x4C, 0x8D, 0x44, 0x24, 0x60, 
    0x48, 0x81, 0xE1, 0x00, 0xF0, 0xFF, 0xFF, 
    0x48, 0x89, 0x4C, 0x24, 0x30, 
    0x48, 0x8D, 0x54, 0x24, 0x30, 
    0x4D, 0x8B, 0x52, 0x00, 
    0x48, 0x8D, 0x44, 0x24, 0x70, 
    0x48, 0x89, 0x44, 0x24, 0x20, 
    0x48, 0x83, 0xC9, 0xFF, 
    0x41, 0xFF, 0x52, 0x38, 
    0x85, 0xC0, 
    0x74, 0x08, 
    0x31, 0xC0,
    0x48, 0x83, 0xC4, 0x48, 
    0xC3, 
    0xCC, 
    0xFF, 0xC0, 
    0x48, 0x83, 0xC4, 0x48, 
    0xC3, 
    0xCC, 0xCC, 0xCC,
    //API_Openprocess
    0x48, 0x83, 0xEC, 0x68, 
    0x4C, 0x8B, 0x05, 0x9D, 0xFC, 0xFF, 0xFF, 
    0x48, 0x33, 0xC0, 
    0x4C, 0x8D, 0x4C, 0x24, 0x20, 
    0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 
    0x0F, 0x57, 0xC0, 
    0x48, 0x89, 0x44, 0x24, 0x28, 
    0x49, 0xF7, 0xD0, 
    0x8B, 0xC2, 
    0x8B, 0xD1, 
    0x0F, 0x11, 0x44, 0x24, 0x30, 
    0x48, 0x89, 0x44, 0x24, 0x20, 
    0x48, 0x8D, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00, 
    0x0F, 0x11, 0x44, 0x24, 0x40, 
    0xC7, 0x44, 0x24, 0x30, 0x30, 0x00, 0x00, 0x00, 
    0x0F, 0x11, 0x44, 0x24, 0x50, 
    0xC7, 0x44, 0x24, 0x48, 0x02, 0x00, 0x00, 0x00, 
    0x49, 0x8B, 0x00, 
    0x4C, 0x8D, 0x44, 0x24, 0x30, 
    0xFF, 0x90, 0x48, 0x00, 0x00, 0x00, 
    0x85, 0xC0, 
    0x74, 0x08, 
    0x33, 0xC0, 
    0x48, 0x83, 0xC4, 0x68, 
    0xC3, 
    0xCC,
    0x48, 0x8B, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 
    0x48, 0x83, 0xC4, 0x68, 
    0xC3, 
    //
    0xCC, 0xCC, 0xCC,
    //
    0x48, 0x83, 0xEC, 0x38,                     //API_ReadProcessmem
    0x48, 0x8B, 0x05, 0x1D, 0xFC, 0xFF, 0xFF, 
    0x48, 0xF7, 0xD0, 
    0x48, 0x8B, 0x00, 
    0x4C, 0x8B, 0x50, 0x30, 
    0x48, 0x8D, 0x44, 0x24, 0x60, 
    0x48, 0x89, 0x44, 0x24, 0x20, 
    0x41, 0xFF, 0xD2, 
    0x85, 0xC0, 
    0x74, 0x08, 
    0x31, 0xC0, 
    0x48, 0x83, 0xC4, 0x38, 
    0xC3, 
    0xCC, 
    0xFF, 0xC0,
    0x48, 0x83, 0xC4, 0x38, 
    0xC3, 
    //
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //
    0x40, 0x53,                                 //API_Sleep
    0x48, 0x83, 0xEC, 0x20, 
    0x48, 0x8B, 0x15, 0xDB, 0xFB, 0xFF, 0xFF, 
    0x8B, 0xD9, 
    0x48, 0x69, 0xCB, 0xF0, 0xD8, 0xFF, 0xFF, 
    0x48, 0xF7, 0xD2, 
    0x48, 0x8B, 0x12, 
    0x48, 0x89, 0x4C, 0x24, 0x38, 
    0x33, 0xC9, 
    0x48, 0x8B, 0x42, 0x68, 
    0x48, 0x8D, 0x54, 0x24, 0x38, 
    0xFF, 0xD0, 
    0x48, 0x83, 0xC4, 0x20, 
    0x5B, 
    0xC3, 
    //
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //getprocaddr
    0x48, 0x89, 0x74, 0x24, 0x20, 
    0x57, 
    0x41, 0x55,
    0x41, 0x56, 
    0x41, 0x57, 
    0x48, 0x8B, 0xF2, 
    0x4C, 0x8B, 0xC9, 
    0x48, 0x85, 0xC9, 
    0x0F, 0x84, 0x43, 0x01, 0x00, 0x00, 
    0x48, 0x85, 0xD2, 
    0x0F, 0x84, 0x3A, 0x01, 0x00, 0x00, 
    0xB8, 0x4D, 0x5A, 0x00, 0x00, 
    0x66, 0x39, 0x01, 
    0x0F, 0x85, 0x2C, 0x01, 0x00, 0x00, 
    0x8B, 0x41, 0x3C, 0x81, 0x3C, 0x08, 0x50, 0x45, 0x00, 0x00, 0x0F, 0x85, 0x1C, 0x01,
    0x00, 0x00, 0x44, 0x8B, 0xBC, 0x08, 0x88, 0x00, 0x00, 0x00, 0x45, 0x85, 0xFF, 0x0F, 0x84, 0x0B,
    0x01, 0x00, 0x00, 0x44, 0x8B, 0xAC, 0x08, 0x8C, 0x00, 0x00, 0x00, 0x41, 0xBE, 0xFF, 0xFF, 0xFF,
    0xFF, 0x4A, 0x8D, 0x3C, 0x39, 0x48, 0x81, 0xFA, 0xFF, 0xFF, 0x00, 0x00, 0x77, 0x1A, 0x2B, 0x77,
    0x10, 0x3B, 0x77, 0x14, 0x0F, 0x83, 0xE4, 0x00, 0x00, 0x00, 0x8B, 0x47, 0x1C, 0x48, 0x03, 0xC1,
    0x8B, 0x14, 0xB0, 0xE9, 0xB3, 0x00, 0x00, 0x00, 0x44, 0x8B, 0x57, 0x18, 0x45, 0x85, 0xD2, 0x0F,
    0x84, 0x94, 0x00, 0x00, 0x00, 0x4C, 0x89, 0x64, 0x24, 0x38, 0x45, 0x33, 0xDB, 0x44, 0x8B, 0x67,
    0x20, 0x4D, 0x03, 0xE1, 0x41, 0x83, 0xEA, 0x01, 0x78, 0x7A, 0x48, 0x89, 0x5C, 0x24, 0x28, 0x48,
    0x89, 0x6C, 0x24, 0x30, 0x66, 0x66, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x43, 0x8D, 0x1C, 0x1A, 0x4C, 0x8B, 0xC6, 0xD1, 0xFB, 0x41, 0x8B, 0x04, 0x9C, 0x49, 0x03, 0xC1,
    0x4C, 0x2B, 0xC0, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x0F, 0xB6, 0x0C, 0x00, 0x0F, 0xB6, 0x10, 0x48, 0x8D, 0x40, 0x01, 0x84, 0xC9, 0x74, 0x04,
    0x3A, 0xCA, 0x74, 0xEC, 0x3A, 0xCA, 0x73, 0x06, 0x44, 0x8D, 0x53, 0xFF, 0xEB, 0x17, 0x76, 0x06,
    0x44, 0x8D, 0x5B, 0x01, 0xEB, 0x0F, 0x8B, 0x4F, 0x24, 0x45, 0x8D, 0x5A, 0x01, 0x49, 0x03, 0xC9,
    0x44, 0x0F, 0xB7, 0x34, 0x59, 0x45, 0x3B, 0xDA, 0x7E, 0xA6, 0x48, 0x8B, 0x6C, 0x24, 0x30, 0x48,
    0x8B, 0x5C, 0x24, 0x28, 0x4C, 0x8B, 0x64, 0x24, 0x38, 0x44, 0x3B, 0x77, 0x14, 0x73, 0x2F, 0x8B,
    0x47, 0x1C, 0x49, 0x03, 0xC1, 0x41, 0x8B, 0xCE, 0x8B, 0x14, 0x88, 0x85, 0xD2, 0x74, 0x1F, 0x41,
    0x3B, 0xD7, 0x72, 0x08, 0x43, 0x8D, 0x04, 0x2F, 0x3B, 0xD0, 0x72, 0x12, 0x8B, 0xC2, 0x49, 0x03,
    0xC1, 
    0x48, 0x8B, 0x74, 0x24, 0x40, 
    0x41, 0x5F, 
    0x41, 0x5E, 
    0x41, 0x5D, 
    0x5F, 
    0xC3, 
    0x48, 0x8B, 0x74, 0x24, 0x40, 
    0x33, 0xC0, 
    0x41, 0x5F, 
    0x41, 0x5E, 
    0x41, 0x5D, 
    0x5F, 
    0xC3, 
    //getprocaddr_end
    0xCC, 0xCC, 0xCC, 
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //Init_NtAPI
    0x4C, 0x8B, 0xDC, 
    0x55, 
    0x56, 
    0x57, 
    0x49, 0x8D, 0x6B, 0xB8, 
    0x48, 0x81, 0xEC, 0x30, 0x01, 0x00, 0x00, 
    0x8B, 0x01, 0x49, 0x8B, 0xF0, 0x65, 0x48, 0x8B, 0x08, 0x48, 0x8B, 0x41, 0x18, 0x48, 0x8B,
    0x48, 0x20, 0x48, 0x8B, 0x01, 0x48, 0x8B, 0x78, 0x20, 0x48, 0x85, 0xFF, 0x0F, 0x84, 0xD5, 0x07,
    0x00, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x83, 0x78, 0x20, 0x00, 0x0F, 0x84, 0xC7, 0x07, 0x00, 0x00,
    0x49, 0x89, 0x5B, 0x08, 0x4D, 0x89, 0x73, 0x10, 0x45, 0x33, 0xF6, 0x8B, 0xDA, 0x85, 0xD2, 0x75,
    0x46, 0x48, 0xB8, 0x88, 0x96, 0x91, 0x9A, 0xA0, 0x98, 0x9A, 0x8B, 0x48, 0x8D, 0x4C, 0x24, 0x38,
    0x48, 0x89, 0x44, 0x24, 0x38, 0xB2, 0x02, 0x48, 0xB8, 0xA0, 0x89, 0x9A, 0x8D, 0x8C, 0x96, 0x90,
    0x91, 0x48, 0x89, 0x44, 0x24, 0x40, 0xE8, 0xA5, 0x07, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x38,
    0x4C, 0x89, 0x74, 0x24, 0x48, 0x48, 0x8B, 0xCF, 0xE8, 0xF3, 0xFD, 0xFF, 0xFF, 0x48, 0x85, 0xC0,
    0x74, 0x05, 0xFF, 0xD0, 0x48, 0x8B, 0x18, 0x48, 0xB8, 0xB1, 0x8B, 0xBE, 0x93, 0x93, 0x90, 0x9C,
    0x9E, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0x48, 0x89, 0x44, 0x24, 0x38, 0xB2, 0x03, 0x48, 0xB8, 0x8B,
    0x9A, 0xA9, 0x96, 0x8D, 0x8B, 0x8A, 0x9E, 0x48, 0x89, 0x44, 0x24, 0x40, 0x48, 0xB8, 0x93, 0xB2,
    0x9A, 0x92, 0x90, 0x8D, 0x86, 0x32, 0x48, 0x89, 0x44, 0x24, 0x48, 0xE8, 0x50, 0x07, 0x00, 0x00,
    0x48, 0x8D, 0x54, 0x24, 0x38, 0x44, 0x88, 0x74, 0x24, 0x4F, 0x48, 0x8B, 0xCF, 0xE8, 0x9E, 0xFD,
    0xFF, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x16, 0x48, 0x85, 0xDB, 0x75, 0x18, 0x48, 0x8D, 0x55, 0xEC,
    0x48, 0x8B, 0xC8, 0xE8, 0x58, 0x07, 0x00, 0x00, 0x83, 0xF8, 0x01, 0x74, 0x0B, 0xB8, 0x02, 0xC0,
    0x00, 0x00, 0xEB, 0x7F, 0x48, 0x89, 0x45, 0x88, 0x48, 0xB8, 0xB1, 0x8B, 0xB9, 0x8D, 0x9A, 0x9A,
    0xA9, 0x96, 0x4C, 0x89, 0xBC, 0x24, 0x60, 0x01, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x38, 0x48,
    0x8D, 0x4C, 0x24, 0x38, 0x48, 0xB8, 0x90, 0x8D, 0x86, 0xE6, 0x9E, 0x93, 0xB2, 0x9A, 0x49, 0xBF,
    0x8D, 0x8B, 0x8A, 0x9E, 0x93, 0xB2, 0x9A, 0x92, 0xB2, 0x03, 0x48, 0x89, 0x44, 0x24, 0x48, 0x4C,
    0x89, 0x7C, 0x24, 0x40, 0xE8, 0xD7, 0x06, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x38, 0x44, 0x88,
    0x74, 0x24, 0x4B, 0x48, 0x8B, 0xCF, 0xE8, 0x25, 0xFD, 0xFF, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x16,
    0x48, 0x85, 0xDB, 0x75, 0x39, 0x48, 0x8D, 0x55, 0xF0, 0x48, 0x8B, 0xC8, 0xE8, 0xDF, 0x06, 0x00,
    0x00, 0x83, 0xF8, 0x01, 0x74, 0x2C, 0xB8, 0x03, 0xC0, 0x00, 0x00, 0x4C, 0x8B, 0xBC, 0x24, 0x60,
    0x01, 0x00, 0x00, 0x48, 0x8B, 0x9C, 0x24, 0x50, 0x01, 0x00, 0x00, 0x4C, 0x8B, 0xB4, 0x24, 0x58,
    0x01, 0x00, 0x00, 0x48, 0x81, 0xC4, 0x30, 0x01, 0x00, 0x00, 0x5F, 0x5E, 0x5D, 0xC3, 0x48, 0x89,
    0x45, 0x90, 0x48, 0xB8, 0xB1, 0x8B, 0xAD, 0x9A, 0x9E, 0x9B, 0xA9, 0x96, 0x4C, 0x89, 0x7C, 0x24,
    0x40, 0x48, 0x89, 0x44, 0x24, 0x38, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0x48, 0xB8, 0x90, 0x8D, 0x86,
    0xF7, 0x93, 0x22, 0xB9, 0x8A, 0xB2, 0x03, 0x48, 0x89, 0x44, 0x24, 0x48, 0xE8, 0x4F, 0x06, 0x00,
    0x00, 0x48, 0x8D, 0x54, 0x24, 0x38, 0x44, 0x88, 0x74, 0x24, 0x4B, 0x48, 0x8B, 0xCF, 0xE8, 0x9D,
    0xFC, 0xFF, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x16, 0x48, 0x85, 0xDB, 0x75, 0x1B, 0x48, 0x8D, 0x55,
    0xF8, 0x48, 0x8B, 0xC8, 0xE8, 0x57, 0x06, 0x00, 0x00, 0x83, 0xF8, 0x01, 0x74, 0x0E, 0xB8, 0x04,
    0xC0, 0x00, 0x00, 0xE9, 0x73, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x45, 0xA0, 0x48, 0xB8, 0xB1, 0x8B,
    0xAF, 0x8D, 0x90, 0x8B, 0x9A, 0x9C, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0x48, 0x89, 0x44, 0x24, 0x38,
    0xB2, 0x03, 0x48, 0xB8, 0x8B, 0xA9, 0x96, 0x8D, 0x8B, 0x8A, 0x9E, 0x93, 0x48, 0x89, 0x44, 0x24,
    0x40, 0x48, 0xB8, 0xB2, 0x9A, 0x92, 0x90, 0x8D, 0x86, 0xE9, 0xAF, 0x48, 0x89, 0x44, 0x24, 0x48,
    0xE8, 0xDB, 0x05, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x38, 0x44, 0x88, 0x74, 0x24, 0x4E, 0x48,
    0x8B, 0xCF, 0xE8, 0x29, 0xFC, 0xFF, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x16, 0x48, 0x85, 0xDB, 0x75,
    0x1B, 0x48, 0x8D, 0x55, 0xFC, 0x48, 0x8B, 0xC8, 0xE8, 0xE3, 0x05, 0x00, 0x00, 0x83, 0xF8, 0x01,
    0x74, 0x0E, 0xB8, 0x06, 0xC0, 0x00, 0x00, 0xE9, 0xFF, 0xFE, 0xFF, 0xFF, 0x48, 0x89, 0x45, 0xA8,
    0x48, 0xB8, 0xB1, 0x8B, 0xB0, 0x8F, 0x9A, 0x91, 0xAF, 0x8D, 0x48, 0x8D, 0x4C, 0x24, 0x60, 0x48,
    0x89, 0x44, 0x24, 0x60, 0xB2, 0x02, 0x48, 0xB8, 0x90, 0x9C, 0x9A, 0x8C, 0x8C, 0x1A, 0xBF, 0xA2,
    0x48, 0x89, 0x44, 0x24, 0x68, 0xE8, 0x76, 0x05, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x60, 0x44,
    0x88, 0x74, 0x24, 0x6D, 0x48, 0x8B, 0xCF, 0xE8, 0xC4, 0xFB, 0xFF, 0xFF, 0x48, 0x85, 0xC0, 0x74,
    0x16, 0x48, 0x85, 0xDB, 0x75, 0x1B, 0x48, 0x8D, 0x55, 0x04, 0x48, 0x8B, 0xC8, 0xE8, 0x7E, 0x05,
    0x00, 0x00, 0x83, 0xF8, 0x01, 0x74, 0x0E, 0xB8, 0x08, 0xC0, 0x00, 0x00, 0xE9, 0x9A, 0xFE, 0xFF,
    0xFF, 0x48, 0x89, 0x45, 0xB8, 0x48, 0xB8, 0xB1, 0x8B, 0xBB, 0x9A, 0x93, 0x9E, 0x86, 0xBA, 0x48,
    0x8D, 0x4D, 0x18, 0x48, 0x89, 0x45, 0x18, 0xB2, 0x02, 0x48, 0xB8, 0x87, 0x9A, 0x9C, 0x8A, 0x8B,
    0x96, 0x90, 0x91, 0x48, 0x89, 0x45, 0x20, 0xE8, 0x14, 0x05, 0x00, 0x00, 0x48, 0x8D, 0x55, 0x18,
    0x4C, 0x89, 0x75, 0x28, 0x48, 0x8B, 0xCF, 0xE8, 0x64, 0xFB, 0xFF, 0xFF, 0x48, 0x85, 0xC0, 0x0F,
    0x84, 0xD8, 0x04, 0x00, 0x00, 0x48, 0x89, 0x45, 0xD8, 0x48, 0x85, 0xDB, 0x0F, 0x85, 0xFD, 0x03,
    0x00, 0x00, 0x8B, 0x48, 0x12, 0x4C, 0x8D, 0x40, 0x12, 0x81, 0xE1, 0xFF, 0xFF, 0xFF, 0x00, 0x81,
    0xF9, 0x0F, 0x05, 0xC3, 0x00, 0x74, 0x17, 0x4C, 0x8D, 0x40, 0x08, 0x8B, 0x40, 0x08, 0x25, 0xFF,
    0xFF, 0xFF, 0x00, 0x3D, 0x0F, 0x05, 0xC3, 0x00, 0x0F, 0x85, 0x9F, 0x04, 0x00, 0x00, 0x8B, 0x45,
    0xEC, 0x48, 0x89, 0x44, 0x24, 0x40, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x0B, 0xC2, 0x48, 0x8B, 0xC8, 0x81, 0xE1, 0xFF, 0x07,
    0x00, 0x00, 0x48, 0xC1, 0xE1, 0x04, 0x49, 0x03, 0xC8, 0x8B, 0x01, 0x25, 0xFF, 0xFF, 0xFF, 0x00,
    0x3D, 0x0F, 0x05, 0xC3, 0x00, 0x75, 0xD9, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x0B, 0xC2, 0x48, 0x8B, 0xD8, 0x81, 0xE3, 0xFF, 0x07,
    0x00, 0x00, 0x48, 0xC1, 0xE3, 0x04, 0x49, 0x03, 0xD8, 0x8B, 0x13, 0x81, 0xE2, 0xFF, 0xFF, 0xFF,
    0x00, 0x81, 0xFA, 0x0F, 0x05, 0xC3, 0x00, 0x75, 0xD7, 0x48, 0xF7, 0xD1, 0xC7, 0x44, 0x24, 0x28,
    0x04, 0x00, 0x00, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x38, 0x4C, 0x8D, 0x4C, 0x24, 0x30, 0x48, 0x8D,
    0x4C, 0x24, 0x38, 0x48, 0xC7, 0x44, 0x24, 0x48, 0xFF, 0xFF, 0xFF, 0xFF, 0x45, 0x33, 0xC0, 0x48,
    0xC7, 0x44, 0x24, 0x30, 0x00, 0x80, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x58, 0x4C, 0x89, 0x74,
    0x24, 0x58, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x30, 0x00, 0x00, 0xE8, 0x11, 0x05, 0x00, 0x00, 0x85,
    0xC0, 0x0F, 0x88, 0x64, 0xFD, 0xFF, 0xFF, 0x48, 0x8B, 0x44, 0x24, 0x58, 0x48, 0x8D, 0xB8, 0x00,
    0x10, 0x00, 0x00, 0x48, 0x89, 0x38, 0x4C, 0x8B, 0x44, 0x24, 0x58, 0x49, 0x81, 0xC0, 0x00, 0x20,
    0x00, 0x00, 0x44, 0x89, 0x75, 0x68, 0x48, 0x81, 0x6C, 0x24, 0x30, 0x00, 0x20, 0x00, 0x00, 0x4C,
    0x89, 0x44, 0x24, 0x60, 0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0xF7, 0xD3, 0x48, 0x0B, 0xD0,
    0x48, 0x8D, 0x44, 0x24, 0x70, 0x48, 0x33, 0xD0, 0x48, 0x8D, 0x45, 0xE0, 0x48, 0x8B, 0xCA, 0x48,
    0xC1, 0xE9, 0x20, 0x4C, 0x8B, 0xC9, 0x4C, 0x8B, 0xD1, 0x4C, 0x33, 0xCA, 0x41, 0xF7, 0xD2, 0x4C,
    0x33, 0xC8, 0x41, 0x0F, 0xB7, 0xC9, 0x45, 0x33, 0xD1, 0x49, 0x8B, 0xC1, 0x48, 0xC1, 0xE8, 0x10,
    0x66, 0x41, 0x33, 0xC1, 0x49, 0xB9, 0xC7, 0x44, 0x24, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0x44, 0x0F,
    0xB6, 0xD8, 0x48, 0x33, 0xC1, 0x0F, 0xB6, 0xC0, 0x48, 0x83, 0xC0, 0x20, 0x49, 0xC1, 0xE3, 0x04,
    0x48, 0xC1, 0xE0, 0x04, 0x4D, 0x03, 0xD8, 0x4E, 0x8D, 0x04, 0x18, 0x0F, 0xB7, 0xC2, 0x66, 0xF7,
    0xD0, 0x49, 0x89, 0x58, 0x08, 0x48, 0x33, 0xC1, 0x41, 0xC7, 0x40, 0x10, 0x50, 0x48, 0x8D, 0x05,
    0x0F, 0xB6, 0xD0, 0x48, 0xB8, 0x4C, 0x87, 0x14, 0x24, 0x59, 0x50, 0x48, 0xB9, 0x49, 0x89, 0x00,
    0x48, 0x83, 0xC2, 0x03, 0x41, 0xC6, 0x40, 0x28, 0xC3, 0x48, 0xC1, 0xE2, 0x04, 0x49, 0x03, 0xD0,
    0x41, 0x0F, 0xB6, 0xCA, 0xC1, 0xE1, 0x04, 0x48, 0x03, 0xCA, 0x8D, 0x41, 0x30, 0x41, 0x2B, 0xC0,
    0x83, 0xE8, 0x18, 0x41, 0x89, 0x40, 0x14, 0x48, 0x8B, 0xC2, 0x48, 0xC1, 0xE0, 0x20, 0x48, 0x0D,
    0x48, 0xC7, 0x04, 0x24, 0x49, 0x89, 0x40, 0x18, 0x48, 0x8B, 0xC2, 0x49, 0x23, 0xC1, 0x48, 0x0D,
    0xC7, 0x44, 0x24, 0x04, 0x49, 0x89, 0x40, 0x20, 0x48, 0xB8, 0x48, 0x8D, 0xA4, 0x24, 0x00, 0xFF,
    0xFF, 0xFF, 0x48, 0x89, 0x41, 0x30, 0x48, 0xB8, 0x48, 0x8D, 0xA4, 0x24, 0x20, 0x02, 0x00, 0x00,
    0x48, 0x89, 0x41, 0x38, 0x48, 0xB8, 0x48, 0x87, 0x04, 0x24, 0x48, 0x94, 0x48, 0x8B, 0x48, 0x89,
    0x41, 0x40, 0x48, 0xB8, 0x68, 0x08, 0x48, 0x8B, 0x40, 0x00, 0x48, 0x83, 0x48, 0x89, 0x41, 0x48,
    0x48, 0xB8, 0x50, 0x48, 0x8B, 0xC4, 0x48, 0x8D, 0xA4, 0x24, 0xC7, 0x41, 0x50, 0xC4, 0x10, 0xC3,
    0xCC, 0x48, 0x89, 0x02, 0x48, 0xB8, 0x80, 0xF9, 0xFF, 0xFF, 0x48, 0x87, 0x2C, 0x24, 0x48, 0x89,
    0x42, 0x08, 0x48, 0xB8, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x89, 0x04, 0x24, 0x48, 0x89, 0x42, 0x10,
    0x48, 0xB8, 0x48, 0x8D, 0xA4, 0x24, 0xE0, 0xFE, 0xFF, 0xFF, 0x48, 0x89, 0x42, 0x18, 0x48, 0xB8,
    0xFF, 0x30, 0x89, 0x28, 0x48, 0x8D, 0x40, 0x08, 0x48, 0x89, 0x42, 0x20, 0x48, 0xB8, 0x0F, 0x10,
    0x40, 0x30, 0x0F, 0x11, 0x44, 0x24, 0x48, 0x89, 0x42, 0x28, 0x48, 0xB8, 0x28, 0x0F, 0x10, 0x40,
    0x40, 0x0F, 0x11, 0x44, 0x48, 0x89, 0x42, 0x30, 0x48, 0xB8, 0x24, 0x38, 0x0F, 0x10, 0x40, 0x50,
    0x0F, 0x11, 0x48, 0x89, 0x42, 0x38, 0x48, 0xB8, 0x44, 0x24, 0x48, 0x0F, 0x10, 0x40, 0x60, 0x0F,
    0x48, 0x89, 0x42, 0x40, 0x49, 0xB9, 0x44, 0x48, 0xF7, 0xD1, 0xFF, 0xE1, 0xCC, 0xCC, 0x49, 0x8D,
    0x0B, 0x4C, 0x89, 0x4A, 0x50, 0x49, 0xF7, 0xD0, 0x48, 0xB8, 0x11, 0x44, 0x24, 0x58, 0x48, 0x87,
    0x40, 0x00, 0x48, 0x89, 0x42, 0x48, 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0x49, 0x89, 0x43, 0x18, 0x48, 0xBA, 0x51, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0xB9, 0x49, 0x89,
    0x13, 0x4D, 0x89, 0x43, 0x08, 0x4D, 0x89, 0x4B, 0x10, 0x49, 0x89, 0x53, 0x20, 0x4D, 0x89, 0x43,
    0x28, 0x4D, 0x89, 0x4B, 0x30, 0x49, 0x89, 0x43, 0x38, 0x49, 0x89, 0x53, 0x40, 0x4D, 0x89, 0x43,
    0x48, 0x4D, 0x89, 0x4B, 0x50, 0x49, 0x89, 0x43, 0x58, 0x49, 0x89, 0x53, 0x60, 0x48, 0x8D, 0x54,
    0x24, 0x60, 0x4D, 0x89, 0x43, 0x68, 0x4C, 0x8D, 0x44, 0x24, 0x30, 0x4D, 0x89, 0x4B, 0x70, 0x41,
    0xB9, 0x20, 0x00, 0x00, 0x00, 0x49, 0x89, 0x43, 0x78, 0x8B, 0x45, 0xEC, 0x89, 0x41, 0x02, 0x8B,
    0x45, 0x04, 0x48, 0x89, 0x4D, 0x88, 0x48, 0x83, 0xC1, 0x20, 0x89, 0x41, 0x02, 0x8B, 0x45, 0xFC,
    0x48, 0x89, 0x4D, 0xB8, 0x48, 0x83, 0xC1, 0x20, 0x89, 0x41, 0x02, 0x8B, 0x45, 0xF8, 0x48, 0x89,
    0x4D, 0xA8, 0x48, 0x83, 0xC1, 0x20, 0x89, 0x41, 0x02, 0x8B, 0x45, 0xFC, 0x48, 0x89, 0x44, 0x24,
    0x40, 0x48, 0x8D, 0x45, 0x68, 0x48, 0x89, 0x4D, 0xA0, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0x48, 0x89,
    0x44, 0x24, 0x20, 0xE8, 0x78, 0x02, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x88, 0xCB, 0xFA, 0xFF, 0xFF,
    0x0F, 0x28, 0x44, 0x24, 0x70, 0x48, 0x8D, 0x45, 0x68, 0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x20,
    0x00, 0x00, 0x4C, 0x8D, 0x44, 0x24, 0x30, 0x0F, 0x11, 0x07, 0x48, 0x8D, 0x54, 0x24, 0x58, 0x41,
    0xB9, 0x02, 0x00, 0x00, 0x00, 0x0F, 0x28, 0x4D, 0x80, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0x0F, 0x11,
    0x4F, 0x10, 0x48, 0x89, 0x44, 0x24, 0x20, 0x0F, 0x28, 0x45, 0x90, 0x0F, 0x11, 0x47, 0x20, 0x0F,
    0x28, 0x4D, 0xA0, 0x0F, 0x11, 0x4F, 0x30, 0x0F, 0x28, 0x45, 0xB0, 0x0F, 0x11, 0x47, 0x40, 0x0F,
    0x28, 0x4D, 0xC0, 0x0F, 0x11, 0x4F, 0x50, 0x0F, 0x28, 0x45, 0xD0, 0x0F, 0x11, 0x47, 0x60, 0xE8,
    0x0C, 0x02, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x88, 0x5F, 0xFA, 0xFF, 0xFF, 0x48, 0x8B, 0x44, 0x24,
    0x58, 0x48, 0xF7, 0xD0, 0x48, 0x89, 0x06, 0x33, 0xC0, 0xE9, 0x4D, 0xFA, 0xFF, 0xFF, 0xCC, 0x45,
    0x33, 0xC0, 0xC7, 0x44, 0x24, 0x28, 0x04, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x4C, 0x24, 0x60, 0x4C,
    0x89, 0x74, 0x24, 0x30, 0x48, 0x8D, 0x54, 0x24, 0x30, 0x48, 0xC7, 0x44, 0x24, 0x60, 0x00, 0x20,
    0x00, 0x00, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x30, 0x00, 0x00, 0x49, 0x8D, 0x48, 0xFF, 0xFF, 0x55,
    0x88, 0x85, 0xC0, 0x0F, 0x85, 0x12, 0xFA, 0xFF, 0xFF, 0x48, 0x8B, 0x4C, 0x24, 0x30, 0x4C, 0x8D,
    0x44, 0x24, 0x60, 0x41, 0xB9, 0x02, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x30, 0x48, 0x8D,
    0x81, 0xE8, 0x03, 0x00, 0x00, 0x48, 0x89, 0x01, 0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0x48,
    0x8B, 0x44, 0x24, 0x30, 0x0F, 0x28, 0x44, 0x24, 0x70, 0x48, 0x05, 0xE8, 0x03, 0x00, 0x00, 0x48,
    0x89, 0x44, 0x24, 0x30, 0x0F, 0x11, 0x00, 0x0F, 0x28, 0x4D, 0x80, 0x0F, 0x11, 0x48, 0x10, 0x0F,
    0x28, 0x45, 0x90, 0x0F, 0x11, 0x40, 0x20, 0x0F, 0x28, 0x4D, 0xA0, 0x0F, 0x11, 0x48, 0x30, 0x0F,
    0x28, 0x45, 0xB0, 0x0F, 0x11, 0x40, 0x40, 0x0F, 0x28, 0x4D, 0xC0, 0x0F, 0x11, 0x48, 0x50, 0x0F,
    0x28, 0x45, 0xD0, 0x0F, 0x11, 0x40, 0x60, 0x48, 0x8D, 0x45, 0x68, 0x48, 0x89, 0x44, 0x24, 0x20,
    0xFF, 0x55, 0xA8, 0x85, 0xC0, 0x0F, 0x85, 0x90, 0xF9, 0xFF, 0xFF, 0x48, 0x8B, 0x44, 0x24, 0x30,
    0x48, 0xF7, 0xD0, 0x48, 0x89, 0x06, 0x33, 0xC0, 
    0xE9, 0x7E, 0xF9, 0xFF, 0xFF, 
    0xB8, 0xDE, 0xC0, 0xAD, 0xDE, 
    0xE9, 0x74, 0xF9, 0xFF, 0xFF, 
    0xB8, 0x35, 0x01, 0x00, 0xC0, 
    0x48, 0x81, 0xC4, 0x30, 0x01, 0x00, 0x00, 
    0x5F, 
    0x5E, 
    0x5D, 
    0xC3, 
    //Init_API_end
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //dec_str_start
    0x80, 0xC2, 0xFF, 0x74, 0x17, 0x0F, 0xB6, 0xC2, 0x48, 0x8D, 0x04, 0xC1, 0x0F, 0x1F, 0x40, 0x00,
    0x48, 0xF7, 0x10, 0x48, 0x8D, 0x40, 0xF8, 0x80, 0xC2, 0xFF, 0x75, 0xF4, 0x0F, 0xB6, 0xC2, 0x48,
    0xF7, 0x14, 0xC1, 0x48, 0x8D, 0x0C, 0xC1, 
    0xC3, 
    //dec_str_end
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	//paser_syscallnum_start
    0x4C, 0x8B, 0xD2, 0x4C, 0x8B, 0xC1, 0x48, 0x85, 0xC9, 0x0F, 0x84, 0xB9, 0x00, 0x00, 0x00, 0x8B,
    0x01, 0x3D, 0x4C, 0x8B, 0xD1, 0xB8, 0x75, 0x0B, 0x8B, 0x41, 0x04, 0x89, 0x02, 0xB8, 0x01, 0x00,
    0x00, 0x00, 0xC3, 0x3C, 0xE9, 0x74, 0x18, 0xB9, 0xFF, 0x25, 0x00, 0x00, 0x66, 0x3B, 0xC1, 0x74,
    0x0E, 0xB9, 0x48, 0xB8, 0x00, 0x00, 0x66, 0x3B, 0xC1, 0x0F, 0x85, 0x89, 0x00, 0x00, 0x00, 0xB8,
    0x01, 0x00, 0x00, 0x00, 0xB9, 0x10, 0x00, 0x00, 0x00, 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x8B, 0xD1, 0x4D, 0x8B, 0xC8, 0x4C, 0x2B, 0xCA, 0x41, 0x81, 0x39, 0x4C, 0x8B, 0xD1, 0xB8, 0x74,
    0x46, 0x42, 0x81, 0x3C, 0x02, 0x4C, 0x8B, 0xD1, 0xB8, 0x4E, 0x8D, 0x0C, 0x02, 0x74, 0x10, 0x83,
    0xC1, 0x10, 0xFF, 0xC0, 0x83, 0xF8, 0x20, 0x76, 0xD7, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x83,
    0xC1, 0x04, 0x46, 0x8B, 0x04, 0x01, 0x41, 0x8B, 0xD0, 0x44, 0x2B, 0xC0, 0x8B, 0xC8, 0xD1, 0xE9,
    0xB8, 0x01, 0x00, 0x00, 0x00, 0x2B, 0xD1, 0x41, 0x81, 0x79, 0x08, 0xF6, 0x04, 0x25, 0x08, 0x44,
    0x0F, 0x44, 0xC2, 0x45, 0x89, 0x02, 0xC3, 0x8B, 0xD0, 0xD1, 0xEA, 0x41, 0x81, 0x79, 0x08, 0xF6,
    0x04, 0x25, 0x08, 0x0F, 0x45, 0xD0, 0x83, 0xC1, 0xFC, 0x4C, 0x2B, 0xC1, 
    0xB8, 0x01, 0x00, 0x00, 0x00, 
    0x41, 0x03, 0x10, 
    0x41, 0x89, 0x12, 
    0xC3, 
    0x33, 0xC0, 
    0xC3, 
    //paser_syscallnum_end
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //syscall_part
    0x48, 0xFF, 0x71, 0x08, 0x4C, 0x8B, 0x51, 0x10, 0x48, 0x8B, 0x49, 0x00, 0x44, 0x48, 0x8D, 0x05,
    0x6C, 0x00, 0x00, 0x00, 0x50, 0x48, 0x8B, 0xC4, 0x48, 0x8D, 0xA4, 0x24, 0x80, 0xF9, 0xFF, 0xFF,
    0x48, 0x87, 0x2C, 0x24, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x89, 0x04, 0x24, 0x48, 0x8D, 0xA4, 0x24,
    0xE0, 0xFE, 0xFF, 0xFF, 0xFF, 0x30, 0x89, 0x28, 0x48, 0x8D, 0x40, 0x08, 0x0F, 0x10, 0x40, 0x30,
    0x0F, 0x11, 0x44, 0x24, 0x28, 0x0F, 0x10, 0x40, 0x40, 0x0F, 0x11, 0x44, 0x24, 0x38, 0x0F, 0x10,
    0x40, 0x50, 0x0F, 0x11, 0x44, 0x24, 0x48, 0x0F, 0x10, 0x40, 0x60, 0x0F, 0x11, 0x44, 0x24, 0x58,
    0x48, 0x87, 0x40, 0x00, 0x44, 0x48, 0xF7, 0xD1, 0xFF, 0xE1, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0x48, 0x8D, 0xA4, 0x24, 0x00, 0xF0, 0xFF, 0xFF, 0x48, 0x8D, 0xA4, 0x24, 0x00, 0xF0, 0xFF, 0xFF,
    0x48, 0x8D, 0xA4, 0x24, 0x20, 0x21, 0x00, 0x00, 0x48, 0x87, 0x04, 0x24, 0x48, 0x94, 
    0x48, 0x8B, 0x68, 0x08, 
    0x48, 0x8B, 0x40, 0x00, 
    0x48, 0x83, 0xC4, 0x10, 
    0xC3, 
    //
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //
    0x4C, 0x48, 0x8B, 0x05, 0x38, 0xF0, 0xFF, 0xFF, 
    0x8B, 0x0D, 0x3A, 0xF0, 0xFF, 0xFF, 
    0x89, 0x08,
    0xC3, 
    //
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};

#define sc_entryVA  (0x1B0)
#define hooked_func_VA (0x200)
#define mem_protect_RXW_VA (0x310)
#define mem_protect_RX_VA (0x320)

const DECLSPEC_ALIGN(32) BYTE _GIUIshell_Const[] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t MemProtectRXW
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t MemProtectRX
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	     //uint64_t PHooked_func
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t Pplat_flag
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	0x53, 0x55, 0x56, 0x57, 							    //push rbx,rbp,rsi,rdi
	0x48, 0x83, 0xEC, 0x48, 							    //sub rsp, 0x48
	0x48, 0x48, 0x8B, 0x1D, 0xD0, 0xFF, 0xFF, 0xFF,	        //mov rbx, qword ptr ds:[hksr_ui_ptr]
	0x48, 0x8D, 0xAC, 0x24, 0x28, 0x00, 0x00, 0x00,         //lea rbp, [rsp + 0x28]
	0x48, 0x89, 0x4D, 0x08,     			                //mov [rbp + 8], rcx
	0x48, 0x89, 0x55, 0x10,                                 //mov [rbp + 0x10], rdx
	0x4C, 0x89, 0x45, 0x18, 							    //mov [rbp + 0x18], r8
	0x4C, 0x89, 0x4D, 0x20, 							    //mov [rbp + 0x20], r9
	0x48, 0x89, 0xD9, 								        //mov rcx, rbx
	0x44, 0xFF, 0x15, 0x9E, 0xFF, 0xFF, 0xFF, 		        //call [MEM_RXW]
	0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00, 				    //nop
	0xF3, 0x0F, 0x6F, 0x05, 0x50, 0x00, 0x00, 0x00,	        //movdqu xmm0, [Hooked_pattern]
	0xF3, 0x0F, 0x7F, 0x03, 							    //movdqu [rbx], xmm0
	0x48, 0x8B, 0x4D, 0x08,     			                //mov rcx, [rbp + 8]
	0x48, 0x8B, 0x55, 0x10, 							    //mov rdx, [rbp + 0x10]
	0xFF, 0xD3, 									        //call rbx
	0xEB, 0x00,										        //nop
	0x4C, 0x48, 0x8B, 0x3D, 0x90, 0xFF, 0xFF, 0xFF, 	    //mov rdi, qword ptr ds:[platflag]
    0x48, 0x89, 0xF9, 
    0x4C, 0xFF, 0x15, 0x6E, 0xFF, 0xFF, 0xFF, 
    0xC7, 0x07, 0x02, 0x00, 0x00, 0x00, 
    0x48, 0x89, 0xF9, 
    0x4C, 0xFF, 0x15, 0x66, 0xFF, 0xFF, 0xFF, 
    0x48, 0x89, 0xD9, 
    0x4C, 0xFF, 0x15, 0x5C, 0xFF, 0xFF, 0xFF, 
    0x48, 0x83, 0xC4, 0x48,
    0x5F, 0x5E, 0x5D, 0x5B, 
    0xC3, 
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};


typedef struct hooked_func_struct
{
	uint64_t func_addr;
	uint64_t Reserved;
    __m128i hookedpart;
	__m128i orgpart;
} hooked_func_struct, *Phooked_func_struct;

// 特征搜索
static uintptr_t PatternScan_Region(uintptr_t startAddress, size_t regionSize, const char* signature)
{
    auto pattern_to_byte = [](const char* pattern)
        {
            std::vector<int> bytes;
            const char* start = pattern;
            const char* end = pattern + strlen(pattern);

            for (const char* current = start; current < end; ++current) 
            {
                if (*current == '?') 
                {
                    ++current;
                    if (*current == '?')
                        ++current;
                    bytes.push_back(-1);
                }
                else 
                {
                    bytes.push_back(strtoul(current, const_cast<char**>(&current), 16));
                }
            }
            return bytes;
        };

    std::vector<int> patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(startAddress);

    for (size_t i = 0; i < regionSize - patternBytes.size(); i++)
    {
        bool found = true;
        for (size_t j = 0; j < patternBytes.size(); ++j) 
        {
            if (scanBytes[i + j] != patternBytes[j] && patternBytes[j] != -1) 
            {
                found = false;
                break;
            }
        }
        if (found) 
            return (uintptr_t)&scanBytes[i];
    }
    return 0;
}


static std::wstring GetLastErrorAsString(DWORD code)
{
    LPWSTR buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buf, 0, NULL);
    std::wstring ret = buf;
    LocalFree(buf);
    return ret;
}


static wstring To_Hexwstring_64bit(uint64_t value)
{
    uint16_t* hstr = (uint16_t*)malloc(0x30);
	if (!hstr)
	{
		ExitProcess(-1);
	}
	for (int i = 15; i >= 0; --i)
	{
        uint16_t byte = value & 0xF;
        if (byte >= 0 && byte <= 9)
        {
            hstr[i] = byte + 0x30;
        }
        else
        {
            hstr[i] = byte + 0x37;
        }
		value >>= 4;
	}
    hstr[16] = 0;
    wstring hexstr = (LPWSTR)hstr;
	free(hstr);
	return hexstr;
}

static wstring To_Hexwstring_32bit(uint32_t value)
{
    uint16_t* hstr = (uint16_t*)malloc(0x20);
    if (!hstr)
    {
		ExitProcess(-1);
    }
    for (int i = 7; i >= 0; --i)
    {
        uint16_t byte = value & 0xF;
        if (byte >= 0 && byte <= 9)
        {
            hstr[i] = byte + 0x30;
        }
        else
        {
            hstr[i] = byte + 0x37;
        }
        value >>= 4;
    }
    hstr[8] = 0; // Ensure null-termination
    wstring hexstr = (LPWSTR)hstr;
    free(hstr);
	return hexstr;
}

//Throw error msgbox
static void Show_Error_Msg(LPCWSTR Prompt_str)
{
    if (ErrorMsg_EN == 0)
        return;
    uint32_t Error_code = *(uint32_t*)((BYTE*)(__readgsqword(0x30)) + 0x68);
    uint32_t LastStatus = *(uint32_t*)((BYTE*)(__readgsqword(0x30)) + 0x1250);
    wstring message{};
    wstring title{};
    {
        if (Prompt_str)
            message = Prompt_str;
        else
            message = L"Default Error Message";
        message += L"\n" + GetLastErrorAsString(Error_code);
        message += L"\nErrorCode: 0x" + To_Hexwstring_32bit(Error_code);
        message += L"\nLastStatus: 0x" + To_Hexwstring_32bit(LastStatus);
    }
    UNICODE_STRING message_str;
    UNICODE_STRING title_str;
    {
        wchar_t* cwstr = (wchar_t*)malloc(0x2000);
		if (!cwstr)
		{
			ExitProcess(-1);
		}
        PEB64* peb = (PEB64*)__readgsqword(0x60);
        HMODULE self = (HMODULE)peb->ImageBaseAddress;
        GetModuleFileNameW(self, cwstr, 0x1000);
        title = cwstr;
        title = title.substr(title.find_last_of(L"\\") + 1);
		free(cwstr); // Free the allocated memory
    }
    InitUnicodeString(&message_str, (PCWSTR)message.c_str());
    InitUnicodeString(&title_str, (PCWSTR)title.c_str());
    ULONG_PTR params[4] = { (ULONG_PTR)&message_str, (ULONG_PTR)&title_str, ((ULONG)ResponseButtonOK | IconError), INFINITE };
    DWORD response;
    NtRaiseHardError(STATUS_SERVICE_NOTIFICATION | HARDERROR_OVERRIDE_ERRORMODE, 4, 3, params, 0, &response);
}

//create pwstr 1 len = 2 byte
static wstring* NewWstring(size_t strlen)
{
    uintptr_t* wcsptr = (uintptr_t*)malloc(sizeof(wstring));
    if (!wcsptr)
    {
        goto __malloc_fail;
    }
    memset(wcsptr, 0, sizeof(wstring));
    if (strlen <= 7)
    {
        *(size_t*)((uintptr_t)wcsptr + 0x10 + sizeof(uintptr_t)) = strlen;
        return (wstring*)wcsptr;
    }
    else
    {
        wchar_t* wcstr = (wchar_t*)malloc(strlen * 2);
        if (!wcstr)
        {
            goto __malloc_fail;
        }
        *(uint64_t*)wcstr = 0;
        *(uintptr_t*)wcsptr = (uintptr_t)wcstr;
        *(size_t*)((uintptr_t)wcsptr + 0x10 + sizeof(uintptr_t)) = strlen;
        return (wstring*)wcsptr;
    }

__malloc_fail:
    Show_Error_Msg(L"malloc failed!");
    ExitProcess(-1);
    return 0;
}

//destroy
static INLINE void DelWstring(wstring** pwstr)
{
    if(*(uintptr_t*)((uintptr_t)*(uintptr_t*)pwstr + 0x10 + sizeof(uintptr_t)) > 7)
        free(**(wchar_t***)pwstr);  
    free(*pwstr);
    *pwstr = 0;
    return;
}

//[in],[in],[out],[out],[in]
static bool Get_Section_info(uintptr_t PE_buffer, LPCSTR Name_sec, uint32_t* Sec_Vsize, uintptr_t* Sec_Remote_RVA, uintptr_t Remote_BaseAddr)
{
    if ((!PE_buffer) || (!Name_sec) || (!Sec_Vsize) || (!Sec_Remote_RVA))
        return 0;
    uint64_t tar_sec = *(uint64_t*)Name_sec;//max 8 byte
    int32_t* WinPEfileVA = (int32_t*)((uint64_t)PE_buffer + 0x3C); //dos_header
    uintptr_t PEfptr = (uintptr_t)((uint64_t)PE_buffer + *WinPEfileVA); //get_winPE_VA
    _IMAGE_NT_HEADERS64* _FilePE_Nt_header = (_IMAGE_NT_HEADERS64*)PEfptr;
    if (_FilePE_Nt_header->Signature == 0x00004550)
    {
        DWORD sec_num = _FilePE_Nt_header->FileHeader.NumberOfSections;//获得指定节段参数
        sec_num++;
        DWORD num = sec_num;
        DWORD target_sec_VA_start = 0;
        do
        {
            PIMAGE_SECTION_HEADER _sec_temp = (PIMAGE_SECTION_HEADER)(PEfptr + 264 + (40 * (static_cast<unsigned long long>(sec_num) - num)));

            if (*(uint64_t*)(_sec_temp->Name) == tar_sec)
            {
                target_sec_VA_start = _sec_temp->VirtualAddress;
                *Sec_Vsize = _sec_temp->Misc.VirtualSize;
                *Sec_Remote_RVA = Remote_BaseAddr + target_sec_VA_start;
                return 1;
            }
            num--;

        } while (num);

        return 0;
    }
    return 0;
}

//通过进程名搜索进程ID
static DWORD GetPID(const wchar_t* ProcessName)
{
    return GetProcPID(ProcessName);

    //DWORD pid = 0;
    //PROCESSENTRY32W* pe32 = (PROCESSENTRY32W*)malloc(sizeof(PROCESSENTRY32W));
    //if (!pe32)
    //    return 0;
    //wstring name = ProcessName;
    //towlower0((wchar_t*)name.c_str());
    //pe32->dwSize = sizeof(PROCESSENTRY32W);
    //HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    //for (Process32FirstW(snap, pe32); Process32NextW(snap, pe32);)
    //{
    //    towlower0(pe32->szExeFile);
    //    if (wcstrcmp0(pe32->szExeFile, name.c_str()))
    //    {
    //        pid = pe32->th32ProcessID;
    //        break;
    //    }
    //}
    //CloseHandle(snap);
    //return pid;

}


static bool WriteConfig(int fps)
{
    HANDLE hFile = CreateFileW(CONFIG_FILENAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        Show_Error_Msg(L"CreateFile failed! (config)");
        return false;
    }
    wstring content{0};
    LPVOID buffer = VirtualAlloc_Internal(0, 0x10000, PAGE_READWRITE);
    if (!buffer)
        return false;
    *(DWORD64*)&content = ((DWORD64)buffer);
    *(DWORD64*)((DWORD64)&content + 0x18) = 0x8000;
    *(DWORD*)buffer = 0x20FEFF;
    {
        content += L"[Setting]\nGenshinPath=" + GenGamePath + L"\n";
    }
    {
        content += L"HKSRPath=" + HKSRGamePath + L"\n";
    }
    {
        content += L"IsAntiMisscontact=" + std::to_wstring(isAntimiss) + L"\n";
    }
    {
        content += L"TargetDevice=" + std::to_wstring(Tar_Device) + L"\n";
    }
    {
        content += L"IsHookGameSet=" + std::to_wstring(isHook) + L"\n";
    }
    {
        content += L"GSTarget60=" + std::to_wstring(Target_set_60) + L"\n";
    }
    {
        content += L"GSTarget30=" + std::to_wstring(Target_set_30) + L"\n";
    }
    {
        content += L"EnableErrorMsg=" + std::to_wstring(ErrorMsg_EN) + L"\n";
    }
    {
        content += L"AutoExit=" + std::to_wstring(AutoExit) + L"\n";
    }
    {
        content += L"GameProcessPriority=" + std::to_wstring(ConfigPriorityClass) + L"\n";
    }
    {
        content += L"FPS=" + std::to_wstring(fps) + L"\n";
    }

    DWORD written = 0;
    bool re = WriteFile(hFile, buffer, content.size() * 2, &written, 0);
    VirtualFree_Internal(buffer, 0, MEM_RELEASE);
    CloseHandle_Internal(hFile);
	memset(&content, 0, sizeof(wstring));
    return re;
}


static bool LoadConfig()
{
    INIReader reader(CONFIG_FILENAME);
    if (reader.ParseError() != 0)
    {
        wprintf_s(L"\n Config Not Found !\n 配置文件未发现\n try read reg info\n 尝试读取启动器注册表配置...\n ......");

    _no_config:
        DWORD length = 0x10000;
        wchar_t* szPath = (wchar_t*)VirtualAlloc_Internal(0, length, PAGE_READWRITE);
        if (!szPath)
        {
            Show_Error_Msg(L"Alloc Memory failed! (Get game path)");
            return 0;
        }
        //尝试从注册表获取游戏路径
        DWORD ver_region = 0;
        HKEY htempKey = 0;
        //Software\\Cognosphere\HYP\\1_0\\hk4e_global
        //Software\\Cognosphere\HYP\\1_0\\hkrpg_global
        //Software\\miHoYo\HYP\1_2\\hk4e_cn
        //Software\\miHoYo\HYP\1_2\\hkrpg_cn
		const wchar_t* CNserver = L"Software\\miHoYo\\HYP\\1_2";
		const wchar_t* Globalserver = L"Software\\Cognosphere\\HYP\\1_0";
        if (!RegOpenKeyW(HKEY_CURRENT_USER, CNserver, &htempKey))
        {
            ver_region |= 0x1;
			RegCloseKey(htempKey);
        }
        if (!RegOpenKeyW(HKEY_CURRENT_USER, Globalserver, &htempKey))
        {
            ver_region |= 0x2;
            RegCloseKey(htempKey);
        }
        if(ver_region)
        {
            HKEY hExtKey = 0;
			DWORD ret = 0;
            _ver_result:
            switch (ver_region)
            {
			    case 0x1: //cn
                {
                    {
                        wstring hk4eKey = CNserver;
                        hk4eKey += L"\\hk4e_cn";
                        ret = RegOpenKeyW(HKEY_CURRENT_USER, hk4eKey.c_str(), &hExtKey);
                        if (ret != ERROR_SUCCESS)
                        {
                            goto _reg_getpath_fail;
                        }
                    }
                    ret = RegGetValueW(hExtKey, NULL, L"GameInstallPath", RRF_RT_REG_SZ, NULL, szPath, &length);
                    RegCloseKey(hExtKey);
                    if (ret != ERROR_SUCCESS)
                    {
                        goto _reg_getpath_fail;
                    }
                    else
                    {
                        wchar_t* pstrend = szPath;
                        while (*pstrend != 0) pstrend++;
                        pstrend[0] = L'\\';
                        pstrend[1] = L'Y';
                        pstrend[2] = L'u';
                        pstrend[3] = L'a';
                        pstrend[4] = L'n';
                        pstrend[5] = L'S';
                        pstrend[6] = L'h';
                        pstrend[7] = L'e';
                        pstrend[8] = L'n';
                        pstrend[9] = L'.';
                        pstrend[10] = L'e';
                        pstrend[11] = L'x';
                        pstrend[12] = L'e';
                        pstrend[13] = 0;
                        if (GetFileAttributesW(szPath) != INVALID_FILE_ATTRIBUTES)
                        {
                            GenGamePath = szPath;
                        }
                    }
					{
						wstring hkrpgKey = CNserver;
						hkrpgKey += L"\\hkrpg_cn";
						ret = RegOpenKeyW(HKEY_CURRENT_USER, hkrpgKey.c_str(), &hExtKey);
						if (ret != ERROR_SUCCESS)
						{
							goto _reg_getpath_fail;
						}
					}
                    ret = RegGetValueW(hExtKey, NULL, L"GameInstallPath", RRF_RT_REG_SZ, NULL, szPath, &length);
					RegCloseKey(hExtKey);
                    if (ret != ERROR_SUCCESS)
                    {
                        goto _reg_getpath_fail;
                    }
                    else
                    {
                        wchar_t* pstrend = szPath;
                        while (*pstrend != 0) pstrend++;
                        pstrend[0] = L'\\';
                        pstrend[1] = L'S';
                        pstrend[2] = L't';
                        pstrend[3] = L'a';
                        pstrend[4] = L'r';
                        pstrend[5] = L'R';
                        pstrend[6] = L'a';
                        pstrend[7] = L'i';
                        pstrend[8] = L'l';
                        pstrend[9] = L'.';
                        pstrend[10] = L'e';
                        pstrend[11] = L'x';
                        pstrend[12] = L'e';
                        pstrend[13] = 0;
                        if (GetFileAttributesW(szPath) != INVALID_FILE_ATTRIBUTES)
						{
							HKSRGamePath = szPath;
						}
                    }
					break;
                }
			    case 0x2: //global
                {
                    {
                        wstring hk4eKey = Globalserver;
                        hk4eKey += L"\\hk4e_global";
                        ret = RegOpenKeyW(HKEY_CURRENT_USER, hk4eKey.c_str(), &hExtKey);
                        if (ret != ERROR_SUCCESS)
                        {
                            goto _reg_getpath_fail;
                        }
                    }
					ret = RegGetValueW(hExtKey, NULL, L"\\hk4e_global\\GameInstallPath", RRF_RT_REG_SZ, NULL, szPath, &length);
					RegCloseKey(hExtKey);
					if (ret != ERROR_SUCCESS)
					{
						goto _reg_getpath_fail;
					}
                    else
                    {
                        wchar_t* pstrend = szPath;
                        while (*pstrend != 0) pstrend++;
						pstrend[0] = L'\\';
                        pstrend[1] = L'G';
                        pstrend[2] = L'e';
                        pstrend[3] = L'n';
                        pstrend[4] = L's';
                        pstrend[5] = L'h';
                        pstrend[6] = L'i';
                        pstrend[7] = L'n';
                        pstrend[8] = L'I';
                        pstrend[9] = L'm';
                        pstrend[10] = L'p';
                        pstrend[11] = L'a';
                        pstrend[12] = L'c';
                        pstrend[13] = L't';
                        pstrend[14] = L'.';
                        pstrend[15] = L'e';
                        pstrend[16] = L'x';
                        pstrend[17] = L'e';
                        pstrend[18] = 0;
                        if (GetFileAttributesW(szPath) != INVALID_FILE_ATTRIBUTES)
						{
							GenGamePath = szPath;
						}
                    }
                    {
                        wstring hkrpgKey = Globalserver;
                        hkrpgKey += L"\\hkrpg_global";
                        ret = RegOpenKeyW(HKEY_CURRENT_USER, hkrpgKey.c_str(), &hExtKey);
                        if (ret != ERROR_SUCCESS)
                        {
                            goto _reg_getpath_fail;
                        }
                    }
                    ret = RegGetValueW(hExtKey, NULL, L"GameInstallPath", RRF_RT_REG_SZ, NULL, szPath, &length);
                    RegCloseKey(hExtKey);
                    if (ret != ERROR_SUCCESS)
                    {
                        goto _reg_getpath_fail;
                    }
                    else
                    {
                        wchar_t* pstrend = szPath;
                        while (*pstrend != 0) pstrend++;
                        pstrend[0] = L'\\';
                        pstrend[1] = L'S';
                        pstrend[2] = L't';
                        pstrend[3] = L'a';
                        pstrend[4] = L'r';
                        pstrend[5] = L'R';
                        pstrend[6] = L'a';
                        pstrend[7] = L'i';
                        pstrend[8] = L'l';
                        pstrend[9] = L'.';
                        pstrend[10] = L'e';
                        pstrend[11] = L'x';
                        pstrend[12] = L'e';
                        pstrend[13] = 0;
                        if (GetFileAttributesW(szPath) != INVALID_FILE_ATTRIBUTES)
                        {
                            HKSRGamePath = szPath;
                        }
                    }
                    break;
                }
                case 0x3:
                {
					ret = MessageBoxW_Internal(L"Both CN and Global version registry keys found! Please select the version you want to launch. \
                        \n注册表内有两个版本的启动器，请选择游戏服务器版本\nClick Yes to CN Ver, No to Global Ver\n点“是”使用国服，点“否“使用国际服", L"Version Selection", MB_ICONQUESTION | MB_YESNO);
                    if (ret == 8)
                    {
						ver_region = 0x1; //CN
						goto _ver_result;
					}
					ver_region = 0x2; //Global
					goto _ver_result;
                }
                default:
                    goto _reg_getpath_fail;
            }
            if (isGenshin)
            {
                GamePath = GenGamePath;
            }
            else
            {
                GamePath = HKSRGamePath;
            }
			goto _getpath_done;
        }

		//没有成功获取到,开始进程搜索//不区分版本
    _reg_getpath_fail:
		wprintf_s(L"\n Search Game Path failed! Don't close this window and Try manually boot game \n 获取启动器注册表配置失败，请手动启动游戏获取路径\n");
        if(1)
        {
            DWORD pid = 0;
            while (1)
            {
                if (isGenshin)
                {
                    if ((pid = GetPID(L"YuanShen.exe")) || (pid = GetPID(L"GenshinImpact.exe")))
                        break;
                }
                else
                {
                    if (pid = GetPID(L"StarRail.exe"))
                        break;
                }
                NtSleep(200);
            }
            HANDLE hProcess = OpenProcess_Internal(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, pid);
            if (!hProcess)
            {
                Show_Error_Msg(L"OpenProcess failed! (Get game path)");
                return 0;
            }

            // 获取进程句柄 - 这权限很低的了 - 不应该获取不了
            // PROCESS_QUERY_LIMITED_INFORMATION - 用于查询进程路经 (K32GetModuleFileNameExA)
            // SYNCHRONIZE - 用于等待进程结束 (WaitForSingleObject)

            if (!QueryFullProcessImageNameW(hProcess, 0, szPath, &length))
            {
                Show_Error_Msg(L"Get game path failed!");
                VirtualFree_Internal(szPath, 0, MEM_RELEASE);
                return 0;
            }
            DWORD ExitCode = STILL_ACTIVE;
            while (ExitCode == STILL_ACTIVE)
            {
                // wait for the game to close then continue
                TerminateProcess_Internal(hProcess, 0);
                WaitForSingleObject(hProcess, 2000);
                GetExitCodeProcess(hProcess, &ExitCode);
            }
            CloseHandle_Internal(hProcess);
        }
        if (isGenshin)
        {
            GenGamePath = szPath;
        }
        else
        {
            HKSRGamePath = szPath;
        }
        GamePath = szPath;

    _getpath_done:
        
        VirtualFree_Internal(szPath, 0, MEM_RELEASE);


        //clean screen
        {
            COORD pos = { 0, 8 };
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleCursorPosition(hOut, pos);
        }
        for (int a = 0; a <= 6; a++)
        {
            for (int i = 0; i <= 16; i++)
            {
                printf_s("               ");
            }
            printf_s("\n");
        }
        {
            COORD pos = { 0, 8 };
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleCursorPosition(hOut, pos);
        }
        goto __path_ok;
    }

    HKSRGamePath = reader.Get(L"Setting", L"HKSRPath", HKSRGamePath);
    GenGamePath = reader.Get(L"Setting", L"GenshinPath", GenGamePath);
    if (isGenshin)
    {
        GamePath = GenGamePath;
        if (GetFileAttributesW(GamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            wprintf_s(L"\n Genshin Path Error!\n Plase open Genshin to set game path.\n 路径错误，请手动打开原神来设置游戏路径 \n");
            goto _no_config;
        }
    }
    else
    {
        GamePath = HKSRGamePath;
        if (GetFileAttributesW(GamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            wprintf_s(L"\n HKSR Path Error!\n Plase open StarRail to set game path.\n 路径错误，请手动打开崩铁来设置游戏路径 \n");
            goto _no_config;
        }   
    }

__path_ok:
    isAntimiss = reader.GetBoolean(L"Setting", L"IsAntiMisscontact", 1);
    Target_set_30 = reader.GetInteger(L"Setting", L"GSTarget30", 60);
    Target_set_60 = reader.GetInteger(L"Setting", L"GSTarget60", 1000);
    ErrorMsg_EN = reader.GetBoolean(L"Setting", L"EnableErrorMsg", 1);
    AutoExit = reader.GetBoolean(L"Setting", L"AutoExit", 0);
    isHook = reader.GetBoolean(L"Setting", L"IsHookGameSet", 0);
    Tar_Device = reader.GetInteger(L"Setting", L"TargetDevice", DEFAULT_DEVICE);
    ConfigPriorityClass = reader.GetInteger(L"Setting", L"GameProcessPriority", 3);
    switch (ConfigPriorityClass)
    {
        case 0 :
            GamePriorityClass = REALTIME_PRIORITY_CLASS;
            break;
        case 1 :
            GamePriorityClass = HIGH_PRIORITY_CLASS;
            break;
        case 2:
            GamePriorityClass = ABOVE_NORMAL_PRIORITY_CLASS;
            break;
        case 3:
            GamePriorityClass = NORMAL_PRIORITY_CLASS; 
            break;
        case 4:
            GamePriorityClass = BELOW_NORMAL_PRIORITY_CLASS;
            break;
        default:
            ConfigPriorityClass = 3;
            GamePriorityClass = NORMAL_PRIORITY_CLASS;
            break;
    }
    FpsValue = reader.GetInteger(L"Setting", L"FPS", FPS_TARGET);
    WriteConfig(FpsValue);
    
    return 1;
}


struct Boot_arg
{
    LPWSTR Game_Arg;
    LPWSTR Path_Lib;
};
//[out] CommandLinew
//The first 16 bytes are used by other arg
static bool Init_Game_boot_arg(Boot_arg* arg)
{
    if (!arg)
    {
        return 0;
    }
    int argNum = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argNum);
    //win32arg maxsize 8191
    std::wstring CommandLine{};
    if (argNum >= 2)
    {
        int _game_argc_start = 2;
        wchar_t boot_genshin[] = L"-genshin";
        wchar_t boot_starrail[] = L"-hksr";
        wchar_t loadLib[] = L"-loadlib";
        wchar_t Use_Mobile_UI[] = L"-enablemobileui";
        wstring* temparg = NewWstring(0x1000);
        *temparg = argvW[1];
        towlower0((wchar_t*)temparg->c_str());
        if (*temparg == boot_genshin)
        {
            SetConsoleTitleA("This console control GenshinFPS");

            if (argNum > 2)
            {
                *temparg = argvW[2];
                towlower0((wchar_t*)temparg->c_str());
                if (*temparg == Use_Mobile_UI)
                {
                    Use_mobile_UI = 1;
                    //CommandLine += L"use_mobile_platform -is_cloud 1 -platform_type CLOUD_THIRD_PARTY_MOBILE ";
                    _game_argc_start = 3;
                }
            }
        }
        else if (*temparg == boot_starrail)
        {
            isGenshin = 0;
            SetConsoleTitleA("This console control HKStarRailFPS");
            if (argNum > 2)
            {
                *temparg = argvW[2];
                towlower0((wchar_t*)temparg->c_str());
                if (*temparg == Use_Mobile_UI)
                {
                    Use_mobile_UI = 1;
                    _game_argc_start = 3;
                }
            }
        }
        else
        {
            Show_Error_Msg(L"参数错误 \nArguments error ( unlocker.exe -[game] -[game argv] ..... ) \n");
            return 0;
        }
        if (argNum > _game_argc_start)
        {
            *temparg = argvW[_game_argc_start];
            towlower0((wchar_t*)temparg->c_str());
            if (*temparg == loadLib)
            {
                _game_argc_start++;
                if (argNum > _game_argc_start)
                {
                    *temparg = argvW[_game_argc_start];
                    LPVOID LibPath = malloc((temparg->size() * 2) + 0x10);
                    strncpy0((wchar_t*)LibPath, temparg->c_str(), temparg->size() * 2);
                    arg->Path_Lib = (LPWSTR)LibPath;
                    _game_argc_start++;
                }
            }
        }
        for (int i = _game_argc_start; i < argNum; i++)
        {
            CommandLine += argvW[i];
            CommandLine += L" ";
        }
        DelWstring(&temparg);
    }
    else
    {
        DWORD gtype = MessageBoxW_Internal(L"Genshin click yes ,StarRail click no ,Cancel to Quit \n启动原神选是，崩铁选否，取消退出 \n", L"GameSelect ", 0x23);
        if (gtype == 3)
        {
            return 0;
        }
        if (gtype == 8)
        {
            SetConsoleTitleA("This console control GenshinFPS");
        }
        if (gtype == 5)
        {
            isGenshin = 0;
            SetConsoleTitleA("This console control HKStarRailFPS");
        }
        //?
    }
    arg->Game_Arg = (LPWSTR)malloc(0x2000);
    if (!arg->Game_Arg)
        return 0;
    *(uint64_t*)arg->Game_Arg = 0;
    strncpy0((wchar_t*)((BYTE*)arg->Game_Arg), CommandLine.c_str(), CommandLine.size() * 2);
    return 1;
}

typedef struct Hook_func_list
{
    uint64_t Pfunc_device_type;//plat_flag
    uint64_t Unhook_func;//hook_bootui
    uint64_t setbug_fix; //func_patch
    uint64_t nop;  
}Hook_func_list, *PHook_func_list;

typedef struct inject_arg
{
    uint64_t Pfps;//GI-fps-set
    uint64_t Bootui;//HKSR ui /GIui type
    uint64_t verfiy;//code verfiy
    PHook_func_list PfuncList;//Phook_funcPtr_list
}inject_arg, *Pinject_arg;

// Hotpatch
static uint64_t inject_patch(HANDLE Tar_handle, uintptr_t _ptr_fps, inject_arg* arg)
{
    if (!_ptr_fps)
        return 0;

    BYTE* _sc_buffer = (BYTE*)VirtualAlloc_Internal(0, sizeof(_shellcode_Const), PAGE_READWRITE);
    if (!_sc_buffer)
    {
        Show_Error_Msg(L"initcode failed!");
        return 0;
    }
    memmove(_sc_buffer, _shellcode_Const, sizeof(_shellcode_Const));
    *(uint32_t*)_sc_buffer = *(uint32_t*)((BYTE*)(__readgsqword(0x30)) + 0x40);      //unlocker PID
    *(uint64_t*)(_sc_buffer + 0x60) = (uint64_t)(&MessageBoxA);
    *(uint64_t*)(_sc_buffer + 0x68) = (uint64_t)(&CloseHandle);

    //Disable errmsg
    if (AutoExit)
    {
        *(uint16_t*)(_sc_buffer + 0x16A) = 0x3AEB;
    }

    //genshin_get_gameset
    if (isGenshin && isHook)
    {
        *(uint64_t*)(_sc_buffer + 0x10) = arg->Pfps;
    }

    //shellcode patch
    *(uint64_t*)(_sc_buffer + 0x8) = (uint64_t)(&FpsValue); //source ptr
    *(uint64_t*)(_sc_buffer + 0x18) = _ptr_fps;

    LPVOID __Tar_proc_buffer = VirtualAllocEx_Internal(Tar_handle, NULL, sizeof(_shellcode_Const), PAGE_READWRITE);
    if (!__Tar_proc_buffer)
    {
        Show_Error_Msg(L"AllocEx Fail! ");
        return 0;
    }
    if (arg->Bootui && (!isGenshin))
    {
        *(uint64_t*)(_sc_buffer + 0x20) = arg->Bootui;//HKSR mob
        *(uint32_t*)(_sc_buffer + 0x28) = 2;
        *(uint64_t*)(_sc_buffer + 0x30) = (uint64_t)__Tar_proc_buffer + 0xFE0;
    }
    if (arg->PfuncList)
    {
        PHook_func_list GI_Func = (PHook_func_list)arg->PfuncList;
        if(GI_Func->Pfunc_device_type)
        {
            LPVOID __payload_ui = VirtualAllocEx_Internal(Tar_handle, NULL, sizeof(_GIUIshell_Const), PAGE_READWRITE);
            if (!__payload_ui)
            {
                Show_Error_Msg(L"Alloc mem Fail! (GIui) 0");
                goto __exit_block;
            }
            BYTE* ui_payload_temp = (BYTE*)VirtualAlloc_Internal(0, sizeof(_GIUIshell_Const), PAGE_READWRITE);
            if (!ui_payload_temp)
            {
                Show_Error_Msg(L"Alloc mem failed! (GIui)");
                goto __exit_block;
            }
            memmove(ui_payload_temp, &_GIUIshell_Const, sizeof(_GIUIshell_Const));
            *(uint64_t*)(ui_payload_temp) = ((uint64_t)__Tar_proc_buffer + mem_protect_RXW_VA);
            *(uint64_t*)(ui_payload_temp + 0x8) = ((uint64_t)__Tar_proc_buffer + mem_protect_RX_VA);
            *(uint64_t*)(ui_payload_temp + 0x10) = GI_Func->Unhook_func;
            *(uint64_t*)(ui_payload_temp + 0x18) = GI_Func->Pfunc_device_type + 1;//plat_flag func_va

            if (!ReadProcessMemoryInternal(Tar_handle, (void*)GI_Func->Unhook_func, ui_payload_temp + sizeof(_GIUIshell_Const), 0x10, 0))
            {
                Show_Error_Msg(L"Failed ReadFunc 0 (GIui)");
                goto __exit_block;
            }
            uint64_t hookpart[2] = { 0x225FF,  ((uint64_t)__payload_ui + 0x30) };
            if (!WriteProcessMemoryInternal(Tar_handle, (void*)GI_Func->Unhook_func, &hookpart, 0x10, 0))
            {
                Show_Error_Msg(L"Failed write payload 0(GIui)");
                goto __exit_block;
            }

            if (!WriteProcessMemoryInternal(Tar_handle, (void*)(GI_Func->Pfunc_device_type + 1), &arg->Bootui, 4, 0))
            {
                Show_Error_Msg(L"Failed write payload 0(GIui)");
                goto __exit_block;
            }
            
            Phooked_func_struct Psettingbug = (Phooked_func_struct)(ui_payload_temp + 0x500);
            Psettingbug->func_addr = GI_Func->setbug_fix;
            //settingbugfix
            if (!ReadProcessMemoryInternal(Tar_handle, (void*)GI_Func->setbug_fix, (void*)&Psettingbug->orgpart, 0x10, 0))
            {
                Show_Error_Msg(L"Failed ReadFunc 1 (GIui)");
                goto __exit_block;
            }
			Psettingbug->hookedpart = Psettingbug->orgpart;
			*(BYTE*)((uint64_t)(&Psettingbug->hookedpart) + 2) = 0xEB;

            //inject to game
            if (!WriteProcessMemoryInternal(Tar_handle, __payload_ui, ui_payload_temp, 0x1000, 0))
            {
                Show_Error_Msg(L"Failed write payload 1(GIui)");
                goto __exit_block;
            }
			VirtualFree_Internal(ui_payload_temp, 0, MEM_RELEASE);
            if (!VirtualProtectEx_Internal(Tar_handle, __payload_ui, 0x1000, PAGE_EXECUTE_READ, 0))
            {
                Show_Error_Msg(L"Failed change RX (GIui)");
                goto __exit_block;
            }
            *(uint64_t*)(_sc_buffer + 0x20) = ((uint64_t)__payload_ui + 0x600);//Hookinfo_buffer
        }
        if(arg->verfiy)//hookverfiy
        {
            *(uint64_t*)(_sc_buffer + 0x28) = arg->verfiy;//func
            if (!ReadProcessMemoryInternal(Tar_handle, (void*)arg->verfiy, (_sc_buffer + 0x40), 0x10, 0))
            {
                Show_Error_Msg(L"Failed ReadFunc (GIui)");
                goto __exit_block;
            }
            uint64_t* hooked_part = (uint64_t*)(_sc_buffer + 0x50);
            *hooked_part = 0x225FF;
            *(hooked_part + 1) = ((uint64_t)__Tar_proc_buffer + hooked_func_VA);
            if (!WriteProcessMemoryInternal(Tar_handle, (void*)arg->verfiy, hooked_part, 0x10, 0))
            {
                Show_Error_Msg(L"Failed hook (GIui)");
                goto __exit_block;
            }
        }
    }
__exit_block:

    if (!WriteProcessMemoryInternal(Tar_handle, __Tar_proc_buffer, (void*)_sc_buffer, 0x1000, 0))
    {
        Show_Error_Msg(L"Write Scode Fail! ");
        return 0;
    }
    VirtualFree_Internal(_sc_buffer, 0, MEM_RELEASE);
    if (VirtualProtectEx_Internal(Tar_handle, __Tar_proc_buffer, 0x1000, PAGE_EXECUTE_READWRITE, 0))
    {
        HANDLE temp = CreateRemoteThreadEx_Internal(Tar_handle, 0, (LPTHREAD_START_ROUTINE)((uint64_t)__Tar_proc_buffer + sc_entryVA), NULL);
        if (!temp)
        {
            Show_Error_Msg(L"Create SyncThread Fail! ");
            return 0;
        }
        CloseHandle_Internal(temp);
        return ((uint64_t)__Tar_proc_buffer);
    }
	return 0;
}

//when DllPath is null return base img addr
static HMODULE RemoteDll_Inject(HANDLE Tar_handle, LPCWSTR DllPath)
{
    size_t Pathsize = 0x2000;
    size_t strlen = 0;
    if (DllPath)
    {
        while (1)
        {
            if (*(WORD*)(DllPath + strlen))
            {
                strlen++;
            }
            else
            {
                strlen *= 2;
                Pathsize += strlen;
                break;
            }
        }
        if (GetFileAttributesW(DllPath) != INVALID_FILE_ATTRIBUTES)
        {
            goto __inject_proc;
        }
		Show_Error_Msg(L"DllPath Not Found!");
    }

__inject_proc:
    LPVOID buffer = VirtualAllocEx_Internal(Tar_handle, NULL, Pathsize, PAGE_READWRITE);
    if (buffer)
    {
        HMODULE result = 0;
        DWORD64 payload[4] = { 0 };
        if (!DllPath)
        {
            payload[0] = 0x5848606A38EC8348;
            payload[1] = 0x10408B48008B4865;
            payload[2] = 0xFE805894844;
            payload[3] = 0xCCCCCCC338C48348;
        }
        else
        {
            payload[0] = 0xB848C03138EC8348;
            payload[1] = (DWORD64)&LoadLibraryW;
            payload[2] = 0xFE605894890D0FF;
            payload[3] = 0xCCC338C483480000;
        }
        if (WriteProcessMemoryInternal(Tar_handle, buffer, &payload, 0x20, 0))
        {
            if (VirtualProtectEx_Internal(Tar_handle, buffer, 0x1000, PAGE_EXECUTE_READ, 0))
            {
                LPVOID RCX = 0;
                if (DllPath)
                {
                    if (!WriteProcessMemoryInternal(Tar_handle, ((BYTE*)buffer) + 0x1000, (void*)DllPath, strlen, 0))
                    {
                        VirtualFreeEx_Internal(Tar_handle, buffer, 0, MEM_RELEASE);
                        return 0;
                    }
                    RCX = ((BYTE*)buffer) + 0x1000;
                }
                HANDLE hThread = CreateRemoteThreadEx_Internal(Tar_handle, 0, (LPTHREAD_START_ROUTINE)buffer, RCX);
                if (hThread)
                {
                    if (WaitForSingleObject(hThread, 60000))
                    {
                        Show_Error_Msg(L"Dll load Wait Time out!");
                    }
                    else
                    {
                        ReadProcessMemoryInternal(Tar_handle, ((PBYTE)buffer + 0x1000), &result, 0x8, 0);
                    }
                    CloseHandle_Internal(hThread);
                }
            }
        }
        VirtualFreeEx_Internal(Tar_handle, buffer, 0, MEM_RELEASE);
        return result;
    }
    return 0;
}


static HMODULE RemoteDll_Inject_mem(HANDLE Tar_handle, LPCWSTR DllPath)
{
    LPVOID buffer = 0;
    SIZE_T file_size = 0;
	if (DllPath)
	{
		HANDLE file_Handle = CreateFileW(DllPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file_Handle != INVALID_HANDLE_VALUE)
        {
            GetFileSizeEx(file_Handle, (PLARGE_INTEGER) &file_size);
            buffer = VirtualAlloc_Internal(NULL, file_size, PAGE_READWRITE);
			if (!buffer)
			{
				Show_Error_Msg(L"VirtualAlloc Failed! (loadlib mem)");
				CloseHandle_Internal(file_Handle);
				return 0;
			}
            if(ReadFile(file_Handle, buffer, file_size, NULL, NULL))
            {
				CloseHandle_Internal(file_Handle);
                goto __inject_proc;
            }
            else
            {
				Show_Error_Msg(L"ReadFile Failed! (loadlib mem)");
                CloseHandle_Internal(file_Handle);
				VirtualFree_Internal(buffer, 0, MEM_RELEASE);
            }
        }
		Show_Error_Msg(L"Load LibFile Failed!");
	}
    return 0;

__inject_proc:
    HMODULE result = 0;
    LPVOID buffer_load = VirtualAllocEx_Internal(Tar_handle, NULL, 0x2000, PAGE_READWRITE);
	LPVOID shell_mem_load = VirtualAllocEx_Internal(Tar_handle, NULL, sizeof(_PE_MEM_LOADER), PAGE_READWRITE);
    LPVOID file_buffer = VirtualAllocEx_Internal(Tar_handle, NULL, file_size, PAGE_READWRITE);
    if (buffer_load && shell_mem_load && file_buffer)
    {
        DWORD64 payload[6] = { 0 };
        payload[0] = 0xBA48C03128EC8348;
        payload[1] = (DWORD64)&LoadLibraryA;
        payload[2] = 0x484C0000001215FF;
        payload[3] = 0xC03300000FE20589;
        payload[4] = 0xCCCCCCC328C48348;
        payload[5] = (DWORD64)shell_mem_load;
        if (WriteProcessMemoryInternal(Tar_handle, buffer_load, &payload, 0x30, 0) && 
            WriteProcessMemoryInternal(Tar_handle, shell_mem_load, (LPVOID) &_PE_MEM_LOADER, sizeof(_PE_MEM_LOADER), 0) &&
            WriteProcessMemoryInternal(Tar_handle, file_buffer, buffer, file_size, 0))
        {
            VirtualFree_Internal(buffer, 0, MEM_RELEASE);
            if (VirtualProtectEx_Internal(Tar_handle, buffer_load, 0x1000, PAGE_EXECUTE_READ, 0) &&
                VirtualProtectEx_Internal(Tar_handle, shell_mem_load, sizeof(_PE_MEM_LOADER), PAGE_EXECUTE_READWRITE, 0) &&
                VirtualProtectEx_Internal(Tar_handle, file_buffer, file_size, PAGE_READONLY, 0))
            {
                HANDLE hThread = CreateRemoteThreadEx_Internal(Tar_handle, 0, (LPTHREAD_START_ROUTINE)buffer_load, file_buffer);
                if (hThread)
                {
                    if (WaitForSingleObject(hThread, 60000)) 
                    {
                        Show_Error_Msg(L"Lib load Wait Time out!");
                        CloseHandle_Internal(hThread);
						goto __failure_safe_exit;
                    }
                    else
                    {
                        int32_t ecode = GetExitCodeThread_Internal(hThread);
                        if (ecode < 0)
                        {
                            BaseSetLastNTError_inter(ecode);
                            Show_Error_Msg(L"Lib load has an error occurred! Game has crashed");
							CloseHandle_Internal(hThread);
							ExitProcess(0);
                        }
                        else
                        {
                            ReadProcessMemoryInternal(Tar_handle, ((BYTE*)buffer_load) + 0x1000, &result, 0x8, 0);
                        }
                    }
                    CloseHandle_Internal(hThread);
                }
                else
                {
                    Show_Error_Msg(L"CreateThread Failed! (loadlib mem)");
                }
            }
			else
			{
				Show_Error_Msg(L"VirtualProtectEx Failed! (loadlib mem)");
			}
        }
        else
        {
			Show_Error_Msg(L"WriteProcessMemory Failed! (loadlib mem)");
        }
    }
	else
    {
        Show_Error_Msg(L"VirtualAllocEx Failed! (loadlib mem)");
    }
    VirtualFreeEx_Internal(Tar_handle, buffer_load, 0, MEM_RELEASE);
    VirtualFreeEx_Internal(Tar_handle, file_buffer, 0, MEM_RELEASE);
    VirtualFreeEx_Internal(Tar_handle, shell_mem_load, 0, MEM_RELEASE);
__failure_safe_exit:
    VirtualFree_Internal(buffer, 0, MEM_RELEASE);
    return result;
}

//Get the address of the ptr in the target process
static uint64_t Hksr_ENmobile_get_Ptr(HANDLE Tar_handle, LPCWSTR GPath)
{
    uintptr_t GameAssembly_PEbuffer;
    HMODULE il2cpp_base;
    {
        wstring path = GPath;
        path += L"\\GameAssembly.dll";
        il2cpp_base = RemoteDll_Inject(Tar_handle, path.c_str());
        if (!il2cpp_base)
        {
            Show_Error_Msg(L"load GameAssembly.dll Failed !\n");
            return 0;
        }
        GameAssembly_PEbuffer = (uintptr_t)VirtualAlloc_Internal(0, 0x1000, PAGE_READWRITE);
        if (!GameAssembly_PEbuffer)
            return 0;
        if (!ReadProcessMemoryInternal(Tar_handle, il2cpp_base, (void*)GameAssembly_PEbuffer, 0x1000, 0))
            return 0;
        
        int32_t* WinPEfileVA = (int32_t*)((uint64_t)GameAssembly_PEbuffer + 0x3C); //dos_header
        PIMAGE_NT_HEADERS64 PEfptr = (PIMAGE_NT_HEADERS64)((int64_t)GameAssembly_PEbuffer + *WinPEfileVA); //get_winPE_VA
        uint32_t imgsize = PEfptr->OptionalHeader.SizeOfImage;
        LPVOID IMGbuffer = VirtualAlloc_Internal(0, imgsize, PAGE_READWRITE);
        if (!IMGbuffer)
            return 0;
        if (!ReadProcessMemoryInternal(Tar_handle, il2cpp_base, IMGbuffer, imgsize, 0))
            return 0;

        VirtualFree_Internal((void*)GameAssembly_PEbuffer, 0, MEM_RELEASE);
        GameAssembly_PEbuffer = (uintptr_t)IMGbuffer;
    }
    uintptr_t Ua_il2cpp_RVA = 0;
    DWORD32 Ua_il2cpp_Vsize = 0;
    uint64_t retvar = 0;
    if (!Get_Section_info(GameAssembly_PEbuffer, "il2cpp", &Ua_il2cpp_Vsize, &Ua_il2cpp_RVA, GameAssembly_PEbuffer))
    {
        Show_Error_Msg(L"get Section info Error !\n");
        goto __exit;
    }
    if (Ua_il2cpp_RVA && Ua_il2cpp_Vsize)
    {
        //80 B9 ?? ?? ?? ?? 00 74 46 C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3       
        //      75 05 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 28 C3          
        DWORD64 tar_addr;
        DWORD64 address;
        if (address = PatternScan_Region((uintptr_t)Ua_il2cpp_RVA, Ua_il2cpp_Vsize, "80 B9 ?? ?? ?? ?? 00 0F 84 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3"))
        {
            tar_addr = address + 15;
        }
        else if (address = PatternScan_Region((uintptr_t)Ua_il2cpp_RVA, Ua_il2cpp_Vsize, "80 B9 ?? ?? ?? ?? 00 74 ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3"))
        {
            tar_addr = address + 11;
        }
        else if (address = PatternScan_Region((uintptr_t)Ua_il2cpp_RVA, Ua_il2cpp_Vsize, "75 05 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 28 C3"))
        {
            tar_addr = address + 9;
        }
        else
        {
            Show_Error_Msg(L"UI pattern outdate!");
            goto __exit;
        }
        int64_t rip = tar_addr;
        rip += *(int32_t*)rip;
        rip += 8;
        rip -= GameAssembly_PEbuffer;
        retvar = ((uint64_t)il2cpp_base + rip);
    }
    
__exit:
    VirtualFree_Internal((void*)GameAssembly_PEbuffer, 0, MEM_RELEASE);
    return retvar;

}

//For choose suspend
static DWORD __stdcall Thread_display(LPVOID null)
{
    while (1)
    {
        NtSleep(100);
        if (Process_endstate)
            break;
        printf_s("\rFPS: %d - %s    %s", FpsValue, FpsValue < 30 ? "Low power state" : "Normal state   ", "  Press END key stop change  ");
    }
    Process_endstate = 0;
    return 0;
}

// 禁用控制台滚动 disable console text roll
static void FullScreen()
{
    HANDLE Hand;
    CONSOLE_SCREEN_BUFFER_INFO Info;
    Hand = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(Hand, &Info);
    SMALL_RECT rect = Info.srWindow;
    COORD size = { rect.Right + 1 ,rect.Bottom + 1 };	//定义缓冲区大小，保持缓冲区大小和屏幕大小一致即可取消边框 
    SetConsoleScreenBufferSize(Hand, size);
}


int main(/*int argc, char** argvA*/void)
{
    
    SetPriorityClass((HANDLE)-1, REALTIME_PRIORITY_CLASS);
    SetThreadPriority((HANDLE)-2, THREAD_PRIORITY_TIME_CRITICAL);
    setlocale(LC_CTYPE, "");
    FullScreen();
    SetConsoleTitleA("HoyoGameFPSunlocker");
    _console_HWND = GetConsoleWindow();
    if (_console_HWND == NULL)
    {
        Show_Error_Msg(L"Get Console HWND Failed!");
    }
    
    wprintf_s(L"FPS unlocker 2.9.0\n\nThis program is OpenSource in this link\n https://github.com/winTEuser/Genshin_StarRail_fps_unlocker \n这个程序开源,链接如上\n\nNTKver: %u\nNTDLLver: %u\n", (uint32_t)*(uint16_t*)(0x7FFE0260), ParseOSBuildBumber());

    if (NTSTATUS r = init_API())
    {
        return r;
    }

    Boot_arg barg{};
    if (Init_Game_boot_arg(&barg) == 0)
        return 0; 

    if (LoadConfig() == 0)
        return 0;

    wstring* ProcessPath = NewWstring(GamePath.size() + 1);
    wstring* ProcessDir = NewWstring(GamePath.size() + 1);
    wstring* procname = NewWstring(32);
    *ProcessPath = GamePath;
    *ProcessDir = ProcessPath->substr(0, ProcessPath->find_last_of(L"\\"));
    *procname = ProcessPath->substr(ProcessPath->find_last_of(L"\\") + 1);

    wprintf_s(L"\nGamePath: %s \n\n", GamePath.c_str());
    if(isGenshin == 0)
    {
        wprintf_s(L"When V-sync is opened, you need open setting then quit to apply change in StarRail.\n当垂直同步开启时解锁帧率需要进设置界面再退出才可应用\n");
    }

    {
    _wait_process_close:
        DWORD pid = GetPID(procname->c_str());
        if (pid)
        {
            int state = MessageBoxW_Internal(L"Game has being running! \n游戏已在运行！\nYou can click Yes to auto close game or click Cancel to manually close. \n点击确定自动关闭游戏或手动关闭游戏后点取消\n", L"Error", 0x11);
            if (state == 6)
            {
                HANDLE tempHandle = OpenProcess_Internal(PROCESS_TERMINATE | SYNCHRONIZE, pid);
                TerminateProcess_Internal(tempHandle, 0);
                WaitForSingleObject(tempHandle, 2000);
                CloseHandle_Internal(tempHandle);
            }
            goto _wait_process_close;
        }
    }

    if (isGenshin)
    {
        
        HANDLE file_Handle = CreateFileW(ProcessPath->c_str(), GENERIC_ALL, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file_Handle != INVALID_HANDLE_VALUE)
        {
            DWORD64 Size = 0;
            GetFileSizeEx(file_Handle, (PLARGE_INTEGER)(&Size));
            if (Size < 0x800000) is_old_version = 1;
            else is_old_version = 0;
            CloseHandle_Internal(file_Handle);
        }
        else
        {
            Show_Error_Msg(L"OpenFile Failed!");
        }
    }
    
    size_t bootsize = sizeof(STARTUPINFOW) + sizeof(PROCESS_INFORMATION) + 0x20;
    LPVOID boot_info = malloc(bootsize);
    STARTUPINFOW* si = (STARTUPINFOW*)((uint8_t*)boot_info + sizeof(PROCESS_INFORMATION) + 0x8);
    PROCESS_INFORMATION* pi = (PROCESS_INFORMATION*)boot_info;
    if (!boot_info)
    {
        Show_Error_Msg(L"Malloc failed!");
        return -1;
    }
    memset(boot_info, 0, bootsize);

    if (!((CreateProcessW_pWin64)~(DWORD64)CreateProcessW_p)(ProcessPath->c_str(), (barg.Game_Arg), NULL, NULL, FALSE, CREATE_SUSPENDED | GamePriorityClass, NULL, ProcessDir->c_str(), si, pi))
    {
        Show_Error_Msg(L"CreateProcess Fail!");
        return 0;
    }
    free(barg.Game_Arg);

    inject_arg injectarg = { 0 };
    Hook_func_list GI_Func = { 0 };
    
    if ((isGenshin == 0) && Use_mobile_UI)
    {
        injectarg.Bootui = Hksr_ENmobile_get_Ptr(pi->hProcess, ProcessDir->c_str());
    }
    //加载和获取模块信息
    LPVOID _mbase_PE_buffer = 0;
    uintptr_t Text_Remote_RVA = 0;
    uintptr_t Unityplayer_baseAddr = 0;
    uint32_t Text_Vsize = 0;
    {
        _mbase_PE_buffer = VirtualAlloc_Internal(0, 0x1000, PAGE_READWRITE);
        if (_mbase_PE_buffer == 0)
        {
            Show_Error_Msg(L"VirtualAlloc Failed! (PE_buffer)");
            TerminateProcess_Internal(pi->hProcess, 0);
            CloseHandle_Internal(pi->hProcess);
            return 0;
        }

        if (isGenshin && is_old_version == 0)
        {
            Unityplayer_baseAddr = (uint64_t)RemoteDll_Inject(pi->hProcess, 0);
        }
        else
        {
            wstring EngPath = *ProcessDir;
            EngPath += L"\\UnityPlayer.dll";
            Unityplayer_baseAddr = (uintptr_t)RemoteDll_Inject(pi->hProcess, EngPath.c_str());
        }

        if (Unityplayer_baseAddr)
        {
            if (ReadProcessMemoryInternal(pi->hProcess, (void*)Unityplayer_baseAddr, _mbase_PE_buffer, 0x1000, 0))
            {
                if (Get_Section_info((uintptr_t)_mbase_PE_buffer, ".text", &Text_Vsize, &Text_Remote_RVA, Unityplayer_baseAddr))
                    goto __Get_target_sec;
            }
        }
        
        Show_Error_Msg(L"Get Target Section Fail! (text)");
        VirtualFree_Internal(_mbase_PE_buffer, 0, MEM_RELEASE);
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }

__Get_target_sec:
    // 在本进程内申请代码段大小的内存 - 用于特征搜索
    LPVOID Copy_Text_VA = VirtualAlloc_Internal(0, Text_Vsize, PAGE_READWRITE);
    if (Copy_Text_VA == NULL)
    {
        Show_Error_Msg(L"Malloc Failed! (text)");
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }
    // 把整个模块读出来
    if (ReadProcessMemoryInternal(pi->hProcess, (void*)Text_Remote_RVA, Copy_Text_VA, Text_Vsize, 0) == 0)
    {
        Show_Error_Msg(L"Readmem Fail ! (text)");
        VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }
   
    //starrail 
    //66 0F 6E 05 ?? ?? ?? ?? F2 0F 10 3D ?? ?? ?? ?? 0F 5B C0
    // 
    //7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8 
    // 
    //7F 0E E8 ? ? ? ? 66 0F 6E C8 0F 5B C9
    //
    //7E 0C E8 ?? ?? ?? ?? 66 0F 6E C8 0F 5B C9 
    // 8B 0D ?? ?? ?? ?? 66 0F 6E C9 0F 5B C9 
    // 计算相对地址 (FPS)
    
    uintptr_t pfps = 0;
    uintptr_t address = 0;
    if (isGenshin)
    {
        if (Use_mobile_UI)
        {
            //platform_flag_func
            address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "E8 ?? ?? ?? ?? 48 8B 7D 40 89 87 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B C0");
            if (address)
            {
                int64_t rip = address;
                rip += 1;
                rip += *(int32_t*)(rip)+4 + 1;// +1 jmp va
                rip += *(int32_t*)(rip)+4;
                GI_Func.Pfunc_device_type = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            }
            else
            {
                Use_mobile_UI = 0;
            }
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "8B 0D ?? ?? ?? ?? 66 0F 6E C9 0F 5B C9");//5.5
        if (address)
        {
            int64_t rip = address;
            rip += 2;
            rip += *(int32_t*)(rip)+4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7E 0C E8 ?? ?? ?? ?? 66 0F 6E C8 0F 5B C9");//5.4
        if (address)
        {
            int64_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip) + 6;
            rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7F 0E E8 ?? ?? ?? ?? 66 0F 6E C8"); // ver 3.7 - 5.3 
        if (address)
        {
            int64_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip) + 6;
            rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8"); // ver old
        if (address)
        {
            int64_t rip = address;
            rip += 4;
            rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        Show_Error_Msg(L"Genshin Pattern Outdated!\nPlase wait new update in github.\n\n");
        VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }
    else
    {//HKSR_pattern
        isHook = 0;
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "66 0F 6E 05 ?? ?? ?? ?? F2 0F 10 3D ?? ?? ?? ?? 0F 5B C0"); //ver 1.0 - last
        if (address)
        {
            int64_t rip = address;
            rip += 4;
            rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            
            if (address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "CC 89 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC CC"))
            {
                int64_t rip = address;
                rip += 3;
                rip += *(int32_t*)(rip)+4;
                if ((rip - (uintptr_t)Copy_Text_VA + (uintptr_t)Text_Remote_RVA) == pfps)
                {
                    rip = address + 1;
                    DWORD64 Patch0_addr_hook = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
                    uint8_t patch = 0x8B;      //mov dword ptr ds:[?????????], ecx   -->  mov ecx, dword ptr ds:[?????????]
                    if (WriteProcessMemoryInternal(pi->hProcess, (LPVOID)Patch0_addr_hook, (LPVOID)&patch, 0x1, 0) == 0)
                    {
                        Show_Error_Msg(L"Patch Fail! ");
                    }
                    goto __Continue;
                }
            }
            Show_Error_Msg(L"Get pattern Fail! ");
            goto __Continue;
        }
        Show_Error_Msg(L"StarRail Pattern Outdated!\nPlase wait new update in github.\n\n");
        VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }
    //-------------------------------------------------------------------------------------------------------------------------------------------------//

__genshin_il:
    if(Use_mobile_UI || isHook)
    {
        uintptr_t UA_baseAddr = Unityplayer_baseAddr;
        if (is_old_version)
        {
            wstring il2cppPath = *ProcessDir;
            il2cppPath += L"\\YuanShen_Data\\Native\\UserAssembly.dll";
            UA_baseAddr = (uintptr_t)RemoteDll_Inject(pi->hProcess, il2cppPath.c_str());
            if (UA_baseAddr)
            {
                if (!ReadProcessMemoryInternal(pi->hProcess, (void*)UA_baseAddr, _mbase_PE_buffer, 0x1000, 0))
                {
                    goto __procfail;
                }
            }
        }
        if (Get_Section_info((uintptr_t)_mbase_PE_buffer, "il2cpp", &Text_Vsize, &Text_Remote_RVA, UA_baseAddr))
        {
            goto __Get_sec_ok;
        }
        Show_Error_Msg(L"Get Section Fail! (il2cpp_GI)");

    __procfail:
        isHook = 0;
        goto __Continue;

    __Get_sec_ok:
        VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
        Copy_Text_VA = VirtualAlloc_Internal(0, Text_Vsize, PAGE_READWRITE);
        if (Copy_Text_VA == NULL)
        {
            Show_Error_Msg(L"Malloc Failed! (il2cpp_GI)");
            goto __procfail;
        }
        if (!ReadProcessMemoryInternal(pi->hProcess, (void*)Text_Remote_RVA, Copy_Text_VA, Text_Vsize, 0))
        {
            Show_Error_Msg(L"Readmem Fail ! (il2cpp_GI)");
            goto __procfail;
        }
        if (isHook)
        {
            address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "48 89 F1 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 48 8B 0D");
            if (address)
            {
                int64_t rip = address;
                rip += 10;
                rip += *(int32_t*)rip;
                rip += 4;
                injectarg.Pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            }
        }
        else isHook = 0;

        //verfiyhook
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "E8 ?? ?? ?? ?? EB 0D 48 89 F1 BA 02 00 00 00 E8 ?? ?? ?? ?? 48 8B 0D");
        if (address)
        {
            int64_t rip = address;
            rip += 0x1;
            rip += *(int32_t*)(rip)+4;
            injectarg.verfiy = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
        }
        else
        {
            Show_Error_Msg(L"GetFunc Fail ! GIx0");
        }
        if (Use_mobile_UI)
        {
            //setting bug
            address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "E8 ?? ?? ?? ?? 83 F8 02 75 0B 48 89 F1 48 89 FA E8");
            if (address)
            {
                int64_t rip = address;
                rip += 0x6;
                GI_Func.setbug_fix = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            }
            else
            {
                Use_mobile_UI = 0;
            }
            //Unhook_hook
            address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "48 89 F1 E8 ?? ?? ?? ?? 48 89 D9 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 80 B9 ?? ?? ?? ?? 00");
            if (address)
            {
                int64_t rip = address;
                rip += 0xC;
                rip += *(int32_t*)(rip)+4;
                GI_Func.Unhook_func = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            }
            else
            {
                Use_mobile_UI = 0;
            }
            if (Use_mobile_UI)
            {
                injectarg.Bootui = Tar_Device;
                injectarg.PfuncList = &GI_Func;
            }
            else 
            {
                GI_Func.Pfunc_device_type = 0;
            }
        }

    }

__Continue:
    uintptr_t Patch_buffer = inject_patch(pi->hProcess, pfps, &injectarg);
    if (!Patch_buffer)
    {
        Show_Error_Msg(L"Inject Fail !\n");
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }

    if (barg.Path_Lib)
    {
        wprintf_s(L"You may be banned for using this feature. Make sure you had checked the source and credibility of the plugin.\n\n");
        HMODULE mod = RemoteDll_Inject_mem(pi->hProcess, barg.Path_Lib);
        if (!mod)
        {
            Show_Error_Msg(L"Dll Inject Fail !\n");
        }
        free(barg.Path_Lib);
    }
    
    DelWstring(&ProcessPath);
    DelWstring(&ProcessDir);
    DelWstring(&procname);

    VirtualFree_Internal(_mbase_PE_buffer, 0, MEM_RELEASE);
    VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
    
	//SetThreadAffinityMask(pi->hThread, 0xF);
	SetThreadPriority(pi->hThread, THREAD_PRIORITY_HIGHEST);
    ResumeThread_Internal(pi->hThread);
    CloseHandle_Internal(pi->hThread);
    
    SetPriorityClass((HANDLE) -1, NORMAL_PRIORITY_CLASS);

    if(!AutoExit)
    {
        wprintf_s(L"PID: %d\n \nDone! \n \nUse ↑ ↓ ← → key to change fps limted\n使用键盘上的方向键调节帧率限制\n\n\n  UpKey : +20\n  DownKey : -20\n  LeftKey : -2\n  RightKey : +2\n\n", pi->dwProcessId);

        // 创建printf线程
        HANDLE hdisplay = CreateRemoteThreadEx_Internal((HANDLE)-1, 0, Thread_display, 0);
        if (!hdisplay)
            Show_Error_Msg(L"Create Thread <Thread_display> Error! ");

        DWORD dwExitCode = STILL_ACTIVE;
        uint32_t fps = FpsValue;
        uint32_t cycle_counter = 0;
        while (1)   // handle key input
        {
            NtSleep(50);
            cycle_counter++;
            GetExitCodeProcess(pi->hProcess, &dwExitCode);
            if (dwExitCode != STILL_ACTIVE)
            {
                printf_s("\nGame Terminated !\n");
                break;
            }
            if ((FpsValue != fps) && (cycle_counter >= 16))
            {
                WriteConfig(fps);
                FpsValue = fps;
                cycle_counter = 0;
            }
            FpsValue = fps;   //Sync_with_ingame_thread
            if ((GetForegroundWindow() != _console_HWND) && (isAntimiss == 1))
            {
                continue;
            }
            if (GetAsyncKeyState(KEY_DECREASE) & 1)
            {
                fps -= 20;
            }
            if (GetAsyncKeyState(KEY_DECREASE_SMALL) & 1)
            {
                fps -= 2;
            }
            if (GetAsyncKeyState(KEY_INCREASE) & 1)
            {
                fps += 20;
            }
            if (GetAsyncKeyState(KEY_INCREASE_SMALL) & 1)
            {
                fps += 2;
            }
            if (fps <= 10)
            {
                fps = 10;
            }
        }
        Process_endstate = 1;
        WaitForSingleObject(hdisplay, INFINITE);
        CloseHandle_Internal(hdisplay);
    }
    else
    {
        NtSleep(1000);
    }
    CloseHandle_Internal(pi->hProcess);
    free(boot_info);
    
    
    return 1;
}





