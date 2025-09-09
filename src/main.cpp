#define KEY_TOGGLE VK_END
#define KEY_INCREASE VK_UP
#define KEY_INCREASE_SMALL VK_RIGHT
#define KEY_DECREASE VK_DOWN
#define KEY_DECREASE_SMALL VK_LEFT
#define FPS_TARGET 120
#define DEFAULT_DEVICE 8 
#define CONFIG_FILENAME (L"hoyofps_config.ini")
#define IsKeyPressed(nVirtKey)    ((GetKeyState(nVirtKey) & (1<<(sizeof(SHORT)*8-1))) != 0)

#ifndef _WIN64
#error you must build in Win x64
#endif


#include <iostream>
#include <vector>
#include <string>

#include <Windows.h>
#include <TlHelp32.h>

#include "NTSYSAPI.h"
#include "inireader.h"


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
 0x68EC834856405340, 0x00000030B8CB8948, 0x4401482024448948, 0x3120244C8D482024,
 0x35E82824448D4CD2, 0x7275C08548000009, 0x0589482824448B48, 0xE8D98948FFFFFF84,
 0x65C689480000007C, 0x0000006025148B4C, 0x617574726956B848, 0x8B4D18528B4D466C,
 0x8B4D00528B4D2052, 0x8948204A8B490052, 0x72382444C7302444, 0x3024548D48006565,
 0x85480000033AE848, 0x28244C8B481474C0, 0xB841D23148D1F748, 0x4890D0FF00008000,
 0x5B5E68C48348F089, 0xCCCCCCCCCCCCCCC3, 0xCCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCCC,
 0xFFD86C355FF510AA, 0xFF5E088D638C73E6, 0x99A783C59A8F3FE6, 0x5EEF8CB19EC806A7,
 0x9A6CC44E6137F867, 0xDDE7818D3E68B92F, 0x22187E72FFAFF17F, 0x2716960ADBDB7837,
 0xE793DEFA50937837, 0x6CDB23BCDDDB6942, 0x2D93E73F95A34D36, 0x65C7A0B4D0601269,
 0x2DAF84E85928C5E2, 0x61EFA08CD0640B69, 0x61E9A764E84067E0, 0x52ACB30B5F4F22E0,
 0xE5A3F2139ACC6B04, 0x8298B77575CF26D8, 0xE4FED11313F055DE, 0xC5F9D11E13744AD1,
 0x8479DD935BB7FDDE, 0x9C0D1D164B7AB955, 0x5C865902862E3214, 0x8B85110E4B62B955,
 0x8B8514B6A3ACBA1D, 0x8DDA2FF7C56F457B, 0xD2F162294E238B09, 0xD245C5100B48FF39,
 0x62CA4E55693CFF39, 0x5B8F8056253CFF39, 0xDE8BC1DD646F8B18, 0x9383295E2C24FFD8,
 0x5306C18F642CBE55, 0x5319CE5FEF688E21, 0x35DB7950FFDF8160, 0x74CA0C5AC3D369A1,
 0x74CA03A52152602A, 0x75D602E93756ED62, 0x743C81A035966E2B, 0x777085E1BED7B85E,
 0xFE3828949FEEFD96, 0xCE1C5C1DD39ED9FA, 0xC11C5C1D4739E0BF, 0x7697191D47399F3B,
 0x33611A5147399FAB, 0x337E153E3335F992, 0xDBB016763F7B72D3, 0x93589D3E3F7B7117,
 0x8326167F5E0FB192, 0x43A3E87C16093AD3, 0xCEEBEE709D417AA7, 0xFC9F27F5D5D17CBB,
 0xB498CC2462DE79C2, 0x3FD01D272ADC2F4F, 0xBA981D272B96C782, 0xF2981D27C112C842,
 0x71D01AAE891A0BC1, 0xB85552A502520306, 0x81104663811BCD73, 0xE62B0305156EC115,
 0xAED4320EFE01B213, 0xAED432C617FC7D90, 0x2ED8BF8ED34B72D1, 0x2ED8BF8E1E5FFF99,
 0x67274071E19E38D1, 0xEC63643B6ADAEDD2, 0x67227BC2AB9BE590, 0x47C2F8C04A18A451,
 0xB0E2384348D92710, 0xE269184348D90352, 0xA6E4508B0DD6475E, 0xE26D185D0E9E277A,
 0x846D185E8776075E, 0x820A231BE1B2F81F, 0x820AF39C6AF3666D, 0xDE81BBB01E33E36D,
 0x96A3CF6B9B7BFB5D, 0x06B9BBAB1E33F8D6, 0x8BF8752056F3CB93, 0x83BBFE68860CCAC3,
 0xF67B7B208E57478B, 0x82BBFE08C9DC066C, 0xCA7DFD4009EF434D, 0x1A82FC1084AE8DC6,
 0xF14477588ADA4D43, 0x0EBB88A44A1D055C, 0xF5740BECB52C13B7, 0x1D8BC26FFDFA98FF,
 0xE5028AFFFDFA9B93, 0x9189C68FD99610DB, 0xDDE1E2D352DE20FF, 0xF98D699F12FA4474,
 0x7AC511BB66710C4C, 0xB609D2E439304488, 0x7AC51E28F5FC8844, 0xB609D2E439304488,
 0xE15F87C41D6CCDC0, 0xE1B3068C4A2D9981, 0x6AFFEC07022D9983, 0x6B926808CBA8D14A,
 0x0F1667DA4EE0D14A, 0x0F163D97F6E0D14B, 0x0F176B12F9E1E82D, 0x5F1F5793C5A0632D,
 0x5F1E1116CAA06368, 0x5F1E991E6E2B2768, 0x5E2B1D118AAE6268, 0x5EA7159501EA6268,
 0xA19434A18CA06268, 0xA19435D1A824EB2C, 0x20DCCA2E57DB546D, 0x0BC6BD2E5724AB97,
 0x0F45B23A391FBBF9, 0x0C0DAE7CB21FBBF8, 0x0C0D15951A0B3039, 0xDE88508D4C807439,
 0x57C4508D4C1CF036, 0xDC80508D4D64D49A, 0x35831DAD23EF9045, 0xBCCF61D522051304,
 0xDAA961D5238537B0, 0xFBAE61D8230128BF, 0x2A6BEA94391DA5FC, 0x2922EA097596E407,
 0x4F448C6FB4BDA8CE, 0x6E438C62B439B7C1, 0x7FF5836AB08FB880, 0x7B8143EEB1C635C8,
 0x7DF281D45DB2F7F2, 0x7B84963FA2E17AB6, 0x350F99D4A3BAF7F2, 0xFC0CD0D5F937B2D6,
 0x2637958CC580BD92, 0x27B7B1384ECC1BEC, 0x26C795BCC5881BEC, 0x27BFB1104EC41BEC,
 0x60CCA56E75801BEC, 0xEB8D646D3C9C5D67, 0xDCF9B6E8B488D6A8, 0xDCF9666ABB5CEDE9,
 0xD3295D4ABFD1AEE9, 0x11A2194ABFD16A6A, 0x1EE3C1C1F6106927, 0x8E85D0B536946991,
 0x8FC666BA12E047AD, 0xBC37137A9623B8E5, 0xBC355B5E0AA8F025, 0xBC35595ECE29B825,
 0x7F6807019268E764, 0xFE20D72ADBBB6C2C, 0xB6F8A42ADBBA4CD6, 0x26EED0F85EF28B5D,
 0x522754F85244841C, 0x92D81CD856080C10, 0xDE55543324CA3758, 0x3675504FAC8A177C,
 0x7EB5DB03AC8A1720, 0x5DB4A0830FFED7A5, 0xEBBB8DF60EAD5AED, 0x393F8F358DE558BE,
 0x62B2C7E5CF6846CA, 0xA00CC8F6B8617ACB, 0xDF81DB40B7DE4646, 0x3DF409C4CFE2CBAE,
 0xD5B8C14F8635A8E6, 0x2A47A1A679CA5532, 0x7CAE60A53008DECD, 0xB062AC69FCF72132,
 0x7CAE5396053504CD, 0xB0629F5AC9F9C801, 0xE4EBD742EDBD414D, 0x6FA3EFAE6EF55169,
 0x2B64A751910CCA6C, 0xDC2DA751910C8248, 0x953ED35191037D88, 0x14772CAE61039D09,
 0x50FE60AE61139DC9, 0x74BAA77E965BCDED, 0x3837EB7E965BC9C5, 0x0837CB5AD29C99E1,
 0x5CBA839AE1D999E1, 0x44EA7C9A6A91D1C5, 0xC7A2BCA96DE81140, 0x8F86F822252B2984,
 0x434A34E11DEFAACC, 0x8F86F82DD1236600, 0x6305B035F567EF4C, 0x9CFA4915F0ECA704,
 0x6CFAAB94B8352C48, 0x6CFA9BB0FCF2D3B7, 0x24C2BFE475BAD3B7, 0x681248AC459E9F3A,
 0x4C46C5E425BADBB7, 0x68024EAC3531978F, 0xA04741E4F5B4DFFF, 0x6BCC08C4D1F856B7,
 0x23088B8CE9AAA9F6, 0xEFC4474025666535, 0x03470F500132EC7D, 0xFCB8F79004B9A445,
 0xFCB8F7B020FD630D, 0xD8FC7AFCF00A2B0D, 0x90FC7A7CF0B36A2D, 0x6FFCF134B8973EA0,
 0xA33FC9F03BDF1EF0, 0x6FF3053CF713D23C, 0xA33FC9F03BDF1EF0, 0x6FF3053CF713D23C,
 0x18FCFDBFBED25974, 0x39FBFDB23ECD5663, 0xCB70B54BB5850034, 0x082FEBEF464D8B7D,
 0x07DCF19866B50834, 0x05889E972446025B, 0x0ACA6D9E5B49F1AB, 0xC606A15DAB48A5D4,
 0x8ACC9A15A944289A, 0x08C3532EE08D6E95, 0x0AAC5CDDE08D6E59, 0x435C5EB18F822CAA,
 0xC5535EB18F02D42B, 0x8C9AD5FD8F02D4BB, 0xC58A3C7EC60D3538, 0x048971AFED44FC13,
 0x728971AF6DBC7D5A, 0x538E71A2EDA37229, 0x01E17E51E7CC7DDA, 0x0E125E0B88C38ECA,
 0x681B2104EEF3ECA5, 0x31642E62FEA293AA, 0x3E971E0381ADF58A, 0x6EC5710C72EDBFE5,
 0x01CA826C2882B016, 0x678ACB1327E4C074, 0x3EF5C47577B5BF7B, 0xBFBDB41408BAD91B,
 0x7D3CFC1408BA59DA, 0xFDD47D5D08BA595A, 0xFD5485DC41BA595A, 0xF21C0891D5C9595A,
 0x8D134A622528DA13, 0x6413356DD6D8DB7F, 0xA8DFF9A129272583, 0x6413356DE5EBE94F,
 0x675AE446ADF9F940, 0xE4121457E9E9F688, 0x25E404BF6AA0E661, 0xA6ACCD3426B8926E,
 0xA2BCC2FC36B7628F, 0x63378EF527B8239E, 0xA27E467E6A7808D2, 0x497F6F711B0C0F3B,
 0x2F1909177D6A692D, 0x0E1E091A7DEE7622, 0x011720156DAF5F2D, 0x105B301A9DBE1B3D,
 0x105B309A743F53DD, 0x70121995047E7AD2, 0x3C0216C5153A6ADD, 0x7D2B190CEA732ACC,
 0x393B164CA35A259C, 0x361B0700B355158D, 0x393B4E29BC6554A4, 0x28375E26AC7410B4,
 0xAB7E4E67857BBEC1, 0x63F503A6AD74C121, 0x059319D2A99D0068, 0x249419DFA9191F67,
 0x2B84F05CE1180E68, 0xDBF139A3A8090A78, 0xCAFE3AD7A7E98931, 0x0632F614A6F88621,
 0xCAFE3AD86A344AED, 0x0632F614A6F88621, 0xCAFE3AD86A344AED, 0x0632F614A6F88621,
 0x8B7BA142F3240D6D, 0x8B7A91AE726CB506, 0xC31F61253B6D3E06, 0x48577964B025368D,
 0x30DC31653B6D16C5, 0x3709B56AC4E85EE5, 0x4F8AFD6A4FA05EE5, 0x4F8AFAADCBAF5EC5,
 0x5FF973E0C3F4D78C, 0x2A2BF63A4802E4C9, 0x8AB167ACC0BAAC8F, 0xB2952B2188313617,
 0xFA979919AC75BF5F, 0x6A01159436FC1FE7, 0xCFE955B072755776, 0xF7CD013D3A755771,
 0x384649751E01DE3D, 0xF8C3018AE1F80DD5, 0xB0DB8AC2310708A1, 0x2C4B19518F8CB919,
 0xA5032175C301F187, 0x2EBB69767139D5C3, 0x6625E3FDFCAF7C59, 0xD4B65BB5BC8B38D0,
 0x5DFE6933311BAA4A, 0x5DFE6E63D9538E0E, 0x29762A5BFD070346, 0xD008C294764F4C62,
 0x981EB654F307B39D, 0x744B3B1CEB726818, 0x744B3C4403BAE350, 0xB449844F77BB1BD3,
 0x3C0C0D0708501BD3, 0xA69680BE83E1A39B, 0xA7F6A4020AAD3532, 0xEFCE804683E53532,
 0x625E380EBBC179BF, 0xDD17A2BC285F9F39, 0x4F8D102FB6D514B4, 0x03C5346B3F9D1706,
 0x03C3E3837FB96B8F, 0x8B87DBA72B34238F, 0x8E6F142C637F07FB, 0x981BD4A92B80F802,
 0xCD969C905E5B7D4A, 0xCD90437896D035BA, 0xCE286F0C9728B6BA, 0xAE0CD387DB28B67A,
 0xFE284F0C9328B67B, 0xA60CFB87DF28B67A, 0xA73C3F069728B67B, 0x2E74FC5BC977B67B,
 0xB4D977EA713F263E, 0x90A5FEA6E796BDA0, 0x1DEDC682A31FF5E0, 0x9B60563AEB27D1AC,
 0xD363E4B05205425B, 0xD365AB581A2106D2, 0x5B21937C4EAC4ED2, 0x26C95CF706E76AA6,
 0x30BD9C724E18955E, 0x6530D4693BC31016, 0x65368381F34858EE, 0x618E8DF5F2B0DBEE,
 0x9E7172861BB0DB2E, 0x15C0CACEBBF55266, 0x988856543065DFC9, 0xA0AC12DD785DFB85,
 0x2D3ABB56C015F837, 0x097E321E538B72BC, 0x84EEA084E1333AFC, 0xCCCAE40DA99CD37A,
 0x9847AC0DA9990892, 0xD009887921DD30B6, 0x98F677812835FF3D, 0xED2DF2C93E413FB8,
 0x25A6BA356BCC77A3, 0x245E39356BC9944B, 0xCD5E39F56D719A3F, 0x651BB0BD928E64C0,
 0xF4813F0D193FDC88, 0xBCE11B4194775127, 0x04A919F3F45315AE, 0xA616037F78C9893E,
 0xA360EB175C8D0076, 0xE700CF43D1C50076, 0x0FCF440BBCE174FE, 0x7B0FC143431E835A,
 0xF647DA36989BCB4C, 0xF33932FE13D3CF19, 0x4B3746FFEB50CF19, 0xB4C9DC16EB500F11,
 0x057194AEAED947EE, 0x4DCB12303D43FC65, 0xFFD357B9755BB1E8, 0x7459CB23F2E3F9EA,
 0x9C798EAABA72697C, 0x842C03E2BA726C68, 0x6CE388AA9207E524, 0x63230DE26DF81260,
 0x26AA45E26DFCCAE4, 0x2557C0EDB679823C, 0x65DA8CFFFEF2823C, 0xE4DA73000113032E,
 0xA8CD0700C2160CD7, 0x57E80F40491E4C5A, 0x572B0A4F741EB3A5, 0x12A00A4F708136AA,
 0x74C64A6B34087E46, 0x55C14A66348C6149, 0x5E896A84F5C45046, 0x59768B053D4F1884,
 0x5A3F8FE4FC071884, 0x5AC0701BD906934C, 0x3C19051B1A039C71, 0x1D1E05161A87837E,
 0x165625F4DBCFB271, 0x11A9C6750344FAB3, 0x12E0C296C20CFAB3, 0xED1F3D74431F716B,
 0x981FFE714CE5F06B, 0xB03BBAB69D12B8BC, 0x947733FE9D12B8B8, 0x193F03DAD19FF480,
 0x511B471D99A7D0CC, 0x19DB745866582F33, 0x19DBF458567C6BF4, 0x6D52B8007228E6BC,
 0x5D52982436EFBE98, 0xD85298212707BE98, 0x90AD67DC438FB158, 0x9015EA941BABF5D3,
 0x1B59D21D53ABF5C3, 0x3B59129C1AF3D187, 0xBA117AE993B7D187, 0xF6117AC99387F5EB,
 0x37594BC6F3A3B162, 0xE752031504EB9180, 0x37614B6520AF1CC8, 0x7FABC02DC0EA9180,
 0xF4E709A68CCA7841, 0xB835FEE746F93490, 0x8B70375049B8FCA3, 0x9B98F6188833B572,
 0xDF5F4F514900F414, 0xD01BB0AEB6FFF030, 0x10ADBF6F85B72886, 0x144E7E26A577ABCE,
 0x5A967D6BA1976A86, 0xADF0BFDCAE8F6E0B, 0x6CC3F7D4F60627DB, 0x694EBF84E646E09A,
 0x7DC9F33CAE965695, 0x7D40BA85E6C60FB1, 0x55007CC4E5048CF9, 0x850335C007C5C43A,
 0xCD07D401CD73CB7B, 0x0D2C95318CFE0178, 0x4538D5B8CDE6E9FB, 0x4870F5580CAE2B70,
 0x50307C1128AAEC38, 0x5D78BD3261686770, 0x7D38347B654C23B7, 0x823810DFE8049BFF,
 0x3A70209E614C6400, 0x3A7022BE45E8E948, 0xBD389AF67DA96000, 0x347011BEE9E14404,
 0xBF3819D651A90445, 0xF779909ED2E10405, 0x7A3154159AB1BC4D, 0xB9219045DB7698E9,
 0x40A1280DD9FFD025, 0xC9E90C215EB72FDA, 0xC1058F69E6FF2798, 0xD1470621C2FBAED0,
 0x2FA722854FB31698, 0x97EF3AC7C6FBE967, 0x9FAFB78FEE72D998, 0x8FA00FC7CE3050D0,
 0x06E82B83DF3F6090, 0x46F824AB677748D2, 0x76BAADE323664792, 0x26FABDEC1B42FFDA,
 0x9EB285AE920AEED5, 0x91D2C5BE9D42CA91, 0xD9967CF7DD0043D9, 0x54DFB03B3CFF922E,
 0x8428F96B7676DE25, 0x0360A14F3267666D, 0xBB28E90DBB2F662D, 0x77E425C177E3AAE1,
 0xCFB59F896FA023A8, 0x46FC26C1905FDC57, 0x0D756BC9D3D69144, 0x4EFC26E9805FD854,
 0x0D756FD9CBD6957C, 0x4EFC2299985FDC44, 0x0D756BC9D3D6910C, 0x59F823A9805FD854,
 0xD4B44BEA0912B870, 0x95C4006344229C34, 0xD64D49634422BC8D, 0x5D4F08EAA86737F5,
 0xDE0780A7212FC7B0, 0x22420BA560A6E771, 0x028388EDF0EB6E39, 0x8BCB70A87BE92FB0,
 0xCA425069F8A187FD, 0xEE06D92104E40CFF, 0xA38F9149416944BF, 0x2AC7A96D0DE40C1F,
 0x2AC7AB15E5C4285B, 0xD53851DE6DCBE8DE, 0x90B519AE498FC0D1, 0xB0B5298A0D4888B9,
 0xBF850DCE800488B9, 0xFEDD299A0D4C8FA8, 0xB3F5269A0D4C8D11, 0xA2FA1EBE41C1C591,
 0xADDA3AFAC889D5DE, 0xA2FA7DEBC71990F6, 0xADCA32FAC8B9DDDE, 0xA28A75EBC70998F6,
 0xADDA3AFAC8C9D5DE, 0x45BA7DEBC71990F6, 0xCDB5BD6EC71992FA, 0xE9F1362638E668A5,
 0xDAF7BF6EE81120FD, 0x9F3B4091125CC93D, 0x9F3F68B5569B090E, 0xD35F4CF9DBD7090E,
 0xF70BC1B1EBF37D87, 0xD70BA195AF3435B7, 0xE70B81B1EBF335B7, 0xB2F47EF966BA35B7,
 0x4D0E6C7C697AB03F, 0xC0425C5825F1F8C0, 0xC0425EE16491DC84, 0x4D0A6EC5301C9484,
 0x4C8326C5301F7C05, 0x047CD93ACFDEBB4D, 0x2038F135FFFAFFC6, 0x6838F13617FFB7B6,
 0x6738E03927DBF33F, 0x6828A828285BBE17, 0x6708E83927CBFB3F, 0x6838A028286BB617,
 0x6778E03927DBF33F, 0x6828A828281BBE17, 0x2048E83927CBFB3F, 0x006CACB06FA3BEB2,
 0x90E9A370EA0BEB4D, 0xA0CDE7FBA2F414B4, 0x60FEE172EA24E3FC, 0xA020598D15DD9D15,
 0x18DFA674613443B8, 0x281B273CA134428D, 0xE4D87A62FE34428C, 0x2814B6AE32F88E40,
 0xEAA2B9B946074CC0, 0xEAE2A6B68703C188, 0x6A1AE63BCF1336C0, 0x22D850343B66C902,
 0xE1195CB973A7DDF5, 0x2DD59075BF6B1139, 0xA89D51FEF3B99A75, 0x239D51FE4A3D95BC,
 0x28E8E92FC171A8BD, 0x28E9512D4875E936, 0x91F125C474B6E936, 0xE5301EA274B6CCC9,
 0xDE561EA2CCFE75C7, 0x66561EA2457B7A06, 0x66560E1B457B7A07, 0x47510E16C5647507,
 0x8D7A42DE4E29A48C, 0xF9C29355021025CD, 0x2849DF573E91678B, 0xAB59AB55321C2933,
 0xDD7953D6F2E339F2, 0x5EBAAC290D1C8125, 0xD5FBAD2D865A85E4, 0x3C2A65A64671C134,
 0x7DFB4EA64671C08C, 0x39F36BA2B079B90D, 0xB230692BF5BBFD02, 0x443810AAB4512CD2,
 0x85BBC0EFBB5909D6, 0x85BBC1577A72452A, 0x46A948166A71042A, 0x8A6584DAA6B2C419,
 0x9A340F96AEC33B51, 0x9FB947D2AE8AB019, 0x5B320F82AE8AB075, 0xA4CDF6028A2E3D3D,
 0xAC21754AAE02BA75, 0x8885F8028A06333D, 0xA00CC8FD75F9CDDD, 0x904CD8F27DB94095,
 0xD05CD7DA59FD519A, 0xC053EFFE1DEC5EDA, 0xCF1BCBBA0CE30E9A, 0x973F8FAB03834E8A,
 0x46C8C7EF03C3C9C2, 0x8A040B23CF0F283D, 0x46C8C7EF03C3E4F1, 0x8A040B23CF0F283D,
 0x75FBFB23EBABA575, 0x8A040B23CF0F283D, 0x8A042A03EBABA575, 0x014CBE4BCFAF223D,
 0x8204BE0B44E72A55, 0x4EC872C788243A91, 0x8204BE0B44E8F65D, 0x4EC872C788243A91,
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
    0x48, 0xE8, 0xF4, 0x02, 0x00, 0x00,                  //call API_OpenProcess
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


const DECLSPEC_ALIGN(32) int8_t g_HexLookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0-15
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 16-31
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 32-47
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 48-63 ('0'-'9')
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 64-79 ('A'-'F')
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 80-95
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 96-111 ('a'-'f')
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  // 112-127
};

#define SSE2_Support 0b0001
#define AVX2_Support 0b0010
#define AVX512_Support 0b0100

static uint8_t InitCPUFeatures()
{
    uint8_t result = 0;

    int cpuInfo[4];
    __cpuid(cpuInfo, 1);

    // 检测SSE2
    if (cpuInfo[3] & (1 << 26))
        result |= SSE2_Support;

    // 检测AVX2
    const int hasOSXSAVE = (cpuInfo[2] & (1 << 27)) != 0;
    const int hasAVX = (cpuInfo[2] & (1 << 28)) != 0;

    if (hasOSXSAVE && hasAVX)
    {
        const unsigned long long xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
        if ((xcrFeatureMask & 6) == 6)
        {
            __cpuidex(cpuInfo, 7, 0);
            if (cpuInfo[1] & (1 << 5))
                result |= AVX2_Support;

            // 检测AVX512
            const int avx512f = (cpuInfo[1] & (1 << 16)) != 0;  // AVX512F
            const int avx512bw = (cpuInfo[1] & (1 << 30)) != 0; // AVX512BW
            const int avx512vl = (cpuInfo[1] & (1 << 31)) != 0; // AVX512VL

            // 需要AVX512F、AVX512BW和AVX512VL支持字节操作
            if (avx512f && avx512bw && avx512vl)
                result |= AVX512_Support;
        }
    }
    return result;
}

static uint8_t g_cpuFeatures = InitCPUFeatures();

//pure C 特征搜索
static uintptr_t PatternScan_Region(uintptr_t startAddress, size_t regionSize, const char* signature)
{
    if (!signature || !startAddress || !regionSize)
        return 0;

    size_t patternLen = 0;
    const char* p = signature;
    __nop(); __nop(); __nop();
    while (*p)
    {
        if (*p == ' ') { p++; continue; }
        if (*p == '?')
        {
            patternLen++;
            p++;
            if (*p == '?') p++;
        }
        else
        {
            patternLen++;
            p += 2;
        }
    }

    if (patternLen == 0) return 0;

    // 内存分配优化
    const size_t kStackThreshold = 128;
    int stackPattern[kStackThreshold];
    int* patternBytes = 0;
    if (patternLen <= kStackThreshold)
        patternBytes = stackPattern;
    else
    {
        patternBytes = (int*)malloc(patternLen * sizeof(int));
        if (!patternBytes) return 0;
    }

    // 解析特征码
    size_t parseIndex = 0;
    p = signature;

    while (*p && parseIndex < patternLen)
    {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '?')
        {
            patternBytes[parseIndex++] = -1;
            p++;
            if (*p == '?') p++;
        }
        else
        {
            const uint8_t char1 = g_HexLookup[(uint8_t)*p++];
            while (*p == ' ') p++; if (!*p) break;
            const uint8_t char2 = g_HexLookup[(uint8_t)*p++];
            if (char1 > 0x0F || char2 > 0x0F)
            {
                if (patternLen > kStackThreshold) free(patternBytes);
                return 0;
            }
            patternBytes[parseIndex++] = (char1 << 4) | char2;
        }
    }

    if (parseIndex != patternLen)
    {
        if (patternLen > kStackThreshold) free(patternBytes);
        return 0;
    }

    // 全通配符特例处理
    if (patternLen == 1 && patternBytes[0] == -1)
    {
        if (patternLen > kStackThreshold) free(patternBytes);
        return regionSize ? startAddress : 0;
    }

    uint8_t* scanBytes = (uint8_t*)startAddress;
    const size_t scanEnd = regionSize - patternLen;
    uintptr_t result = 0;
    int firstByte = -1;
    size_t firstIndex = 0;
    for (; firstIndex < patternLen; firstIndex++)
    {
        if (patternBytes[firstIndex] != -1)
        {
            firstByte = patternBytes[firstIndex];
            break;
        }
    }
    if (firstByte == -1)
    {
        if (regionSize >= patternLen)
        {
            result = (uintptr_t)scanBytes;
        }
        if (patternLen > kStackThreshold) free(patternBytes);
        return result;
    }
    __nop(); __nop(); __nop();
    if (g_cpuFeatures & AVX512_Support)
    {
        size_t scanEnd = regionSize - patternLen;
        size_t stepSize = 64;
        __m512i firstByteVec = _mm512_set1_epi8((char)firstByte);
        for (size_t i = 0; i <= scanEnd; i += stepSize)
        {
            if (i + 64 >= regionSize) break;
            __m512i block = _mm512_loadu_si512((const __m512i*)(scanBytes + i));
            __mmask64 mask = _mm512_cmpeq_epi8_mask(block, firstByteVec);
            while (mask != 0)
            {
                DWORD bit;
                _BitScanForward64(&bit, mask);
                mask &= mask - 1;
                size_t pos = i + bit;
                if (pos > scanEnd) continue;
                int match = 1;
                for (size_t j = firstIndex + 1; j < patternLen; j++)
                {
                    if (patternBytes[j] == -1) continue;
                    if (scanBytes[pos + j] != (uint8_t)patternBytes[j])
                    {
                        match = 0;
                        break;
                    }
                }
                if (match)
                {
                    _mm256_zeroupper();
                    if (patternLen > kStackThreshold) free(patternBytes);
                    return (uintptr_t)(scanBytes + pos);
                }
            }
        }
        _mm256_zeroupper();
    }
    else if (g_cpuFeatures & AVX2_Support)
    {
        __m256i firstByteVec = _mm256_set1_epi8((char)firstByte);
        size_t stepSize = 32;
        for (size_t i = 0; i <= scanEnd; i += stepSize)
        {
            if (i + 31 >= regionSize) break;
            __m256i block = _mm256_loadu_si256((const __m256i*)(scanBytes + i));
            __m256i cmp = _mm256_cmpeq_epi8(block, firstByteVec);
            DWORD mask = (DWORD)_mm256_movemask_epi8(cmp);
            while (mask != 0)
            {
                DWORD bit;
                _BitScanForward(&bit, mask);
                mask &= mask - 1;
                size_t pos = i + bit;
                if (pos > scanEnd) continue;
                int match = 1;
                for (size_t j = firstIndex + 1; j < patternLen; j++)
                {
                    if (patternBytes[j] == -1) continue;
                    if (scanBytes[pos + j] != (uint8_t)patternBytes[j])
                    {
                        match = 0;
                        break;
                    }
                }
                if (match)
                {
                    _mm256_zeroupper();
                    if (patternLen > kStackThreshold) free(patternBytes);
                    return (uintptr_t)(scanBytes + pos);
                }
            }
        }
        _mm256_zeroupper();
    }
    else
    {
        // SSE
        __m128i firstByteVec = _mm_set1_epi8((char)firstByte);
        size_t stepSize = 16;
        for (size_t i = 0; i <= scanEnd; i += stepSize)
        {
            if (i + 16 >= regionSize) break;
            __m128i block = _mm_loadu_si128((const __m128i*)(scanBytes + i));
            __m128i cmp = _mm_cmpeq_epi8(block, firstByteVec);
            DWORD mask = (DWORD)_mm_movemask_epi8(cmp);
            while (mask != 0)
            {
                DWORD bit;
                _BitScanForward(&bit, mask);
                mask &= mask - 1;
                size_t pos = i + bit;
                if (pos > scanEnd) continue;
                int match = 1;
                for (size_t j = firstIndex + 1; j < patternLen; j++)
                {
                    if (patternBytes[j] == -1) continue;

                    if (scanBytes[pos + j] != (uint8_t)patternBytes[j])
                    {
                        match = 0;
                        break;
                    }
                }
                if (match)
                {
                    if (patternLen > kStackThreshold) free(patternBytes);
                    return (uintptr_t)(scanBytes + pos);
                }
            }
        }
    }

    // No SIMD
    size_t skipTable[256] = { 0 };
    __nop();
    for (size_t i = 0; i < patternLen; i++)
    {
        if (patternBytes[i] != -1)
        {
            skipTable[(uint8_t)patternBytes[i]] = patternLen - i - 1;
        }
    }
    size_t i = 0;
    while (i <= scanEnd)
    {
        int match = 1;
        size_t j = patternLen - 1;

        while (j != (size_t)-1)
        {
            if (patternBytes[j] == -1)
            {
                j--;
                continue;
            }

            if (scanBytes[i + j] != (uint8_t)patternBytes[j])
            {
                match = 0;
                break;
            }
            j--;
        }
        if (match)
        {
            if (patternLen > kStackThreshold) free(patternBytes);
            return (uintptr_t)(scanBytes + i);
        }
        if (i + patternLen < regionSize)
        {
            size_t skip = skipTable[scanBytes[i + patternLen]];
            i += (skip > 0) ? skip : 1;
        }
        else
        {
            i++;
        }
    }

    if (patternLen > kStackThreshold) free(patternBytes);
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
static FORCEINLINE void DelWstring(wstring** pwstr)
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
    int32_t FpsValue_t = reader.GetInteger(L"Setting", L"FPS", FPS_TARGET);
    if (FpsValue_t > 1000)
        FpsValue_t = 1000;
    FpsValue = FpsValue_t;
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
static uint64_t inject_patch(HANDLE Tar_handle, uintptr_t Tar_ModBase, uintptr_t _ptr_fps, inject_arg* arg)
{
    if (!_ptr_fps)
        return 0;

    BYTE* _sc_buffer = (BYTE*)VirtualAlloc_Internal(0, 0x2000, PAGE_READWRITE);
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
    if (!isGenshin)
    {
        *(uint64_t*)(_sc_buffer + 0x18) = _ptr_fps;
    }

    //genshin_get_gameset
    if (isGenshin && isHook)
    {
        *(uint64_t*)(_sc_buffer + 0x10) = arg->Pfps;
    }

    //shellcode patch
    *(uint64_t*)(_sc_buffer + 0x8) = (uint64_t)(&FpsValue); //source ptr
    

    LPVOID __Tar_proc_buffer = VirtualAllocEx_Internal(Tar_handle, NULL, 0x2000, PAGE_READWRITE);
    if (!__Tar_proc_buffer)
    {
        Show_Error_Msg(L"AllocEx Fail! ");
        return 0;
    }
    uint64_t hook_info_ptr = ((uint64_t)_sc_buffer + 0x1000);
    if (arg->Bootui && (!isGenshin))
    {
        *(uint64_t*)(_sc_buffer + 0x20) = arg->Bootui;//HKSR mob
        *(uint32_t*)(_sc_buffer + 0x28) = 2;
        *(uint64_t*)(_sc_buffer + 0x30) = (uint64_t)__Tar_proc_buffer + 0xFE0;
    }
    if (arg->PfuncList)
    {
        PHook_func_list GI_Func = (PHook_func_list)arg->PfuncList;
        
        if (1)//basefps
        {
            uint64_t Private_buffer = 0;
            for (uint64_t buffer = 0x10000; !Private_buffer && buffer < 0x7FFF8000; buffer += 0x1000)
            {
                Private_buffer = (uint64_t)VirtualAllocEx_Internal(Tar_handle, (void*)(Tar_ModBase - buffer), 0x1000, PAGE_READWRITE);
            }
            if (!Private_buffer)
            {
                Show_Error_Msg(L"AllocEx Fail! 0xFFFF");
                return 0;
            }
            *(uint64_t*)(_sc_buffer + 0x18) = Private_buffer;
            uint64_t alienaddr = _ptr_fps & 0xFFFFFFFFFFFFFFF8;
            Phooked_func_struct Pfps_patch = (Phooked_func_struct)hook_info_ptr;
            Pfps_patch->func_addr = alienaddr;
            if (!ReadProcessMemoryInternal(Tar_handle, (void*)alienaddr, (void*)&Pfps_patch->orgpart, 0x10, 0))
            {
                Show_Error_Msg(L"Failed Readfpspart (GI)");
                goto __exit_block;
            }
            Pfps_patch->hookedpart = Pfps_patch->orgpart;
            uint8_t mask = _ptr_fps & 0x7;
            int32_t immva = (int32_t)(Private_buffer - _ptr_fps) - 4;
            *(int32_t*)(((uint64_t)(&Pfps_patch->hookedpart)) + mask) = immva;
            hook_info_ptr = (uint64_t)hook_info_ptr + sizeof(hooked_func_struct);
        }


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
            *(uint64_t*)(_sc_buffer + 0x20) = ((uint64_t)__Tar_proc_buffer + 0x1000);//Hookinfo_buffer
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

    if (!WriteProcessMemoryInternal(Tar_handle, __Tar_proc_buffer, (void*)_sc_buffer, 0x2000, 0))
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
                if(*(WORD*)buffer == 0x5A4D)
                {
                    CloseHandle_Internal(file_Handle);
                    goto __inject_proc;
                }
                else
                {
                    Show_Error_Msg(L"Bad PE file (loadlib mem)");
                }
            }
            else
            {
                Show_Error_Msg(L"ReadFile Failed! (loadlib mem)");
            }
            CloseHandle_Internal(file_Handle);
			VirtualFree_Internal(buffer, 0, MEM_RELEASE);
            return 0;
        }
		Show_Error_Msg(L"Open LibFile Failed!");
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

        //66 0F 6E 0D ?? ?? ?? ?? 0F 57 C0 0F 5B C9
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "66 0F 6E 0D ?? ?? ?? ?? 0F 57 C0 0F 5B C9");//5.5
        if (address)
        {
            int64_t rip = address;
            rip += 4;
            //rip += *(int32_t*)(rip)+4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7E 0C E8 ?? ?? ?? ?? 66 0F 6E C8 0F 5B C9");//5.4
        if (address)
        {
            int64_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip) + 6;
            //rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7F 0E E8 ?? ?? ?? ?? 66 0F 6E C8"); // ver 3.7 - 5.3 
        if (address)
        {
            int64_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip) + 6;
            //rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8"); // ver old
        if (address)
        {
            int64_t rip = address;
            rip += 4;
            //rip += *(int32_t*)(rip) + 4;
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
    if(1)
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
            injectarg.PfuncList = &GI_Func;
        }
        else
        {
            Show_Error_Msg(L"GetFunc Fail ! GIxv");
            TerminateProcess_Internal(pi->hProcess, 0);
            CloseHandle_Internal(pi->hProcess);
            return 0;
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
            }
            else 
            {
                GI_Func.Pfunc_device_type = 0;
            }
        }
    }

__Continue:
    uintptr_t Patch_buffer = inject_patch(pi->hProcess, Unityplayer_baseAddr, pfps, &injectarg);
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
        wstring str_addr = To_Hexwstring_64bit((uint64_t)mod);
        wprintf_s(L"plugin baseAddr : 0x%s", str_addr.c_str());
        free(barg.Path_Lib);
    }
    
    DelWstring(&ProcessPath);
    DelWstring(&ProcessDir);
    DelWstring(&procname);

    VirtualFree_Internal(_mbase_PE_buffer, 0, MEM_RELEASE);
    VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
    
	//SetThreadAffinityMask(pi->hThread, 0xF);
	SetThreadPriority(pi->hThread, THREAD_PRIORITY_TIME_CRITICAL);
    ResumeThread_Internal(pi->hThread);
    CloseHandle_Internal(pi->hThread);
    
    SetPriorityClass((HANDLE) -1, NORMAL_PRIORITY_CLASS);

    wprintf_s(L"PID: %d\n \nDone! \n \n", pi->dwProcessId);

    if(!AutoExit)
    {
        wprintf_s(L"Use ↑ ↓ ← → key to change fps limted\n使用键盘上的方向键调节帧率限制\n\n\n  UpKey : +20\n  DownKey : -20\n  LeftKey : -2\n  RightKey : +2\n\n");

        // 创建printf线程
        HANDLE hdisplay = CreateRemoteThreadEx_Internal((HANDLE)-1, 0, Thread_display, 0);
        if (!hdisplay)
            Show_Error_Msg(L"Create Thread <Thread_display> Error! ");

        uint32_t fps = FpsValue;
        uint32_t cycle_counter = 0;
        while (1)   // handle key input
        {
            NtSleep(50);
            cycle_counter++;
            if (GetExitCodeProcess_Internal(pi->hProcess) != STILL_ACTIVE)
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
            if (fps > 1000)
            {
                fps = 1000;
            }
        }
        Process_endstate = 1;
        WaitForSingleObject(hdisplay, INFINITE);
        CloseHandle_Internal(hdisplay);
    }
    else
    {
        wprintf_s(L"Exit......");
        NtSleep(2000);
    }
    CloseHandle_Internal(pi->hProcess);
    free(boot_info);
    
    
    return 1;
}





