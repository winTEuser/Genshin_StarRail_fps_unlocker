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
#include <stddef.h>
#include <stdint.h>
#include <locale.h>
#include <intrin.h>
#include <emmintrin.h>
#include <immintrin.h>

#include <Windows.h>
#include <TlHelp32.h>

#include "NTSYSAPI.h"
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
 0x846D185E8776075E, 0x820A231BE1B2F81F, 0x820AF39C6AF3666D, 0x0742EBAC36782E6D,
 0x820AE8277E5E5AB6, 0x820AAC3871402E76, 0x0F4B62B339801D33, 0x0708E9FBE97F1C63,
 0x72C86CB3E124912B, 0x0608E99BA6AFD0CC, 0x4ECEEAD3669C95ED, 0x9E31EB83EBDD5B66,
 0x75F760CBE5A99BE3, 0x8A089F37256ED3FC, 0x71C71C7FDA5FC517, 0x9938D5FC92894E5F,
 0x61B19D6C92894D33, 0x153AD11CB6E5C67B, 0x5952F5403DADF65F, 0x7D3E7E0C7D8992D4,
 0xFE7606280902DAEC, 0x32BAC57756439228, 0xFE7609BB9A8F5EE4, 0x32BAC57756439228,
 0x65EC9057721F1B60, 0x6500111F255E4F21, 0xEE4CFB946D5E4F23, 0xEF217F9BA4DB07EA,
 0x8BA57049219307EA, 0x8BA52A04999307EB, 0x8BA47C8196923E8D, 0xDBAC4000AAD3B58D,
 0xDBAD0685A5D3B5C8, 0xDBAD8E8D0158F1C8, 0xDA980A82E5DDB4C8, 0xDA1402066E99B4C8,
 0x25272332E3D3B4C8, 0x25272242C7573D8C, 0xA46FDDBD38A882CD, 0x8F75AABD38577D37,
 0x8BF6A5A9566C6D59, 0x88BEB9EFDD6C6D58, 0x88BE02067578E699, 0x5A3B471E23F3A299,
 0xD377471E236F2696, 0x5833471E2217023A, 0xB1300A3E4C9C46E5, 0x387C76464D76C5A4,
 0x5E1A76464CF6E110, 0x7F1D764B4C72FE1F, 0xAED8FD07566E735C, 0xAD91FD9A1AE532A7,
 0xCBF79BFCDBCE7E6E, 0xEAF09BF1DB4A6161, 0xFB4694F9DFFC6E20, 0xFF32547DDEB5E368,
 0xF941964732C12152, 0xFF3781ACCD92AC16, 0xB1BC8E47CCC92152, 0x78BFC74696446476,
 0xA284821FAAF36B32, 0xA304A6AB21BFCD4C, 0xA274822FAAFBCD4C, 0xA30CA68321B7CD4C,
 0xE47FB2FD1AF3CD4C, 0x6F3E73FE53EF8BC7, 0x584AA17BDBFB0008, 0x584A71F9D42F3B49,
 0x579A4AD9D0A27849, 0x95110ED9D0A2BCCA, 0x9A50D6529963BF87, 0x0A36C72659E7BF31,
 0x0B7571297D93910D, 0x388404E9F9506E45, 0x38864CCD65DB2685, 0x38864ECDA15A6E85,
 0xFBDB1092FD1B31C4, 0x7A93C0B9B4C8BA8C, 0x324BB3B9B4C99A76, 0xA25DC76B31815DFD,
 0xD694436B3D3752BC, 0x166B0B4B397BDAB0, 0x5AE643A04BB9E1F8, 0xB2C647DCC3F9C1DC,
 0xFA06CC90C3F9C180, 0xD907B710608D0105, 0x6F089A6561DE8C4D, 0xBD8C98A6E2968E1E,
 0xE601D076A01B906A, 0x24BFDF65D712AC6B, 0x5B32CCD3D8AD90E6, 0xB9471E57A0911D0E,
 0x510BD6DCE9467E46, 0xAEF4B63516B98392, 0xF81D77365F7B086D, 0x34D1BBFA9384F792,
 0xF81D44056A46D26D, 0x34D188C9A68A1EA1, 0x6058C0D182CE97ED, 0xEB10F83D018687C9,
 0xAFD7B0C2FE7F1CCC, 0x589EB0C2FE7F54E8, 0x118DC4C2FE70AB28, 0x90C43B3D0E704BA9,
 0xD44D773D0E604B69, 0xF009B0EDF9281B4D, 0xBC84FCEDF9281F65, 0x8C84DCC9BDEF4F41,
 0xD80994098EAA4F41, 0xC0596B0905E20765, 0x4311AB3A029BC7E0, 0x0B35EFB14A58FF24,
 0xC7F92372729C7C6C, 0x0B35EFBEBE50B0A0, 0xE7B6A7A69A1439EC, 0x18495E869F9F71A4,
 0xE849BC07D746FAE8, 0xE8498C2393810517, 0xA071A8771AC90517, 0xECA15F3F2AED499A,
 0xC8F5D2774AC90D17, 0xECB1593F5A42412F, 0x24F456779AC7095F, 0xEF7F1F57BE8B8017,
 0xA7BB9C1F86D97F56, 0x6B7750D34A15B395, 0x87F418C36E413ADD, 0x780BE0036BCA72E5,
 0x780BE0234F8EB5AD, 0x5C4F6D6F9F79FDAD, 0x144F6DEF9FC0BC8D, 0xEB4FE6A7D7E4E800,
 0x278CDE6354ACC850, 0xEB4012AF9860049C, 0x278CDE6354ACC850, 0xEB4012AF9860049C,
 0x9C4FEA2CD1A18FD4, 0xBD48EA2151BE80C3, 0x4FC3A2D8DAF6D694, 0x8C9CFC7C293E5DDD,
 0x836FE60B09C6DE94, 0x813B89044B35D4FB, 0x8E797A0D343A270B, 0x42B5B6CEC43B7374,
 0x0E7F8D86C637FE3A, 0x8C7044BD8FFEB835, 0x8E1F4B4E8FFEB8F9, 0xC7EF4922E0F1FA0A,
 0x41E04922E071028B, 0x0829C26EE071021B, 0x41392BEDA97EE398, 0x803A663C82372AB3,
 0xF63A663C02CFABFA, 0xD73D663182D0A489, 0x855269C288BFAB7A, 0x8AA14998E7B0586A,
 0xECA8369781803A05, 0xB5D739F191D1450A, 0xBA240990EEDE232A, 0xEA76669F1D9E6945,
 0x857995FF47F166B6, 0xE339DC80489716D4, 0xBA46D3E618C669DB, 0x3B0EA38767C90FBB,
 0xF98FEB8767C98F7A, 0x79676ACE67C98FFA, 0x79E7924F2EC98FFA, 0x76AF1F02BABA8FFA,
 0x09A05DF14A5B0CB3, 0xE0A022FEB9AB0DDF, 0x2C6CEE324654F323, 0xE0A022FE8A983FEF,
 0xE3E9F3D5C28A2FE0, 0x60A103C4869A2028, 0xA157132C05D330C1, 0x221FDAA749CB44CE,
 0x260FD56F59C4B42F, 0xE784996648CBF53E, 0x26CD51ED050BDE72, 0xCDCC78E2747FD99B,
 0xABAA1E841219BF8D, 0x8AAD1E89129DA082, 0x85A4378602DC898D, 0x94E82789F2CDCD9D,
 0x94E827091B4C857D, 0xF4A10E066B0DAC72, 0xB8B101567A49BC7D, 0xF9980E9F8500FC6C,
 0xBD8801DFCC29F33C, 0xB2A81093DC26C32D, 0xBD8859BAD3168204, 0xAC8449B5C307C614,
 0x2FCD59F4EA086861, 0xE7461435C2071781, 0x81200E41C6EED6C8, 0xA0270E4CC66AC9C7,
 0xAF37E7CF8E6BD8C8, 0x5F422E30C77ADCD8, 0x4E4D2D44C89A5F91, 0x8281E187C98B5081,
 0x4E4D2D4B05479C4D, 0x8281E187C98B5081, 0x4E4D2D4B05479C4D, 0x8281E187C98B5081,
 0x0FC8B6D19C57DBCD, 0x0FC9863D1D1F63A6, 0x47AC76B6541EE8A6, 0xCCE46EF7DF56E02D,
 0xB46F26F6541EC065, 0xB3BAA2F9AB9B8845, 0xCB39EAF920D38845, 0xCB39ED3EA4DC8865,
 0xDB4A6473AC87012C, 0xAE98E1A927713269, 0x0E02703FAFC97A2F, 0x36263CB2E742E0B7,
 0x7E248E8AC30669FF, 0xEEB20207598FC947, 0x4B5A42231D0681D6, 0x737E16AE550681D1,
 0xBCF55EE67172089D, 0x7C7016198E8BDB75, 0x34689D515E74DE01, 0xA8F80EC2E0FF6FB9,
 0x21B036E6AC722727, 0xAA087EE51E4A0363, 0xE296F46E93DCAAF9, 0x50054C26D3F8EE70,
 0xD94D7EA05E687CEA, 0xD94D79F0B62058AE, 0xADC53DC89274D5E6, 0x54BBD507193C9AC2,
 0x1CADA1C79C74653D, 0xF0F82C8F8401BEB8, 0xF0F82BD76CC935F0, 0x30FA93DC18C8CD73,
 0xB8BF1A946723CD73, 0x2225972DEC92753B, 0x2345B39165DEE392, 0x6B7D97D5EC96E392,
 0xE6ED2F9DD4B2AF1F, 0x59A4B52F472C4999, 0xCB3E07BCD9A6C214, 0x877623F850EEC1A6,
 0x8770F41010CABD2F, 0x0F34CC344447F52F, 0x0ADC03BF0C0CD15B, 0x1CA8C33A44F32EA2,
 0x49258B033128ABEA, 0x492354EBF9A3E31A, 0x4A9B789FF85B601A, 0x2ABFC414B45B60DA,
 0x7A9B589FFC5B60DB, 0x22BFEC14B05B60DA, 0x238F2895F85B60DB, 0xAAC7EBC8A60460DB,
 0x306A60791E4CF09E, 0x1416E93588E56B00, 0x995ED111CC6C2340, 0x1FD341A98454070C,
 0x57D0F3233D7694FB, 0x57D6BCCB7552D072, 0xDF9284EF21DF9872, 0xA27A4B646994BC06,
 0xB40E8BE1216B43FE, 0xE183C3FA54B0C6B6, 0xE18594129C3B8E4E, 0xE53D9A669DC30D4E,
 0x1AC2651574C30D8E, 0x9173DD5DD48684C6, 0x1C3B41C75F160969, 0x241F054E172E2D25,
 0xA989ACC5AF662E97, 0x8DCD258D3CF8A41C, 0x005DB7178E40EC5C, 0x4879F39EC6EF05DA,
 0x1CF4BB9EC6EADE32, 0x54BA9FEA4EAEE616, 0x1C4560124746299D, 0x699EE55A5132E918,
 0xA115ADA604BFA103, 0xA0ED2EA604BA42EB, 0x49ED2E6602024C9F, 0xE1A8A72EFDFDB260,
 0x7032289E764C0A28, 0x38520CD2FB048787, 0x801A0E609B20C30E, 0x22A514EC17BA5F9E,
 0x27D3FC8433FED6D6, 0x63B3D8D0BEB6D6D6, 0x8B7C5398D392A25E, 0xFFBCD6D02C6D55FA,
 0x72F4CDA5F7E81DEC, 0x778A256D7CA019B9, 0xCF84516C842319B9, 0x307ACB858423D9B1,
 0x81C2833DC1AA914E, 0xC97805A352302AC5, 0x7B60402A1A286748, 0xF0EADCB09D902F4A,
 0x18CA9939D501BFDC, 0x009F1471D501BAC8, 0xE8509F39FD743384, 0xE7901A71028BC4C0,
 0xA2195271028F1C44, 0xA1E4D77ED90A549C, 0xE1699B6C9181549C, 0x606964936E60D58E,
 0x2C7E1093AD65DA77, 0xD35B18D3266D9AFA, 0xD3981DDC1B6D6505, 0x96131DDC1FF2E00A,
 0xF0755DF85B7BA8E6, 0xD1725DF55BFFB7E9, 0xDA3A7D179AB786E6, 0xDDC59C96523CCE24,
 0xDE8C98779374CE24, 0xDE736788B67545EC, 0xB8AA128875704AD1, 0x99AD128575F455DE,
 0x92E53267B4BC64D1, 0x951AD1E66C372C13, 0x9653D505AD7F2C13, 0x69AC2AE72C6CA7CB,
 0x1CACE9E2239626CB, 0x3488AD25F2616E1C, 0x10C4246DF2616E18, 0x9D8C1449BEEC2220,
 0xD5A8508EF6D4066C, 0x9D6863CB092BF993, 0x9D68E3CB390FBD54, 0xE9E1AF931D5B301C,
 0xD9E18FB7599C6838, 0x5CE18FB248746838, 0x141E704F2CFC67F8, 0x14A6FD0774D82373,
 0x9FEAC58E3CD82363, 0xBFEA050F75800727, 0x3EA26D7AFCC40727, 0x72A26D5AFCF4234B,
 0xB3EA5C559CD067C2, 0x63E114866B984720, 0xB3D25CF64FDCCA68, 0xFB18D7BEAF994720,
 0x70541E35E3B9AEE1, 0x3C86E974298AE230, 0x0FC320C326CB2A03, 0x1F2BE18BE74063D2,
 0x5BEC58C2267322B4, 0x54A8A73DD98C2690, 0x941EA8FCEAC4FE26, 0x90FD69B5CA047D6E,
 0xDE256AF8CEE4BC26, 0x2943A84FC1FCB8AB, 0xE870E0479975F17B, 0xEDFDA8178935363A,
 0xF97AE4AFC1E58035, 0xF9F3AD1689B5D911, 0xD1B36B578A775A59, 0x01B0225368B6129A,
 0x49B4C392A2001DDB, 0x899F82A2E38DD7D8, 0xC18BC22BA2953F5B, 0xCCC3E2CB63DDFDD0,
 0xD4836B8247D93A98, 0xD9CBAAA10E1BB1D0, 0xF98B23E80A3FF517, 0x068B074C87774D5F,
 0xBEC3370D0E3FB2A0, 0xBEC3352D2A9B3FE8, 0x398B8D6512DAB6A0, 0xB0C3062D869292A4,
 0x3B8B0E453EDAD2E5, 0x73CA870DBD92D2A5, 0xFE824386F5C26AED, 0x3D9287D6B4054E49,
 0xC4123F9EB68C0685, 0x4D5A1BB231C4F97A, 0x45B698FA898CF138, 0x55F411B2AD887870,
 0xAB14351620C0C038, 0x135C2D54A9883FC7, 0x1B1CA01C81010F38, 0x0B131854A1438670,
 0x825B3C10B04CB630, 0xC24B333808049E72, 0xF209BA704C159132, 0xA249AA7F7431297A,
 0x1A01923DFD793875, 0x1561D22DF2311C31, 0x5D256B64B2739579, 0xD06CA7A8538C448E,
 0x009BEEF819050885, 0x87D3B6DC5D14B0CD, 0x3F9BFE9ED45CB08D, 0xF357325218907C41,
 0x4B06881A00D3F508, 0xC24F3152FF2C0AF7, 0x89C67C5ABCA547E4, 0xCA4F317AEF2C0EF4,
 0x89C6784AA4A543DC, 0xCA4F350AF72C0AE4, 0x89C67C5ABCA547AC, 0xDD4B343AEF2C0EF4,
 0x50075C7966616ED0, 0x117717F02B514A94, 0x52FE5EF02B516A2D, 0xD9FC1F79C714E155,
 0x5AB497344E5C1110, 0xA6F11C360FD531D1, 0x86309F7E9F98B899, 0x0F78673B149AF910,
 0x4EF147FA97D2515D, 0x6AB5CEB26B97DA5F, 0x273C86DA2E1A921F, 0xAE74BEFE6297DABF,
 0xAE74BC868AB7FEFB, 0x518B464D02B83E7E, 0x14060E3D26FC1671, 0x34063E19623B5E19,
 0x3B361A5DEF775E19, 0x7A6E3E09623F5908, 0x37463109623F5BB1, 0x2649092D2EB21331,
 0x29692D69A7FA037E, 0x26496A78A86A4656, 0x29792569A7CA0B7E, 0x26396278A87A4E56,
 0x29692D69A7BA037E, 0xC1096A78A86A4656, 0x4906AAFDA86A445A, 0x6D4221B55795BE05,
 0x5E44A8FD8762F65D, 0x1B8857027D2F1F9D, 0x1B8C7F2639E8DFAE, 0x57EC5B6AB4A4DFAE,
 0x73B8D6228480AB27, 0x53B8B606C047E317, 0x63B896228480E317, 0x3647696A09C9E317,
 0xC9BD7BEF0609669F, 0x44F14BCB4A822E60, 0x44F149720BE20A24, 0xC9B979565F6F4224,
 0xC83031565F6CAAA5, 0x80CFCEA9A0AD6DED, 0xA48BE6A690892966, 0xEC8BE6A5788C6116,
 0xE38BF7AA48A8259F, 0xEC9BBFBB472868B7, 0xE3BBFFAA48B82D9F, 0xEC8BB7BB471860B7,
 0xE3CBF7AA48A8259F, 0xEC9BBFBB476868B7, 0xA4FBFFAA48B82D9F, 0x84DFBB2300D06812,
 0x145AB4E385783DED, 0x247EF068CD87C214, 0xE44DF6E18557355C, 0x24934E1E7AAE4BB5,
 0x9C6CB1E70E479518, 0xACA830AFCE47942D, 0x606B6DF19147942C, 0xACA7A13D5D8B58E0,
 0x6E11AE2A29749A60, 0x6E51B125E8701728, 0xEEA9F1A8A060E060, 0xA66B47A754151FA2,
 0x65AA4B2A1CD40B55, 0xA96687E6D018C799, 0x2C2E466D9CCA4CD5, 0xA72E466D254E431C,
 0xAC5BFEBCAE027E1D, 0xAC5A46BE27063F96, 0x154232571BC53F96, 0x618309311BC51A69,
 0x5AE50931A38DA367, 0xE2E509312A08ACA6, 0xE2E519882A08ACA7, 0xC3E21985AA17A3A7,
 0x09C9554D215A722C, 0x7D7184C66D63F36D, 0xACFAC8C451E2B12B, 0x2FEABCC65D6FFF93,
 0x59CA44459D90EF52, 0xDA09BBBA626F5785, 0x5148BABEE9295344, 0xB899723529021794,
 0xF94859352902162C, 0xBD407C31DF0A6FAD, 0x36837EB89AC82BA2, 0xC08B0739DB22FA72,
 0x0108D77CD42ADF76, 0x0108D6C41501938A, 0xC21A5F850502D28A, 0x0ED69349C9C112B9,
 0x1E871805C1B0EDF1, 0x1B0A5041C1F966B9, 0xDF811811C1F966D5, 0x207EE191E55DEB9D,
 0x289262D9C1716CD5, 0x0C36EF91E575E59D, 0x24BFDF6E1A8A1B7D, 0x14FFCF6112CA9635,
 0x54EFC049368E873A, 0x44E0F86D729F887A, 0x4BA8DC296390D83A, 0x138C98386CF0982A,
 0xC27BD07C6CB01F62, 0x0EB71CB0A07CFE9D, 0xC27BD07C6CB03251, 0x0EB71CB0A07CFE9D,
 0xF148ECB084D873D5, 0x0EB71CB0A07CFE9D, 0x0EB73D9084D873D5, 0x85FFA9D8A0DCF49D,
 0x06B7A9982B94FCF5, 0xCA7B6554E757EC31, 0x06B7A9982B9B20FD, 0xCA7B6554E757EC31,
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
    if (!signature)
        return 0;

    size_t patternLen = 0;
    const char* p = signature;

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

    const size_t kStackThreshold = 128;
    int stackPattern[kStackThreshold];
    int* patternBytes = (patternLen <= kStackThreshold) ? stackPattern :
        (int*)malloc(patternLen * sizeof(int));
    if (!patternBytes && patternLen > kStackThreshold) return 0;

    size_t parseIndex = 0;
    p = signature;
    //
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
    __nop();__nop();__nop();
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
                if (pos > scanEnd)
                    continue;

                int match = 1;

                for (size_t j = firstIndex; j < patternLen; j++)
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
                for (size_t j = firstIndex; j < patternLen; j++)
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
                for (size_t j = firstIndex; j < patternLen; j++)
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





