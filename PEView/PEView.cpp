// PEView.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <fstream>
#include <Windows.h>
#include <iomanip>
#include <string>
using namespace std ;
//#define FilePath1  "C:\\Windows\\System32\\notepad.exe"
//#define FilePath2  "C:\\Users\\admin\\source\\repos\\DLLTest\\Debug\\DLLTest.exe"
//#define FilePath4  "C:\\Windows\\System32\\calc.exe"
//#define FilePath3  "C:\\Users\\admin\\Desktop\\MirInject\\Debug\\MirInject.dll"
//#define FilePath   "C:\\Windows\\WinSxS\\wow64_microsoft-windows-user32_31bf3856ad364e35_10.0.18362.959_none_2d5e5441335b7c69\\user32.dll"
PDWORD g_BaseAddress = NULL;
int    g_FileSize;

void  zzDosHead();//dos头
void  zzOptionalHeader();//可选头
void  zzNTHeader();//nt 头
int   zzRvaToRaw(int RVA);
void  zzImportDirectoryTable();//导入表
void  zzImportAddressTable();//导入地址表
DWORD FileSize( CHAR* Filepath);
BOOL zzGetfile( CHAR *Filepath);
void  zzExportDirectory();//导出表
void  zzBaeRelocationTable();//重定位表
int main()
{
    string str;
    cout << "输入PE文件路径:";
    getline(cin, str);
    char Filepath[256];//最大路径长度256个字节
    strcpy_s(Filepath,str.c_str());
    // cout <<Filepath;
    //打开文件失败
    if (zzGetfile(Filepath) == false)
    {
        return 0;
    };
    zzDosHead();
    zzNTHeader();
    zzOptionalHeader();
    zzImportDirectoryTable();
    zzImportAddressTable();
    zzExportDirectory();
    zzBaeRelocationTable();
}

BOOL zzGetfile( CHAR * Filepath)
{
    ifstream l_FileIfstream;
    int size = FileSize(Filepath);
    g_FileSize = size;
    if (size == 0) 
    {
        cout << "打开文件失败";
        return false;
    }
    PBYTE l_byte = (PBYTE)malloc(size);
    l_FileIfstream.open(Filepath, ios::binary);
    l_FileIfstream.seekg(0);
    l_FileIfstream.read((char*)l_byte, size);
    l_FileIfstream.close();
    g_BaseAddress = (DWORD *)l_byte;
    return true;
}

DWORD FileSize( CHAR* Filepath)
{
    //TCHAR szFileName[MAX_PATH] = TEXT(Filepath);
    //字符串转化 char* to  LPCWSTR
    WCHAR wszClassName[256];
    MultiByteToWideChar(CP_ACP, 0, Filepath, strlen(Filepath) + 1, wszClassName,
        sizeof(wszClassName) / sizeof(wszClassName[0]));

    HANDLE hFile = CreateFile(wszClassName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        if (0 == GetLastError())
        {
            printf("file not exist");
        }
        return 0;
    }
    DWORD dwFileSize = 0;
    dwFileSize = GetFileSize(hFile, NULL);
    CloseHandle(hFile);
    return dwFileSize;
}

//dos 头
void  zzDosHead()
{
    PIMAGE_DOS_HEADER l_pFileDos;//DOS头结构体指针   
    l_pFileDos = (PIMAGE_DOS_HEADER)(g_BaseAddress);
    cout << "---------------------- IMAGE_DOS_HEADER-----------------" << endl;
    cout << "               Signature:" <<hex << l_pFileDos->e_magic<<endl;
    cout << "offset to New Exe Header:"<<hex << l_pFileDos->e_lfanew<< endl;


}

//nt 头
void zzNTHeader() 
{
    PIMAGE_DOS_HEADER l_pFileDos;//DOS头结构体指针  
    PIMAGE_FILE_HEADER l_pNTHeader;//NT 头结构体指针
    l_pFileDos = (PIMAGE_DOS_HEADER)(g_BaseAddress);
    BYTE  l_NTNTheaderAdd = l_pFileDos->e_lfanew;//获取NT的基地址

    l_pNTHeader = (PIMAGE_FILE_HEADER)((BYTE *)g_BaseAddress+ l_NTNTheaderAdd+4);
    cout << "----------------------IMAGE_FILE_HEADER-----------------" << endl;
    cout <<"             Machine:"<< hex << l_pNTHeader->Machine<<endl;
    cout <<"    NumberOfSections:"<< hex << l_pNTHeader->NumberOfSections << endl;
    cout <<"SizeOfOptionalHeader:"<< hex << l_pNTHeader->SizeOfOptionalHeader << endl;
    cout <<"     Characteristics:"<< hex << l_pNTHeader->Characteristics << endl;
}




//可选头
void  zzOptionalHeader()
{
  
    PIMAGE_OPTIONAL_HEADER l_pOptionalHeader;//可选头结构体指针
    PIMAGE_DATA_DIRECTORY  l_PDateDirectory;//date结构体指针

    PIMAGE_DOS_HEADER l_pFileDos;//DOS头结构体指针  
    l_pFileDos = (PIMAGE_DOS_HEADER)(g_BaseAddress);
    BYTE  l_NTNTheaderAdd = l_pFileDos->e_lfanew;//获取NT的基地址

    l_pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((PBYTE)g_BaseAddress + l_NTNTheaderAdd+0x18);
    cout <<"--------------------IMAGE_OPTIONAL_HEADER---------------"<<endl;
    cout <<"              Magic:"<< hex << l_pOptionalHeader->Magic<<endl;
    cout <<"AddressOfEntryPoint:"<< hex << l_pOptionalHeader->AddressOfEntryPoint<<endl;
    cout <<"          ImageBase:"<< hex << l_pOptionalHeader->ImageBase<<endl;
    cout <<"   SectionAlignment:"<< hex << l_pOptionalHeader->SectionAlignment << endl;
    cout <<"        SizeOfImage:"<< hex << l_pOptionalHeader->SizeOfImage << endl;
    cout <<"      SizeOfHeaders:"<< hex << l_pOptionalHeader->SizeOfHeaders << endl;
    cout <<"          Subsystem:"<< hex << l_pOptionalHeader->Subsystem << endl;
    cout <<"NumberOfRvaAndSizes:"<< hex << l_pOptionalHeader->NumberOfRvaAndSizes << endl;
}


typedef struct mySections
{
    DWORD RAW_begin;//文件开始位置
    DWORD RVA_begin;//内存开始位置
} *pMySections;


// RVA 到RAW
int zzRvaToRaw(int RVA) 
{
    PIMAGE_SECTION_HEADER l_pSectionHeader;//节区头指针
    int l_NumberOfSections = NULL;
    PIMAGE_DOS_HEADER l_pFileDos;//DOS头结构体指针  
    PIMAGE_FILE_HEADER l_pNTHeader;//NT 头结构体指针
    BYTE  l_NTNTheaderAdd;
    pMySections l_pSection;

    l_pFileDos = (PIMAGE_DOS_HEADER)(g_BaseAddress);
    l_NTNTheaderAdd = l_pFileDos->e_lfanew;//获取NT的基地址

    l_pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)g_BaseAddress + l_NTNTheaderAdd + 0xf8);
    l_pNTHeader = (PIMAGE_FILE_HEADER)((BYTE*)g_BaseAddress + l_NTNTheaderAdd + 4);
    l_NumberOfSections = l_pNTHeader->NumberOfSections;
     // cout << "  " << l_NumberOfSections<<endl;
    l_pSection = (pMySections)malloc(sizeof(mySections) * l_NumberOfSections);

    for (int i = 0; i < l_NumberOfSections; i++)
    {
        l_pSection[i].RAW_begin = l_pSectionHeader[i].PointerToRawData;
        l_pSection[i].RVA_begin = l_pSectionHeader[i].VirtualAddress;
        //cout << l_pSection[i].RAW_begin<<endl;
        //cout << l_pSection[i].RVA_begin << endl;
    }

    for (int i = 0; i < l_NumberOfSections; i++)
    {
        if (RVA < l_pSection[i].RVA_begin) 
        {
            int Result =RVA - l_pSection[i - 1].RVA_begin + l_pSection[i - 1].RAW_begin;           
            free((void*)l_pSection);           
            return Result;
        }
    }
    int Result= RVA - l_pSection[l_NumberOfSections - 1].RVA_begin + l_pSection[l_NumberOfSections - 1].RAW_begin;
    free((void*)l_pSection);
    return  Result;
}


void zzImportDirectoryTable() 
{
    PIMAGE_OPTIONAL_HEADER l_pOptionalHeader;//可选头结构体指针
    PIMAGE_DATA_DIRECTORY  l_PDateDirectory;//date结构体指针
    BYTE  l_NTNTheaderAdd;
    PIMAGE_DOS_HEADER l_pFileDos;//DOS头结构体指针
    PIMAGE_IMPORT_DESCRIPTOR l_PImportDescriptor;
    int l_importTableRva;
    l_pFileDos = (PIMAGE_DOS_HEADER)(g_BaseAddress);
    l_NTNTheaderAdd = l_pFileDos->e_lfanew;//获取NT的基地址

    l_pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((PBYTE)g_BaseAddress + l_NTNTheaderAdd + 0x18);

    l_PDateDirectory = l_pOptionalHeader->DataDirectory;
    l_importTableRva = l_PDateDirectory[1].VirtualAddress;//import directory table的RvA

    int index = zzRvaToRaw(l_importTableRva);//获取import directory table的RAW
  

   //从RAW 的地址读取g_importTableSize大小的数据

   l_PImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)g_BaseAddress + index);
   //cout << "--------------------IMAGE_OPTIONAL_HEADER---------------" << endl;
   cout << "-------------------IMAGE_IMPORT_DESCRIPTOR--------------" << endl;
   while (l_PImportDescriptor->Name != 0x0)
   {
       //获取dll的名称
       int NameIndex =zzRvaToRaw(l_PImportDescriptor->Name);
       PCHAR l_pName;//默认名称长度不超过50
       l_pName = (CHAR*)((PBYTE)g_BaseAddress + NameIndex);
       //cout << NameIndex<<endl;

       cout <<"OriginalFirstThunk:"<< hex << l_PImportDescriptor->OriginalFirstThunk<< endl;
       cout <<"              Name:"<< hex << l_PImportDescriptor->Name<<"  "<< l_pName <<endl;
       cout <<"        FirstThunk:"<< hex << l_PImportDescriptor->FirstThunk << endl;
       cout << endl;
       l_PImportDescriptor++;
   }
 
}

// 地址导入表
void zzImportAddressTable()
{
    PIMAGE_OPTIONAL_HEADER l_pOptionalHeader;//可选头结构体指针
    PIMAGE_DATA_DIRECTORY  l_PDateDirectory;//date结构体指针
    BYTE  l_NTNTheaderAdd;
    PIMAGE_DOS_HEADER l_pFileDos;//DOS头结构体指针
    PIMAGE_IMPORT_DESCRIPTOR l_PImportDescriptor;
    int l_importTableRva;
    l_pFileDos = (PIMAGE_DOS_HEADER)(g_BaseAddress);
    l_NTNTheaderAdd = l_pFileDos->e_lfanew;//获取NT的基地址

    l_pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((PBYTE)g_BaseAddress + l_NTNTheaderAdd + 0x18);

    l_PDateDirectory = l_pOptionalHeader->DataDirectory;
    l_importTableRva = l_PDateDirectory[1].VirtualAddress;//import directory table的RvA

    int index = zzRvaToRaw(l_importTableRva);//获取import directory table的RAW


   //从RAW 的地址读取g_importTableSize大小的数据

    l_PImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)g_BaseAddress + index);
    cout << "-------------------IMPORT_ADDRESS_TABLE--------------" << endl;
    cout << setfill('0');
    while (l_PImportDescriptor->Name != 0x0)
    {
        int RVA = l_PImportDescriptor->FirstThunk;//获取地址导入表的RVA
        int RAW = zzRvaToRaw(RVA);//将RVA转化为RAW
        //cout <<"RAW"<<RAW<<endl;
        //将地址导入表的数据装入l_importAddressTableByte
        BYTE *l_importAddressTableByte=(BYTE *)((PBYTE)g_BaseAddress + RAW);

        DWORD* l_pDword = (DWORD*)l_importAddressTableByte;
        while (*l_pDword != 0x0) 
        {
            
            //cout << hex<<*l_pDword<<"  " << hex <<zzRvaToRaw(*l_pDword) << endl;
            if (zzRvaToRaw(*l_pDword) > g_FileSize) 
            {
                RVA = RVA + 4;
                l_pDword++;
                continue;
            }
            PBYTE l_pName=((PBYTE)g_BaseAddress+zzRvaToRaw(*l_pDword)+2);// 名称加两字节偏移？           
            cout<<setw(8)<< hex<< RVA <<" "<< setw(8) << hex << *l_pDword<<" "<<l_pName<<endl;
            RVA = RVA + 4;
            l_pDword++;
        }
        cout << endl;
        l_PImportDescriptor++;

    }
}

// 导出表信息

void zzExportDirectory() 
{
    PIMAGE_OPTIONAL_HEADER l_pOptionalHeader;//可选头结构体指针
    PIMAGE_EXPORT_DIRECTORY l_pExportDirectory;//导出表结构体指针
    BYTE  l_NTNTheaderAdd;
    PIMAGE_DOS_HEADER l_pFileDos;//DOS头结构体指针
    PIMAGE_IMPORT_DESCRIPTOR l_PImportDescriptor;
    int l_ExportDirectory;

    l_pFileDos = (PIMAGE_DOS_HEADER)(g_BaseAddress);
    l_NTNTheaderAdd = l_pFileDos->e_lfanew;//获取NT的基地址

    l_pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((PBYTE)g_BaseAddress + l_NTNTheaderAdd + 0x18);

    l_ExportDirectory = l_pOptionalHeader->DataDirectory[0].VirtualAddress;//IMAGE_EXPORT_DIRECTOARY的RvA
    
     //判断是否存在导出表
    if (l_ExportDirectory == 0x0) 
    {
        cout << "没有导出表" << endl;
        return;
    }

    int index = zzRvaToRaw(l_ExportDirectory);//获取IMAGE_EXPORT_DIRECTOARY的 RAW

    //获取IMAGE_EXPORT_DIRECTOARY的地址
    l_pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)g_BaseAddress + index);

    cout << "------------------IMAGE_EXPORT_DIRECTORY--------------" << endl;
    cout << " NumberOfFunctions:" << hex << l_pExportDirectory->NumberOfFunctions << endl;
    cout << "     NumberOfNames:" << hex << l_pExportDirectory->NumberOfNames << endl;
    cout << "AddressOfFunctions:" << hex << l_pExportDirectory->AddressOfFunctions  << endl;
    cout << "    AddressOfNames:" << hex << l_pExportDirectory->AddressOfNames  << endl;
    int l_nameRva = l_pExportDirectory->AddressOfNames;//名称数组RVA
    int *l_pNameAddress = (int *)((PBYTE)g_BaseAddress + zzRvaToRaw(l_nameRva));//函数名所在RVA

    int l_funRva = l_pExportDirectory->AddressOfFunctions;//导出函数地址数组RVA
    int* l_pfunAddress = (int*)((PBYTE)g_BaseAddress + zzRvaToRaw(l_funRva));
    
    int l_addressRva = l_pExportDirectory->AddressOfFunctions;
    // 遍历输出函数RVA和函数名称
    cout << setfill('0');

    for (int i = 0; i < l_pExportDirectory->NumberOfNames; i++) 
    {  
        //cout << hex << *l_pNameAddress << endl;
        PBYTE l_pName = ((PBYTE)g_BaseAddress + zzRvaToRaw(*l_pNameAddress));
        cout<<setw(8)<<hex<< *l_pfunAddress<<" "<<l_pName<<endl;
        l_pNameAddress++;
        l_pfunAddress++;
    }
}

//重定位表
void zzBaeRelocationTable()
{
    PIMAGE_OPTIONAL_HEADER l_pOptionalHeader;//可选头结构体指针
    PIMAGE_EXPORT_DIRECTORY l_pExportDirectory;//导出表结构体指针
    BYTE  l_NTNTheaderAdd;
    PIMAGE_DOS_HEADER l_pFileDos;//DOS头结构体指针
    PIMAGE_IMPORT_DESCRIPTOR l_PImportDescriptor;
    PIMAGE_BASE_RELOCATION  l_pBaeRelocation;//重定位表结构体指针
    int l_BaeRelocation;
    int l_BaeRelocationSize;

    l_pFileDos = (PIMAGE_DOS_HEADER)(g_BaseAddress);
    l_NTNTheaderAdd = l_pFileDos->e_lfanew;//获取NT的基地址

    l_pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((PBYTE)g_BaseAddress + l_NTNTheaderAdd + 0x18);

    l_BaeRelocation = l_pOptionalHeader->DataDirectory[5].VirtualAddress;//IMAGE_EXPORT_DIRECTOARY的RvA
    l_BaeRelocationSize = l_pOptionalHeader->DataDirectory[5].Size;
    l_pBaeRelocation = (PIMAGE_BASE_RELOCATION)((PBYTE)g_BaseAddress + zzRvaToRaw(l_BaeRelocation));
    cout << setfill('0');
    cout << "------------------IMAGE_BASE_RELOCATION--------------" << endl;
    int l_sum = 0;
    do {

        cout <<"VirtualAddress:"<<"  "<< setw(8) << hex << l_pBaeRelocation->VirtualAddress << endl;
        l_BaeRelocation = l_BaeRelocation + 4;
        cout <<"   SizeOfBlock:"  <<"  "<< setw(8) << hex << l_pBaeRelocation->SizeOfBlock << endl;
        l_BaeRelocation = l_BaeRelocation + 4;

       // cout << hex << &l_pBaeRelocation<<endl;
        short int* l_pValue = (short int*)((PBYTE)l_pBaeRelocation + 8);
        
        while (l_pValue< (short int *)((PBYTE)l_pBaeRelocation + (l_pBaeRelocation->SizeOfBlock)))
        {
            cout << setw(8) << hex << l_BaeRelocation << "  " << setw(4) << hex << *l_pValue << endl;
            l_BaeRelocation = l_BaeRelocation + 2;
            l_pValue++;
        }
        l_sum = l_sum + l_pBaeRelocation->SizeOfBlock;
        l_pBaeRelocation =(PIMAGE_BASE_RELOCATION)((PBYTE)l_pBaeRelocation + (l_pBaeRelocation->SizeOfBlock));
       
        //cout <<sum<<endl;
        cout << endl;
        //cout << l_pBaeRelocation;
    } while (l_sum<l_BaeRelocationSize);


}








// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
