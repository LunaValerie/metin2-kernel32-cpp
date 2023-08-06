#define eKernel32	/*kernel32*/XorStr<0x41,9,0x1533420A>("\x2A\x27\x31\x2A\x20\x2A\x74\x7A"+0x1533420A).s
typedef UINT(__stdcall *threadFunc_t)(void*);
HANDLE CreateStealthThread(threadFunc_t pThreadFunc, void *pArgument) // by Ende! //
{
   BYTE *pK32     = (BYTE*)GetModuleHandle(eKernel32);
   BYTE *pPopRet  = nullptr;
   DWORD oldProt;

   auto rva2va = [&](DWORD dwVA)
   { 
      return (void*)((uintptr_t)pK32 + dwVA);
   };

   void *pWriteTarget = nullptr;

   auto pMz          = (IMAGE_DOS_HEADER*)pK32;
   auto pNt          = (IMAGE_NT_HEADERS32*)rva2va(pMz->e_lfanew);
   auto pCurSection  = (IMAGE_SECTION_HEADER*)((uintptr_t)pNt + sizeof(IMAGE_NT_HEADERS32));

   for(int i=0; i<pNt->FileHeader.NumberOfSections; ++i)
   {
      if(memcmp(".text", pCurSection->Name, 5) == 0)
      {
         pWriteTarget = (void*)((uintptr_t)rva2va(pCurSection->VirtualAddress) + pCurSection->Misc.VirtualSize - 6);
         break;
      }
      ++pCurSection;
   }

   if(!pWriteTarget) return NULL;

   uint8_t shellcode[] = "\x68\x00\x00\x00\x00\xC2";
   *(threadFunc_t*)(shellcode + 1) = pThreadFunc;
   
   VirtualProtect(pWriteTarget, 6, PAGE_EXECUTE_READWRITE, &oldProt);
   memcpy(pWriteTarget, shellcode, 6);
   VirtualProtect(pWriteTarget, 6, oldProt, &oldProt);

   return CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)pWriteTarget, pArgument, NULL, nullptr);
}