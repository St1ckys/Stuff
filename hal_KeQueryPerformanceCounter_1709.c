1709

LARGE_INTEGER __stdcall KeQueryPerformanceCounter(PLARGE_INTEGER PerformanceFrequency)
{

  v1 = PerformanceFrequency;
  v2 = HalpPerformanceCounter;
  if ( *(_DWORD *)(HalpPerformanceCounter + 228) == 5 )
  {
    v24 = *(_QWORD *)(HalpPerformanceCounter + 192) >> 10;
    v3 = MEMORY[0xFFFFF780000003B8];
    if ( *(_DWORD *)(HalpPerformanceCounter + 224) & 0x10000 )
      v4 = *(_QWORD *)(HalpPerformanceCounter + 72)
         + (unsigned int)(*(_DWORD *)(HalpPerformanceCounter + 80) * HIDWORD(KeGetPcr()[1].LockArray));
    else
      v4 = *(_QWORD *)(HalpPerformanceCounter + 72);
    v5 = *(_QWORD *)(HalpPerformanceCounter + 112);
    if ( (__int64 (__fastcall *)())v5 == HalpTscQueryCounterOrdered )
    {
      __asm { rdtscp }
      v6 = ((_QWORD)HalpTscQueryCounterOrdered << 32) | v5;
    }
    else
    {
      v6 = ((__int64 (__fastcall *)(__int64))v5)(v4);
    }
    v7.QuadPart = (unsigned __int64)(v6 + v3) >> 10;
    goto LABEL_7;
  }
  v24 = *(_QWORD *)(HalpPerformanceCounter + 192);
  do
  {
    v9 = *(_QWORD *)(v2 + 208);
    do
    {
      v10 = *(_QWORD *)(v2 + 200);
      v11 = HalpTimerGetInternalData(v2);
      v12 = *(__int64 (__fastcall **)())(v2 + 112);
      if ( v12 == HalpHpetQueryCounter )
        v13 = *(unsigned int *)(HalpHpetBaseAddress + 240);
      else
        v13 = ((__int64 (__fastcall *)(__int64))v12)(v11);
      _InterlockedOr(&v23, 0);
      v14 = *(_QWORD *)(v2 + 200);
    }
    while ( v10 != v14 );
  }
  while ( v9 != *(_QWORD *)(v2 + 208) );
  v15 = *(_DWORD *)(v2 + 220);
  v16 = v13;
  if ( v15 == 64 )
  {
LABEL_21:
    v7.QuadPart = v16 + v9;
    goto LABEL_7;
  }
  v17 = v10 ^ v13;
  if ( !_bittest64((const __int64 *)&v17, (unsigned __int8)(v15 - 1)) )
  {
    v16 = v13 | v10 & ~((1i64 << v15) - 1);
    goto LABEL_21;
  }
  v22 = (v13 | v10 ^ v10 & ((1i64 << v15) - 1)) + (1i64 << v15);
  if ( v13 >= (v10 & (unsigned __int64)((1i64 << v15) - 1)) )
    v22 = v13 | v10 ^ v10 & ((1i64 << v15) - 1);
  _InterlockedCompareExchange((volatile signed __int64 *)(v2 + 200), v22, v14);
  v7.QuadPart = v22 + v9;
LABEL_7:
  if ( v2 != HalpOriginalPerformanceCounter && HalpOriginalPerformanceCounter )
  {
    v18 = *(_QWORD *)(HalpOriginalPerformanceCounter + 192);
    if ( *(_DWORD *)(HalpOriginalPerformanceCounter + 228) == 5 )
      v18 >>= 10;
    if ( v7.QuadPart && v24 && v24 != v18 )
    {
      if ( v24 == 14318180 )
        v19 = v7.QuadPart / 0xDA7A64ui64;
      else
        v19 = v7.QuadPart / v24;
      v20 = v18 * (v7.QuadPart - v24 * v19);
      if ( v24 == 14318180 )
        v21 = v20 / 0xDA7A64;
      else
        v21 = v20 / v24;
      v7.QuadPart = v21 + v18 * v19;
    }
    result = v7;
    if ( v1 )
      v1->QuadPart = v18;
  }
  else
  {
    if ( v1 )
      v1->QuadPart = v24;
    result = v7;
  }
  return result;
}