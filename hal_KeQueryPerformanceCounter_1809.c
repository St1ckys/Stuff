1809

LARGE_INTEGER __stdcall KeQueryPerformanceCounter(PLARGE_INTEGER PerformanceFrequency)
{

  v1 = PerformanceFrequency;
  v2 = HalpPerformanceCounter;
  if ( *(_DWORD *)(HalpPerformanceCounter + 228) == 5 )
  {
    v37 = 10000000i64;
    if ( HalpTimerReferencePage )
    {
      if ( *(_DWORD *)(HalpPerformanceCounter + 224) & 0x10000 )
        v20 = *(_QWORD *)(HalpPerformanceCounter + 72)
            + (unsigned int)(*(_DWORD *)(HalpPerformanceCounter + 80) * HIDWORD(KeGetPcr()[1].LockArray));
      else
        v20 = *(_QWORD *)(HalpPerformanceCounter + 72);
      v21 = (*(__int64 (__fastcall **)(__int64))(HalpPerformanceCounter + 112))(v20);
      v22 = MEMORY[0xFFFFF780000003B8];
      v10.QuadPart = v22 + RtlUnsignedMultiplyHigh(v21, *(_QWORD *)(HalpTimerReferencePage + 8));
    }
    else
    {
      do
      {
        v24 = *(_QWORD *)(v2 + 208);
        do
        {
          v25 = *(_QWORD *)(v2 + 200);
          v26 = HalpTimerGetInternalData(v2);
          v27 = (*(__int64 (__fastcall **)(__int64))(v2 + 112))(v26);
          _InterlockedOr(&v36, 0);
          v28 = *(_QWORD *)(v2 + 200);
        }
        while ( v25 != v28 );
      }
      while ( v24 != *(_QWORD *)(v2 + 208) );
      v29 = *(_DWORD *)(v2 + 220);
      if ( v29 == 64 )
      {
        v35 = v27;
      }
      else
      {
        v30 = 1i64 << v29;
        v31 = (unsigned __int8)(v29 - 1);
        v32 = v25 ^ v27;
        v33 = v30 - 1;
        if ( _bittest64((const __int64 *)&v32, v31) )
        {
          v34 = v25 & v33;
          v35 = v27 | v25 ^ v34;
          if ( v27 < v34 )
            v35 += v30;
          _InterlockedCompareExchange((volatile signed __int64 *)(v2 + 200), v35, v28);
        }
        else
        {
          v35 = v27 | v25 & ~v33;
        }
      }
      v10.QuadPart = HalpTimerScaleCounter(v24 + v35, *(_QWORD *)(v2 + 192), 10000000i64);
    }
  }
  else
  {
    v37 = *(_QWORD *)(HalpPerformanceCounter + 192);
    do
    {
      v3 = *(_QWORD *)(v2 + 208);
      do
      {
        v4 = *(_QWORD *)(v2 + 200);
        v5 = HalpTimerGetInternalData(v2);
        v6 = (*(__int64 (__fastcall **)(__int64))(v2 + 112))(v5);
        _InterlockedOr(&v36, 0);
        v7 = *(_QWORD *)(v2 + 200);
      }
      while ( v4 != v7 );
    }
    while ( v3 != *(_QWORD *)(v2 + 208) );
    v8 = *(_DWORD *)(v2 + 220);
    if ( v8 == 64 )
    {
      v9 = v6;
    }
    else
    {
      v12 = 1i64 << v8;
      v13 = (unsigned __int8)(v8 - 1);
      v14 = v4 ^ v6;
      v15 = v12 - 1;
      if ( _bittest64((const __int64 *)&v14, v13) )
      {
        v23 = v4 & v15;
        v9 = v6 | v4 ^ v23;
        if ( v6 < v23 )
          v9 += v12;
        _InterlockedCompareExchange((volatile signed __int64 *)(v2 + 200), v9, v7);
      }
      else
      {
        v9 = v6 | v4 & ~v15;
      }
    }
    v10.QuadPart = v9 + v3;
  }
  if ( v2 != HalpOriginalPerformanceCounter && HalpOriginalPerformanceCounter )
  {
    v16 = *(_QWORD *)(HalpOriginalPerformanceCounter + 192);
    if ( *(_DWORD *)(HalpOriginalPerformanceCounter + 228) == 5 )
      v16 = 10000000i64;
    if ( v10.QuadPart && v37 && v37 != v16 )
    {
      if ( v37 == 14318180 )
        v17 = v10.QuadPart / 0xDA7A64ui64;
      else
        v17 = v10.QuadPart / v37;
      v18 = v16 * (v10.QuadPart - v37 * v17);
      if ( v37 == 14318180 )
        v19 = v18 / 0xDA7A64;
      else
        v19 = v18 / v37;
      v10.QuadPart = v19 + v16 * v17;
    }
    result = v10;
    if ( v1 )
      v1->QuadPart = v16;
  }
  else
  {
    if ( v1 )
      v1->QuadPart = v37;
    result = v10;
  }
  return result;
}