---
title: Silly way to execute shellcode - VectorOverloading2
date: 2026-04-24 13:46:40
tags:
---

# Introduction 

Vector Overloading is a local PE injection technique first observed in [Checkpoint SW blog - GachiLoader](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/) . It abuses the Windows PE Loader process itself to map a "malicious" payload into memory, hiding behind a legitimate DLL load operation.

The technique was covered in the blog post designed for a **legitimate PE file** , when I read about this technique I'm curious what will happens when you try to replace it and make it load shellcode instead. So in this blog post, I will walk you through what's needed to be done to get shellcode executed, it might be silly and not very "evasive", but it's fun


## Summary of VectorOverloading technique

The **VectorOverloading** technique is used for a **legitimate PE fie** , which means valid **PE headers, and all other stuffs** ( You can read the original blog post of CheckpointSW for more details, they did a great job at covering it ). 

VectorOverloading technique includes 2 phases:

**Phase 1: Prepare the section** 

- `CreateFileW ( "wmp.dll" )` : Open the "donor" DLL from Disk
- `NtCreateSection ( SEC_IMAGE )` : Create section object backed by **wmp.dll**
- `NtMapViewOfSection` ( PAGE RW) : Map it to process 
- Wipe out the donor's DLL content, write our PE
- Handling PE relocations, memory protections, ...

**Phase 2: Hijack the DLL load via VEH**

The techniques work with two interception points:

- Register VEH and set HWBP ( Hardware breakpoint on `NtOpenSection` )
- Trigger `LoadLibraryW("amsi.dll")` ( it can be any dll, just to kick off the PE loader process. the GachiLoader use `amsi.dll` because it's lower detection rate )
- `NtOpenSection` : HWBP number 1, replace section handle with ours ( the Windows PE Loader think it opened `amsi.dll` 's section, but we gave it our `wmp.dll` -backed section )
- `NtMapViewOfSection` : HWBP number 2, replace base address and ViewSize with our pre-mapped Views
- Windows PE Loader processes our mapped image, walks import table, resvole imports, applies section protections, resolve relocations, ... everything is perfect and look like a legitimate `amsi.dll` loaded into process


By creating a `SEC_IMAGE` section from a legitimate, signed Microsoft DLL, your payload's memory now living in a back memory with legitimate signatures. 

That's sound good, can we extend this method to shellcode/sRDI for extra flexibility, since a lot of PEs can be turned into sRDI, and we can easily add our evasive tradecraft on top by using [Tradecraft Garden](https://tradecraftgarden.org/)


## Changing payload to shellcode instead of PE file

When your payload is a **shellcode/sRDI** with no PE headers, everything changed because **VectorOverloading** heavily rely on Windows PE Loader to load the PE payload. But the shellcode doesn't need PE Loader's help, it resolves its own imports, relocations, ... 

So what went wrong when we try to give it a shellcode payload, `beacon_x64.bin` for example 

After `NtMapViewOfSection` is intercepted, the loader expect the mapped memory is a PE image with valid PE charasteristics, headers, ... but instead it finds no PE haeder ( no `MZ` signature )

At this point, the Windows PE Loader will **fails** . What does Windows PE Loader do after this process fails  to load ?. 

It cleans up by calling `NtUnmapViewOfSection` which will end up win your shellcode payload is unmmaped from memory before it get a chance to executed. 


### Attempting to make VectorOverloading2
The loader calls `NtUnmapViewOfSection` on the base address to undo the mapping, so your shellcode vanishes.  What if you intercept `NtUnmapViewOfSection` to prevent it from doing so ?.

We can do this by:
- Placing a third HWBP on `NtUnmapViewOfSection` to skip the syscall entirely
- Set `RAX = 0 ` ( STATUS_SUCCESS) , clean up all HWBPs of the 2 inteception points.

Windows PE Loader thinks unmap process is succeed, but our shellcode still lives in memory.

**Copied from VectorOverloading.cpp source code** (https://github.com/CheckPointSW/VectoredOverloading/blob/main/main.cpp#L68 )


```cpp
LONG InjectHandler ( PEXCEPTION_POINTERS ExceptionInfo ) {
    // First 2 interception points 
    //....

    // Intercept NtUnmapViewOfSection - VectorOverloading2
    case LdrState::StateClose: {
      if ( ( PVOID ) ctx->Rdx != gBaseAddress )
        return EXCEPTION_CONTINUE_EXECUTION;

      printf ( "[*] gLdrState == LdrState::StateClose (intercepted "
        "NtUnmapViewOfSection)\r\n" );

      // Skip syscall
      ctx->Rax = 0;
      BYTE* rip = ( BYTE* ) ctx->Rip;
      while ( *rip != 0xC3 )
        ++rip;
      ctx->Rip = ( ULONG_PTR ) (rip);

      // Clear all HWBP
      ctx->Dr0 = 0LL;
      ctx->Dr1 = 0LL;
      ctx->Dr2 = 0LL;
      ctx->Dr3 = 0LL;
      ctx->Dr6 = 0LL;
      ctx->Dr7 = 0LL;
      ctx->EFlags |= 0x10000u;

      NtContinue ( ctx, FALSE );
      return EXCEPTION_CONTINUE_EXECUTION;
    }

}

```

### Profit

We have successfully adapt this technique to load Cobalt beacon. 

Also one of the other benefit besides you can extend this and apply any evasive tradecraft with sRDI, is that you can safely remove the PE mapping ( copy sections, fix relocations, process imports, ... ) because you don't need it anymore.


![Exec shellcode by adapting VectorOverLoading](/images/vector_overload2.jpg)

I don't think this technique provides any addition of stealth/evasion in any means, it's just fun to do and to research how far our capabilities can reach. 

It did successfully help us to get back a beacon in security product X, the image below is not for name and shame, it's just an interesting observation. When the background scan of product X kicks in, it detects and kill our process immediately


If you have any ideas to push this further, please do let me know 

![Get cobalt beacon and perform spawn inject](/images/vector_overload2_2.jpg)



## Reference:
- Full source code can be found [here](https://github.com/mr-r3bot/VectorOverloading2)
- https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/
- https://tradecraftgarden.org/