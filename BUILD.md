## Pinned upstream

- **7-Zip source** lives under [`vendor/7zip`](vendor/7zip) (clone of [ip7z/7zip](https://github.com/ip7z/7zip).
- **Recorded commit:** `0766b733fe3e06dd2a7f9a3cfbf2108ac73abd17` (tag `26.03`)

## Local patches to vendored 7-Zip

- [`vendor/7zip/CPP/7zip/Archive/DllExports.cpp`](vendor/7zip/CPP/7zip/Archive/DllExports.cpp): `g_hInstance` is non-`static` (matches `CPP/Windows/DLL.cpp`); `SetLargePageMode` calls `z7_LargePage_Set(0,0,0)`.
- [`vendor/7zip/CPP/7zip/Archive/HandlerCont.{h,cpp}`](vendor/7zip/CPP/7zip/Archive/HandlerCont.cpp): restore virtual `CreateItemInStream` so IFS/ARC/MAR can decode on extract (upstream 26.03 only copies raw limited streams); `Extract` is non-final so IFS can pipeline encode+write.
- [`vendor/7zip/CPP/7zip/Archive/ExtIsArcStub.cpp`](vendor/7zip/CPP/7zip/Archive/ExtIsArcStub.cpp): stub for `NExt::IsArc_Ext` because `ExtHandler.cpp` is not linked.
- Custom archive handlers under `vendor/7zip/CPP/7zip/Archive/` (`Bar`, `Qar`, `Mar`, `Arc`, `Ifs`, `TwoDx`, `S3p`, `Arcfile`, `D2`) are plugin-owned, not upstream.
- [`vendor/fpng`](vendor/fpng): [fpng](https://github.com/richgel999/fpng) for fast IFS texture PNG encode (replaces lodepng on that path).

## Build (Windows, Visual Studio 2022)

Use the CMake bundled with VS if `cmake` is not on `PATH`:

```text
"C:\Program Files\Microsoft Visual Studio\2022\<Edition>\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
```

From the repo root:

```bat
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Output: `build/Release/ktar.dll`
