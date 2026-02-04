#Requires AutoHotkey v1.1.35+
;==============================================================
; ProtectString — DPAPI-based string encryption/decryption helper (CryptProtectData/CryptUnprotectData)
;
; GitHub: https://github.com/SevenKeyboard/protect-string
; Author: SevenKeyboard Ltd. (2026)
; License: MIT License
;==============================================================

/*
Example Usage:

    msgbox % cipherText := ProtectString.encrypt("Simple example")
    msgbox % ProtectString.decrypt(cipherText) ;  "Simple example"

    plainText := A_IsUnicode
        ? "Unicode build: supports beyond BMP, e.g. " . chr(0x1F600) . " (U+1F600)."
        : "ANSI build: mostly BMP/locale-limited; example ± (U+00B1)."
    cipherText := ProtectString.encrypt(plainText, "Entropy text", "HexRaw", "LocalMachine", "UiForbidden Audit", "UTF-8", "Description text")
    decryptedText := ProtectString.decrypt(cipherText, "Entropy text", "HexRaw",, "UiForbidden", "UTF-8", dataDescrText)
    msgbox % cipherText . "`n`n" . decryptedText "`n`n" . dataDescrText
    msgbox % (plainText == decryptedText) ;  true

*/

class VersionManager_ProtectString
{
    static _ := VersionManager_ProtectString._init()
    _init()    {
        global
        PROTECTSTRING_VERSION := "1.0.0"
    }
}
class ProtectString
{
    encrypt(plainText
        ,entropyText := ""
        ,outFmt := "Base64"     ;  Base64 | HexRaw              (one)
        ,scope := "CurrentUser" ;  CurrentUser | LocalMachine   (one)
        ,flags := "UiForbidden" ;  UiForbidden + Audit          (space-separated)
        ,enc := "UNSET_D45AD9E3"
        ,dataDescrText := "")
    {
        static CRYPTPROTECT_LOCAL_MACHINE   := 0x4
            ,CRYPTPROTECT_UI_FORBIDDEN      := 0x1
            ,CRYPTPROTECT_AUDIT             := 0x10
            ,CRYPT_STRING_BASE64            := 0x00000001
            ,CRYPT_STRING_HEXRAW            := 0x0000000c
            ,CRYPT_STRING_NOCRLF            := 0x40000000

        if (!A_IsUnicode)    {
            enc := "cp0"
        }  else  {
            if (enc == "UNSET_D45AD9E3")
                enc := "UTF-16"
        }
        ;==============================================================
        ;   CryptProtectData function (dpapi.h)
        ;     https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
        ;==============================================================
        ;  *pDataIn
        cbIn := this._encodeTextToBytes(pbIn, plainText, enc)
        varSetCapacity(blobIn, A_PtrSize * 2, 0)
        numPut(cbIn, blobIn, 0, "UInt")
        numPut(&pbIn, blobIn, A_PtrSize, "Ptr")
        ;  *pOptionalEntropy
        if (entropyText !== "")    {
            cbEnt := this._encodeTextToBytes(pbEnt, entropyText, enc)
            varSetCapacity(blobEnt, A_PtrSize * 2, 0)
            numPut(cbEnt, blobEnt, 0, "UInt")
            numPut(&pbEnt, blobEnt, A_PtrSize, "Ptr")
        }
        ;  dwFlags
        dwFlags := 0
        if (scope = "LocalMachine")
            dwFlags |= CRYPTPROTECT_LOCAL_MACHINE
        for _,v in strSplit(flags, [A_Space, A_Tab])    {
            dwFlags |= (v = "UiForbidden" ? CRYPTPROTECT_UI_FORBIDDEN
                : v = "Audit" ? CRYPTPROTECT_AUDIT
                : 0)
        }
        ;  *pDataOut
        varSetCapacity(blobOut, A_PtrSize * 2, 0)
        args := ["Crypt32.dll\CryptProtectData"
            ,"Ptr",&blobIn] ;  *pDataIn
        if (dataDescrText !== "") ;  szDataDescr
            args.push(A_IsUnicode ? "WStr" : "AStr",dataDescrText)
        else
            args.push("Ptr",0)
        args.push("Ptr",(isSet(blobEnt) ? &blobEnt : 0) ;  *pOptionalEntropy
            ,"Ptr",0 ;  pvReserved
            ,"Ptr",0 ;  *pPromptStruct
            ,"UInt",dwFlags ;  dwFlags
            ,"Ptr",&blobOut ;  *pDataOut
            ,"Int")
        bResult := dllCall(args*)
        if (!bResult)
            return ""
        ;==============================================================
        ;   CryptBinaryToStringA function (wincrypt.h)
        ;     https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptbinarytostringa
        ;   CryptBinaryToStringW function (wincrypt.h)
        ;     https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptbinarytostringw
        ;==============================================================
        cipherText := ""
        cbOut := numGet(blobOut, 0, "UInt")
        pbOut := numGet(blobOut, A_PtrSize, "Ptr")
        dwFlags := 0
        dwFlags |= outFmt = "HexRaw" ? CRYPT_STRING_HEXRAW : CRYPT_STRING_BASE64
        dwFlags |= CRYPT_STRING_NOCRLF
        bResult := dllCall("Crypt32.dll\CryptBinaryToString" . (A_IsUnicode ? "W" : "A")
            ,"Ptr",pbOut + 0
            ,"UInt",cbOut
            ,"UInt",dwFlags
            ,"Ptr",0 ;  The function will place the required number of characters, including the terminating NULL character, in the value pointed to by pcchString.
            ,"UInt*",pcchString
            ,"Int")
        if (bResult)    {
            varSetCapacity(pszString, pcchString * (A_IsUnicode ? 2 : 1))
            bResult := dllCall("Crypt32.dll\CryptBinaryToString" . (A_IsUnicode ? "W" : "A")
                ,"Ptr",pbOut + 0
                ,"UInt",cbOut
                ,"UInt",dwFlags
                ,"Ptr",&pszString
                ,"UInt*",pcchString
                ,"Int")
            cipherText := strGet(&pszString, pcchString, A_IsUnicode ? "UTF-16" : "cp0")
        }
        if (pbOut)
            dllCall("Kernel32.dll\LocalFree", "Ptr",pbOut + 0, "Ptr")
        return cipherText
    }
    ;----------------------------------------------------------
    decrypt(cipherText
        ,entropyText := ""
        ,outFmt := "Base64"     ;  Base64 | HexRaw                   (one)
        ,_ := ""
        ,flags := "UiForbidden" ;  UiForbidden + VerifyProtection    (space-separated)
        ,enc := "UNSET_D45AD9E3"
        ,byRef dataDescrText := "UNSET_080D9478")
    {
        static CRYPT_STRING_BASE64          := 0x00000001
            ,CRYPT_STRING_HEXRAW            := 0x0000000c
            ,CRYPTPROTECT_UI_FORBIDDEN      := 0x1
            ,CRYPTPROTECT_VERIFY_PROTECTION := 0x40
            
        if (!A_IsUnicode)    {
            enc := "cp0"
        }  else  {
            if (enc == "UNSET_D45AD9E3")
                enc := "UTF-16"
        }
        if (dataDescrText !== "UNSET_080D9478")
            ppszDataDescr := 0
        dataDescrText := ""
        ;==============================================================
        ;   CryptStringToBinaryA function (wincrypt.h)
        ;     https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptstringtobinarya
        ;   CryptStringToBinaryW function (dpapi.h)
        ;     https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptstringtobinaryw
        ;==============================================================
        dwFlags := 0
        dwFlags |= outFmt = "HexRaw" ? CRYPT_STRING_HEXRAW : CRYPT_STRING_BASE64
        bResult := dllCall("Crypt32.dll\CryptStringToBinary" . (A_IsUnicode ? "W" : "A")
            ,A_IsUnicode ? "WStr" : "AStr",cipherText
            ,"UInt",0 ;  cchString
            ,"UInt",dwFlags ;  dwFlags
            ,"Ptr",0 ;  *pbBinary
            ,"UInt*",pcbBinary := 0 ;  *pcbBinary
            ,"Ptr",0 ;  *pdwSkip
            ,"Ptr",0 ;  *pdwFlags
            ,"Int")
        if (!bResult)
            return ""
        varSetCapacity(pbBinary, pcbBinary, 0)
        bResult := dllCall("Crypt32.dll\CryptStringToBinary" . (A_IsUnicode ? "W" : "A")
            ,A_IsUnicode ? "WStr" : "AStr",cipherText
            ,"UInt",0 ;  cchString
            ,"UInt",dwFlags ;  dwFlags
            ,"Ptr",&pbBinary ;  *pbBinary
            ,"UInt*",pcbBinary ;  *pcbBinary
            ,"Ptr",0 ;  *pdwSkip
            ,"Ptr",0 ;  *pdwFlags
            ,"Int")
        if (!bResult)
            return ""
        ;==============================================================
        ;   CryptUnprotectData function (dpapi.h)
        ;     https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata
        ;==============================================================
        ;  *pDataIn
        varSetCapacity(blobIn, A_PtrSize * 2, 0)
        numPut(pcbBinary, blobIn, 0, "UInt")
        numPut(&pbBinary, blobIn, A_PtrSize, "Ptr")
        ;  *pOptionalEntropy
        if (entropyText !== "")    {
            cbEnt := this._encodeTextToBytes(pbEnt, entropyText, enc)
            varSetCapacity(blobEnt, A_PtrSize * 2, 0)
            numPut(cbEnt, blobEnt, 0, "UInt")
            numPut(&pbEnt, blobEnt, A_PtrSize, "Ptr")
        }
        ;  dwFlags
        dwFlags := 0
        for _,v in strSplit(flags, [A_Space, A_Tab])    {
            dwFlags |= (v = "UiForbidden" ? CRYPTPROTECT_UI_FORBIDDEN
                : v = "VerifyProtection" ? CRYPTPROTECT_VERIFY_PROTECTION
                : 0)
        }
        ;  *pDataOut
        varSetCapacity(blobOut, A_PtrSize * 2, 0)
        args := ["Ptr",(isSet(blobEnt) ? &blobEnt : 0) ;  *pOptionalEntropy
            ,"Ptr",0 ;  pvReserved
            ,"Ptr",0 ;  *pPromptStruct
            ,"UInt",dwFlags ;  dwFlags
            ,"Ptr",&blobOut ;  *pDataOut
            ,"Int"]
        if (isSet(ppszDataDescr))    {
            bResult := dllCall("Crypt32.dll\CryptUnprotectData"
                ,"Ptr",&blobIn ;  *pDataIn
                ,"Ptr*",ppszDataDescr ;   *ppszDataDescr
                ,args*)
        }  else  {
            bResult := dllCall("Crypt32.dll\CryptUnprotectData"
                ,"Ptr",&blobIn ;  *pDataIn
                ,"Ptr",0 ;   *ppszDataDescr
                ,args*)
        }
        if (!bResult)
            return ""
        cbOut := numGet(blobOut, 0, "UInt")
        pbOut := numGet(blobOut, A_PtrSize, "Ptr")
        plainText := strGet(pbOut + 0, cbOut // ((enc = "UTF-16" || enc = "cp1200") ? 2 : 1), enc)
        if (pbOut)
            dllCall("Kernel32.dll\LocalFree", "Ptr",pbOut + 0, "Ptr")
        if (isSet(ppszDataDescr) && ppszDataDescr)    {
            dataDescrText := strGet(ppszDataDescr, A_IsUnicode ? "UTF-16" : "cp0")
            dllCall("Kernel32.dll\LocalFree", "Ptr",ppszDataDescr + 0, "Ptr")
        }
        return plainText
    }
    ;----------------------------------------------------------
    ;  VarSetCapacity(buf, -1) trims the variable to the string length (excluding the terminating NUL).
    _encodeTextToBytes(byRef buf, text, enc)    {
        cbWithNull := strPut(text, enc) * ((enc = "UTF-16" || enc = "cp1200") ? 2 : 1)
        varSetCapacity(buf, cbWithNull, 0)
        strPut(text, &buf, enc)
        cb := varSetCapacity(buf, -1)
        return cb
    }
}