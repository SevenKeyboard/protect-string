#Requires AutoHotkey v2.0.0+
;==============================================================
; ProtectString — DPAPI-based string encryption/decryption helper (CryptProtectData/CryptUnprotectData)
;
; GitHub: https://github.com/SevenKeyboard/protect-string
; Author: SevenKeyboard Ltd. (2026)
; License: MIT License
;==============================================================

/*
Example Usage:

    msgbox(cipherText := ProtectString.encrypt("Simple example"))
    msgbox(ProtectString.decrypt(cipherText)) ;  "Simple example"

    plainText := "Unicode build: supports beyond BMP, e.g. " . chr(0x1F600) . " (U+1F600)."
    cipherText := ProtectString.encrypt(plainText, "Entropy text", "HexRaw", "LocalMachine", "UiForbidden Audit", "UTF-8", "Description text")
    decryptedText := ProtectString.decrypt(cipherText, "Entropy text", "HexRaw",, "UiForbidden", "UTF-8", &dataDescrText := "")
    msgbox(cipherText . "`n`n" . decryptedText "`n`n" . dataDescrText)
    msgbox(plainText == decryptedText) ;  true

*/

class VersionManager_ProtectString
{
    static _ := this._init()
    static _init()    {
        global
        PROTECTSTRING_VERSION := "1.0.0"
    }
}
class ProtectString
{
    static encrypt(plainText
        ,entropyText := ""
        ,outFmt := "Base64"     ;  Base64 | HexRaw              (one)
        ,scope := "CurrentUser" ;  CurrentUser | LocalMachine   (one)
        ,flags := "UiForbidden" ;  UiForbidden + Audit          (space-separated)
        ,enc := "UTF-16"
        ,dataDescrText := "")
    {
        static CRYPTPROTECT_LOCAL_MACHINE   := 0x4
            ,CRYPTPROTECT_UI_FORBIDDEN      := 0x1
            ,CRYPTPROTECT_AUDIT             := 0x10
            ,CRYPT_STRING_BASE64            := 0x00000001
            ,CRYPT_STRING_HEXRAW            := 0x0000000c
            ,CRYPT_STRING_NOCRLF            := 0x40000000
        ;==============================================================
        ;   CryptProtectData function (dpapi.h)
        ;     https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
        ;==============================================================
        ;  *pDataIn
        cbIn := this._encodeTextToBytes(&pbIn, plainText, enc)
        blobIn := buffer(A_PtrSize * 2, 0)
        numPut("UInt",cbIn, blobIn, 0)
        numPut("Ptr",pbIn.Ptr, blobIn, A_PtrSize)
        ;  *pOptionalEntropy
        if (entropyText !== "")    {
            cbEnt := this._encodeTextToBytes(&pbEnt, entropyText, enc)
            blobEnt := buffer(A_PtrSize * 2, 0)
            numPut("UInt",cbEnt, blobEnt, 0)
            numPut("Ptr",pbEnt.Ptr, blobEnt, A_PtrSize)
        }
        ;  dwFlags
        dwFlags := 0
        if (scope = "LocalMachine")
            dwFlags |= CRYPTPROTECT_LOCAL_MACHINE
        for v in strSplit(flags, [A_Space, A_Tab])    {
            dwFlags |= (v = "UiForbidden" ? CRYPTPROTECT_UI_FORBIDDEN
                : v = "Audit" ? CRYPTPROTECT_AUDIT
                : 0)
        }
        ;  *pDataOut
        blobOut := buffer(A_PtrSize * 2, 0)
        args := ["Crypt32.dll\CryptProtectData"
            ,"Ptr",blobIn.Ptr] ;  *pDataIn
        if (dataDescrText !== "") ;  szDataDescr
            args.push("WStr",dataDescrText)
        else
            args.push("Ptr",0)
        args.push("Ptr",(isSet(blobEnt) ? blobEnt.Ptr : 0) ;  *pOptionalEntropy
            ,"Ptr",0 ;  pvReserved
            ,"Ptr",0 ;  *pPromptStruct
            ,"UInt",dwFlags ;  dwFlags
            ,"Ptr",blobOut.Ptr ;  *pDataOut
            ,"Int")
        bResult := dllCall(args*)
        if (!bResult)
            return ""
        ;==============================================================
        ;   CryptBinaryToStringW function (wincrypt.h)
        ;     https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptbinarytostringw
        ;==============================================================
        cipherText := ""
        cbOut := numGet(blobOut, 0, "UInt")
        pbOut := numGet(blobOut, A_PtrSize, "Ptr")
        dwFlags := 0
        dwFlags |= outFmt = "HexRaw" ? CRYPT_STRING_HEXRAW : CRYPT_STRING_BASE64
        dwFlags |= CRYPT_STRING_NOCRLF
        bResult := dllCall("Crypt32.dll\CryptBinaryToStringW"
            ,"Ptr",pbOut + 0
            ,"UInt",cbOut
            ,"UInt",dwFlags
            ,"Ptr",0 ;  The function will place the required number of characters, including the terminating NULL character, in the value pointed to by pcchString.
            ,"UInt*",&(pcchString := 0)
            ,"Int")
        if (bResult)    {
            pszString := buffer(pcchString * 2)
            bResult := dllCall("Crypt32.dll\CryptBinaryToStringW"
                ,"Ptr",pbOut + 0
                ,"UInt",cbOut
                ,"UInt",dwFlags
                ,"Ptr",pszString.Ptr
                ,"UInt*",&pcchString
                ,"Int")
            cipherText := strGet(pszString, pcchString, "UTF-16")
        }
        if (pbOut)
            dllCall("Kernel32.dll\LocalFree", "Ptr",pbOut + 0, "Ptr")
        return cipherText
    }
    ;----------------------------------------------------------
    static decrypt(cipherText
        ,entropyText := ""
        ,outFmt := "Base64"     ;  Base64 | HexRaw                  (one)
        ,_?
        ,flags := "UiForbidden" ;  UiForbidden + VerifyProtection   (space-separated)
        ,enc := "UTF-16"
        ,&dataDescrText?)
    {
        static CRYPT_STRING_BASE64          := 0x00000001
            ,CRYPT_STRING_HEXRAW            := 0x0000000c
            ,CRYPTPROTECT_UI_FORBIDDEN      := 0x1
            ,CRYPTPROTECT_VERIFY_PROTECTION := 0x40
            
        if (isSet(dataDescrText))
            dataDescrText := "", ppszDataDescr := 0
        ;==============================================================
        ;   CryptStringToBinaryW function (dpapi.h)
        ;     https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptstringtobinaryw
        ;==============================================================
        dwFlags := 0
        dwFlags |= outFmt = "HexRaw" ? CRYPT_STRING_HEXRAW : CRYPT_STRING_BASE64
        bResult := dllCall("Crypt32.dll\CryptStringToBinaryW"
            ,"WStr",cipherText
            ,"UInt",0 ;  cchString
            ,"UInt",dwFlags ;  dwFlags
            ,"Ptr",0 ;  *pbBinary
            ,"UInt*",&(pcbBinary := 0) ;  *pcbBinary
            ,"Ptr",0 ;  *pdwSkip
            ,"Ptr",0 ;  *pdwFlags
            ,"Int")
        if (!bResult)
            return ""
        pbBinary := buffer(pcbBinary, 0)
        bResult := dllCall("Crypt32.dll\CryptStringToBinaryW"
            ,"WStr",cipherText
            ,"UInt",0 ;  cchString
            ,"UInt",dwFlags ;  dwFlags
            ,"Ptr",pbBinary.Ptr ;  *pbBinary
            ,"UInt*",&pcbBinary ;  *pcbBinary
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
        blobIn := buffer(A_PtrSize * 2, 0)
        numPut("UInt",pcbBinary, blobIn, 0)
        numPut("Ptr",pbBinary.Ptr, blobIn, A_PtrSize)
        ;  *pOptionalEntropy
        if (entropyText !== "")    {
            cbEnt := this._encodeTextToBytes(&pbEnt, entropyText, enc)
            blobEnt := buffer(A_PtrSize * 2, 0)
            numPut("UInt",cbEnt, blobEnt, 0)
            numPut("Ptr",pbEnt.Ptr, blobEnt, A_PtrSize)
        }
        ;  dwFlags
        dwFlags := 0
        for v in strSplit(flags, [A_Space, A_Tab])    {
            dwFlags |= (v = "UiForbidden" ? CRYPTPROTECT_UI_FORBIDDEN
                : v = "VerifyProtection" ? CRYPTPROTECT_VERIFY_PROTECTION
                : 0)
        }
        ;  *pDataOut
        blobOut := buffer(A_PtrSize * 2, 0)
        args := ["Ptr",(isSet(blobEnt) ? blobEnt.Ptr : 0) ;  *pOptionalEntropy
            ,"Ptr",0 ;  pvReserved
            ,"Ptr",0 ;  *pPromptStruct
            ,"UInt",dwFlags ;  dwFlags
            ,"Ptr",blobOut.Ptr ;  *pDataOut
            ,"Int"]
        if (isSet(ppszDataDescr))    {
            bResult := dllCall("Crypt32.dll\CryptUnprotectData"
                ,"Ptr",blobIn.Ptr ;  *pDataIn
                ,"Ptr*",&ppszDataDescr ;   *ppszDataDescr
                ,args*)
        }  else  {
            bResult := dllCall("Crypt32.dll\CryptUnprotectData"
                ,"Ptr",blobIn.Ptr ;  *pDataIn
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
        if (ppszDataDescr??0)    {
            dataDescrText := strGet(ppszDataDescr, "UTF-16")
            dllCall("Kernel32.dll\LocalFree", "Ptr",ppszDataDescr + 0, "Ptr")
        }
        return plainText
    }
    ;----------------------------------------------------------
    ;  Note: buf contains the terminating NUL written by StrPut(), but cb excludes it.
    ;  Use cb (not buf.Size) as DATA_BLOB.cbData.
    static _encodeTextToBytes(&buf, text, enc)    {
        cbWithNull := strPut(text, enc)
        buf := buffer(cbWithNull, 0)
        strPut(text, buf, enc)
        cb := cbWithNull - strPut("", enc)
        return cb
    }
}