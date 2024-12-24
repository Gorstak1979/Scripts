SetTitleMatchMode 2
Loop {
    WinGetTitle, Title, A  ; Corrected this line with a comma
    If InStr(Title, "Discord") {
        Send ^+m
    }
    Sleep 1000
}

