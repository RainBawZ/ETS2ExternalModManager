Function Convert-ProfileFolderName {
    [CmdletBinding()]
    [OutputType([String])]
    
    Param (
        [Parameter(Mandatory)]
        [String]$FolderName
    )

    If ( $FolderName.StartsWith('CLOUD:') ) { $FolderName = $FolderName.Substring(6) }

    [Collections.Generic.List[Char]]$Chars = [Collections.Generic.List[Char]]::New()
    For ( $i = 0; $i -lt $FolderName.Length; $i += 2 ) { $Chars.Add( [Char][Byte]"0x$( $FolderName.Substring( $i, 2 ) )" ) }

    [String]$Converted = $Chars -Join ''
    
    Return $Converted
}
