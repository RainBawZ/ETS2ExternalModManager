#STR_version=3.7.0;
#STR_profile=***GAME_PROFILE_PLACEHOLDER***;
#NUM_start=0;
#NUM_validate=0;
#NUM_purge=0;
#NUM_noconfig=0;
#STR_loadorder=Default;
#NUM_editor=0;
#STR_server=http://your.domain/repo;
#STR_offlinedata={};
#NUM_logretention=0;
#NUM_experimental=182;
#STR_targetgame=ETS2;
#NUM_autobackup=1;
#NUM_retainlogs=1;
#STR_atsprofile=***GAME_PROFILE_PLACEHOLDER***;
#NUM_drawingspeed=500;
#PERSIST_END

#***GAME_PROFILE_PLACEHOLDER***

<#

    COPYRIGHT © 2026 RainBawZ

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software
    and associated documentation files (the "Software"), to deal in the Software without restriction,
    including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#>

# TODO: Implement ANSI text formatting ### (Write-HostX, Write-Host, Write-HostFancy) > Write-ANSI
# TODO: Add cross-platform (Windows/Linux) compatibility ### Will be separate script
# TODO: Add core mod management (dll/injector mods) ### Install-CoreMod
# TODO: Implement Test-GameConfiguration
# TODO: Fix self-restart
# TODO: Improve GUI/Form functionality and layout

Param (
    [Parameter(Position = 0)][String]$InputParam,
    [ValidateSet('ETS2', 'ATS')][String]$_Game
)

If (!$PSBoundParameters.ContainsKey('InputParam')) {
    [Diagnostics.Stopwatch]$T__LoadTimer = [Diagnostics.Stopwatch]::StartNew()
    [DateTime]$T__LoadTime               = [DateTime]::Now
    [String]$Global:SessionId            = (Get-FileHash -InputStream ([IO.MemoryStream]::New([Byte[]][Char[]]$T__LoadTime.ToString())) -Algorithm MD5).Hash.Substring(0, 8)
    [String]$T__Game                     = $_Game
    [String]$T__Tab                      = ' ' * 4
    [String]$T__Message                  = '. . .  L O A D I N G  . . .'
    [String]$T__SessionStr               = " Session ID: $Global:SessionId"
    $T__Message                          = ' ' * [Math]::Max(0, [Math]::Floor(($Host.UI.RawUI.WindowSize.Width - $T__Message.Length) / 2) - $T__SessionStr.Length) + $T__Message

    If ($T__Game -NotIn 'ETS2', 'ATS') {
        [Collections.Generic.List[String]]$T__Data = @()

        If ($PSVersionTable.PSVersion.Major -lt 7) {
            [IO.StreamReader]$T__Reader = [IO.StreamReader]::New($PSCommandPath)
            Try {While ($T__Reader.Peek() -ne -1) {
                [String]$T__Line = $T__Reader.ReadLine()
                If ($T__Line -eq '#PERSIST_END') {Break}
                Else                             {$T__Data.Add($T__Line)}
            }}
            Catch   {[Collections.Generic.List[String]]$T__Data = @('#STR_targetgame=XXXX;')}
            Finally {[Void]$T__Reader.Dispose(); Remove-Variable T__Reader, T__Line -EA 0}
        }
        Else {
            [Threading.CancellationTokenSource]$T__tSrc            = [Threading.CancellationTokenSource]::New()
            [Collections.Generic.IAsyncEnumerable[String]]$T__Enm  = [IO.File]::ReadLinesAsync($PSCommandPath, $T__tSrc.Token)
            [Collections.Generic.IAsyncEnumerator[String]]$T__Feed = $T__Enm.GetAsyncEnumerator($T__tSrc.Token)

            Try {While ($T__Feed.MoveNextAsync().AsTask().Result -And !$T__tSrc.IsCancellationRequested) {
                If ($T__Feed.Current -eq '#PERSIST_END') {$T__tSrc.Cancel(); Break}
                Else                                     {$T__Data.Add($T__Feed.Current)} 
            }}
            Catch   {[Collections.Generic.List[String]]$T__Data = @('#STR_targetgame=XXXX;')}
            Finally {
                If ($Null -ne $T__Feed) {[Void]$T__Feed.DisposeAsync()}
                If ($Null -ne $T__tSrc) {[Void]$T__tSrc.Dispose()}

                Remove-Variable T__tSrc, T__Enm, T__Feed -EA 0
            }
        }

        Switch (($T__Data | Where-Object {$_ -Match '^#STR_targetgame=\w+;$'}) | ForEach-Object {[Regex]::Match($_, '(?<=^#STR_targetgame=)\w+(?=;$)').Value}) {
            {$_ -In 'ETS2', 'ATS'} {[String]$T__Game = $_; Break}

            Default {
                [String]$T__OsDependentPattern = ('(?<=\\Documents\\)[ \w]+(?=\\?)', '(?<=\/home\/)[ \w]+(?=\/?)')[$Env:Os -NotMatch 'Windows']
                [String]$T__Game = ([Regex]::Match($PSScriptRoot, $T__OsDependentPattern).Value -Split ' ' | ForEach-Object {$_[0]}) -Join ''

                If ($T__Game -NotIn 'ETS2', 'ATS') {
                    Try {[Console]::CursorVisible = $True} Catch {}
                    Write-Host -NoNewline -ForegroundColor Red 'Failed to auto-detect sim name. '
                    Write-Host -NoNewline 'Select manually [0: ETS2 | 1: ATS | ESC: Exit]'
                    $Host.UI.RawUI.FlushInputBuffer()

                    Do {
                        If ($Null -ne $T__In) {[Console]::Beep(700, 250)}
                        [Byte]$T__In = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown').VirtualKeyCode
                        If ($T__In -eq 27) {Exit}
                    } Until ($T__In -In [Byte[]][Char[]]'01')

                    Clear-Host
                    [String]$T__Game = ('ETS2', 'ATS')[$T__In - 48]

                    Remove-Variable T__Data, T__OsDependentPattern, T__In -EA 0

                    Break
                }
            }
        }
    }
    
    [String]$T__GameMode = "Targeting: $T__Game "

    [Hashtable]$T__LoadSplat_Session = @{
        Object          = "`n$T__SessionStr"
        ForegroundColor = [ConsoleColor]::DarkGray
        BackgroundColor = [ConsoleColor]::DarkBlue
        NoNewline       = $True
    }
    [Hashtable]$T__LoadSplat_Message = @{
        Object          = "$T__Message$(' ' * [Math]::Max(0, $Host.UI.RawUI.BufferSize.Width - $T__Message.Length - $T__SessionStr.Length - $T__GameMode.Length))"
        ForegroundColor = [ConsoleColor]::White
        BackgroundColor = [ConsoleColor]::DarkBlue
        NoNewline       = $True
    }
    [Hashtable]$T__LoadSplat_Target = @{
        Object          = $T__GameMode
        ForegroundColor = [ConsoleColor]::DarkGray
        BackgroundColor = [ConsoleColor]::DarkBlue
        NoNewline       = $True
    }

    Try {[Console]::CursorVisible = $False} Catch {}

    Write-Host @T__LoadSplat_Session
    Write-Host @T__LoadSplat_Message
    Write-Host @T__LoadSplat_Target
    Write-Host -NoNewline "`n`n$($T__Tab * 3)Loading functions... "

    [Diagnostics.Stopwatch]$T__StepTimer = [Diagnostics.Stopwatch]::StartNew()

    Remove-Variable T__Message, T__SessionStr, T__GameMode, T__LoadSplat*, _Game -EA 0
}

Function Sync-Ets2ModRepo {
    [CmdletBinding()]
    Param ([String]$Updated)

    Function Limit-Range {
        [CmdletBinding()]
        [OutputType([Double])]

        Param (
            [Parameter(Mandatory, Position = 0)][Double]$Value,
            [Parameter(Mandatory, Position = 1)][Double]$Min,
            [Parameter(Mandatory, Position = 2)][Double]$Max
        )

        # TODO: Swap upper and lower bounds if Min > Max?
        If ($Max - $Min -lt 0) {
            Write-Log ERROR "Invalid range: Maximum value ($Max) cannot be less than the Minimum value ($Min)."
            Throw 'Invalid range'
        }
        If ($Global:ClampAvailable) {Return [Math]::Clamp($Value, $Min, $Max)} Else {Return ($Value, $Min, $Max)[$Value -lt $Min + ($Value -gt $Max * 2)]}
    }

    Function Test-AnsiSupport {

        Write-Log INFO 'Received ANSI support test request.'

        If ($PSStyle -And $PSStyle.OutputRendering -eq 'Ansi') {
            Write-Log INFO 'ANSI support detected via $PSStyle.OutputRendering.'
            Return $True
        }
        If (!$Host.UI) {
            Write-Log ERROR 'Host.UI is unavailable. ANSI unsupported.'
            Return $False
        }

        If ($Host.UI.PSObject.Properties.Name.Contains('SupportsVirtualTerminal') -And $Host.UI.SupportsVirtualTerminal) {
            Write-Log INFO 'ANSI support detected via Host.UI.SupportsVirtualTerminal.'
            Return $True
        }

        Switch -Regex ($Host.Name) {
            '(Visual Studio Code)|(ConsoleHost)' {
                Write-Log INFO "Supported VSCode host or ConsoleHost '$($Host.Name)' detected. Confirming environment variables."
                If ($Env:WT_Session)          {Write-Log INFO 'ANSI support confirmed via WT_Session environment variable.';            Return $True}
                If ($Env:TERM -Match 'xterm') {Write-Log INFO "ANSI support confirmed via TERM environment variable matching 'xterm.'"; Return $True}
                If ($Env:COLORTERM)           {Write-Log INFO 'ANSI support confirmed via COLORTERM environment variable.';             Return $True}
                If ($Env:ANSICON)             {Write-Log INFO 'ANSI support confirmed via ANSICON environment variable.';               Return $True}
                If ($env:ConEmuANSI -eq 'ON') {Write-Log INFO 'ANSI support confirmed via ConEmuANSI environment variable set to ON.';  Return $True}

                Write-Log ERROR 'No environment variables indicate ANSI support. Assuming ANSI unsupported.'
                Return $False
            }
            Default {
                Write-Log ERROR "Unknown PSHost '$($Host.Name)'. Assuming ANSI unsupported."
                Return $False
            }
        }
        Write-Log ERROR 'ANSI unsupported.'
        Return $False
    }

    Function Resolve-Ansi {
        Param ([String]$Name)

        If ([String]::IsNullOrWhiteSpace($Name)) {Return}
        If ($Name[0] -eq '/')                    {Return '[0m'}

        [String]$Value = $Null

        If ($Script:Ansi__Alias.TryGetValue($Name, [Ref]$Value)) {$Name = $Value}
        #If ($Name.Length -lt 3)                                  {Return}
        If ($Script:Ansi__Map.TryGetValue($Name, [Ref]$Value))   {Return $Value}
    }

    Function Initialize-Ansi {
        Param ([Switch]$Force)

        Write-Log INFO "Received ANSI subsystem init request$(('', ' (-Force)')[$Force.IsPresent])."

        If ($Script:Ansi__Init) {
            If (!$Force.IsPresent) {
                Write-Log INFO 'ANSI subsystem already initialized. Use -Force to force re-initialization.'
                Return
            }
            Write-Log INFO 'Forcing ANSI subsystem re-initialization.'

            Get-Variable -Name Ansi__* -Exclude Ansi__Incompatible -Scope Script -EA 0 | Remove-Variable -Scope Script -Force -EA 0

            Write-Log INFO 'Cleared existing ANSI subsystem.'
        }

        Write-Log INFO 'Checking ANSI support.'
        $Script:Ansi__Incompatible = !(Test-AnsiSupport)
        If ($Script:Ansi__Incompatible) {Throw 'ANSI formatting is not supported'}

        [StringComparer]$StrComp = [StringComparer]::OrdinalIgnoreCase

        Write-Log INFO 'Initializing ANSI sequence maps.'

        [Collections.Generic.Dictionary[String, String]]$AliasMap = [Collections.Generic.Dictionary[String, String]]::New(21, $StrComp)
        [Collections.Generic.Dictionary[String, String]]$SpecMap  = [Collections.Generic.Dictionary[String, String]]::New(6,  $StrComp)
        [Collections.Generic.Dictionary[String, String]]$BgMap    = [Collections.Generic.Dictionary[String, String]]::New(8,  $StrComp)
        [Collections.Generic.Dictionary[String, String]]$FgMap    = [Collections.Generic.Dictionary[String, String]]::New(16, $StrComp)

        $AliasMap.Add('DRed',     'DarkRed')
        $AliasMap.Add('DGreen',   'DarkGreen')
        $AliasMap.Add('DYellow',  'DarkYellow')
        $AliasMap.Add('DBlue',    'DarkBlue')
        $AliasMap.Add('DMagenta', 'DarkMagenta')
        $AliasMap.Add('DCyan',    'DarkCyan')
        $AliasMap.Add('DGray',    'DarkGray')
        $AliasMap.Add('BBlk',     'BgBlack')
        $AliasMap.Add('BRed',     'BgRed')
        $AliasMap.Add('BGrn',     'BgGreen')
        $AliasMap.Add('BYlo',     'BgYellow')
        $AliasMap.Add('BBlu',     'BgBlue')
        $AliasMap.Add('BMgt',     'BgMagenta')
        $AliasMap.Add('BCya',     'BgCyan')
        $AliasMap.Add('BWht',     'BgWhite')
        $AliasMap.Add('Cls',      'ClearScreen')
        $AliasMap.Add('Cle',      'ClearEnd')
        $AliasMap.Add('U',        'Underline')
        $AliasMap.Add('I',        'Invert')
        $AliasMap.Add('F',        'Blink')
        $AliasMap.Add('R',        'Reset')
        $AliasMap.Add('B',        'Bold')

        $SpecMap.Add('Reset',       '[0m')
        $SpecMap.Add('Invert',      '[7m')
        $SpecMap.Add('Bold',        '[1m')
        $SpecMap.Add('Underline',   '[4m')
        $SpecMap.Add('Blink',       '[5m')
        $SpecMap.Add('BrightBg',    '[5m')
        $SpecMap.Add('ClearEnd',    '[K')
        $SpecMap.Add('ClearScreen', '[2J')
        
        $BgMap.Add('BgBlack',   '[40m')
        $BgMap.Add('BgRed',     '[41m')
        $BgMap.Add('BgGreen',   '[42m')
        $BgMap.Add('BgYellow',  '[43m')
        $BgMap.Add('BgBlue',    '[44m')
        $BgMap.Add('BgMagenta', '[45m')
        $BgMap.Add('BgCyan',    '[46m')
        $BgMap.Add('BgWhite',   '[47m')

        $FgMap.Add('Black',       '[30m')
        $FgMap.Add('DarkRed',     '[31m')
        $FgMap.Add('DarkGreen',   '[32m')
        $FgMap.Add('DarkYellow',  '[33m')
        $FgMap.Add('DarkBlue',    '[34m')
        $FgMap.Add('DarkMagenta', '[35m')
        $FgMap.Add('DarkCyan',    '[36m')
        $FgMap.Add('Gray',        '[37m')
        $FgMap.Add('DarkGray',    '[1;30m')
        $FgMap.Add('Red',         '[1;31m')
        $FgMap.Add('Green',       '[1;32m')
        $FgMap.Add('Yellow',      '[1;33m')
        $FgMap.Add('Blue',        '[1;34m')
        $FgMap.Add('Magenta',     '[1;35m')
        $FgMap.Add('Cyan',        '[1;36m')
        $FgMap.Add('White',       '[1;37m')

        [Collections.Generic.Dictionary[String, String]]$Map = [Collections.Generic.Dictionary[String, String]]::New($SpecMap.Count + $FgMap.Count + $BgMap.Count, $StrComp)
        ForEach ($Entry in $SpecMap.GetEnumerator()) {$Map[$Entry.Key] = $Entry.Value}
        ForEach ($Entry in $FgMap.GetEnumerator())   {$Map[$Entry.Key] = $Entry.Value}
        ForEach ($Entry in $BgMap.GetEnumerator())   {$Map[$Entry.Key] = $Entry.Value}

        Write-Log INFO 'Compiling ANSI regex patterns and replacers.'
        
        # RegexOptions:
        # 512 = CultureInvariant; 8 = ExplicitCapture; 4 = Compiled
        [Regex]       $Script:Ansi__Pattern  = [Regex]::New('(?<X>\\)?<(?<Tag>/?[A-Za-z][A-Za-z_]*?)>', 524) # 524 = 512 -bor 8 -bor 4 // CultureInvariant + ExplicitCapture + Compiled
        [Regex]       $Script:Ansi__StripCsi = [Regex]::New('\e\[[\d;?]*[ -/]* [@-~]', 524)                  # 524 = 512 -bor 8 -bor 4 // CultureInvariant + ExplicitCapture + Compiled
        [ScriptBlock] $Script:Ansi__Replacer = {
            Param ($Match)
            If ($Match.Groups['X'].Success) {Return $Match.Value.Substring(1)}
            $Seq = Resolve-Ansi $Match.Groups['Tag'].Value
            If ($Seq) {Return "`e$Seq"}
            Return $Match.Value
        }
        [ScriptBlock] $Script:Ansi__StripReplacer = {
            Param ($Match)
            If ($Match.Groups['X'].Success) {Return $Match.Value.Substring(1)}
            Return ''
        }

        [Collections.Generic.Dictionary[String, String]]$Script:Ansi__Alias = $AliasMap
        [Collections.Generic.Dictionary[String, String]]$Script:Ansi__Map   = $Map

        [Bool]$Script:Ansi__Init = $True

        Write-Log INFO 'ANSI subsystem initialized successfully.'
    }

    Function Write-Ansi {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        [OutputType([Void], [String])]

        Param (
            [Parameter(Mandatory, Position = 0)]
            [AllowEmptyString()]
            [Alias('Text')]
            [String[]]$String,

            [Parameter(Position = 1)]
            [Byte]$Indent = 0,

            [Parameter(Mandatory, ParameterSetName = 'PassThru')]
            [Switch]$PassThru,

            [Parameter(ParameterSetName = 'Default')]
            [Switch]$NoNewline,

            [Parameter(ParameterSetName = 'Default')]
            [Switch]$NoConsole,

            [Switch]$NoReset
        )

        If (!$Script:Ansi__Init -And !$Script:Ansi__Incompatible) {
            Write-Log INFO 'ANSI subsystem is not initialized. Initializing.'
            Initialize-Ansi
        }
        ElseIf ($Script:Ansi__Incompatible) {
            [String]$String = $String -Join "`n"
            If ($PSCmdlet.ParameterSetName -eq 'Default') {
                If (!$NoNewline.IsPresent) {$String += "`n"}
                If ($NoConsole.IsPresent)  {Write-Host -NoNewline -Object $String}
                Else                       {[Console]::Write($String)}
                Return
            }
            Else {Return $String}
        }

        [String]$Pfx = ' ' * $Indent
        [String]$Raw = $Pfx + ($String -Join "`n$Pfx")

        If ($Raw.IndexOf('<') -ge 0) {[String]$OutString = $Script:Ansi__Pattern.Replace($Raw, $Script:Ansi__Replacer)}
        Else                         {[String]$OutString = $Raw}

        If (!$NoReset.IsPresent) {$OutString += "`e[0m"}

        If ($PSCmdlet.ParameterSetName -eq 'Default') {

            If (!$NoNewline.IsPresent) {$OutString += "`n"}
            If ($NoConsole.IsPresent)  {Write-Host -NoNewline -Object $OutString}
            Else                       {[Console]::Write($OutString)}
        }
        Else {
            [String]$Plain = $Script:Ansi__Pattern.Replace($Raw, $Script:Ansi__StripReplacer)
            Return $Script:Ansi__StripCsi.Replace($Plain, '')
        }
    }

    Function Write-HostX {
        [CmdletBinding()]
        [OutputType([Void])]

        Param (
            [Parameter(Mandatory, Position = 0)][ValidateScript({$_ -ge 0 -And $_ -le [Console]::BufferWidth})][UInt16]$X,
            [Parameter(Mandatory, Position = 1, ValueFromRemainingArguments)][String]$InputString,
            [ConsoleColor]$Color,
            [Switch]$Newline
        )

        [UInt16]$BufferWidth = [Console]::BufferWidth
        [UInt16]$InputLimit  = $BufferWidth - $X

        [String]$Plain = $Script:Ansi__Pattern.Replace($InputString, $Script:Ansi__StripReplacer)
        $Plain         = $Script:Ansi__StripCsi.Replace($Plain, '')
        # Prevent screen buffer overflows (line wrapping breaks the layout)
        If ($Plain.Length -ge $InputLimit) {$Plain = ($Plain.Substring(0, $InputLimit - 5) + '[...]')}

        [UInt16]$InputLength = $InputString.Length
        [Int]$RawPadLength   = $InputLimit - $InputLength
        [UInt16]$PadLength   = Limit-Range $RawPadLength 0 $BufferWidth

        If ($Color) {
            Write-Log WARN 'Write-HostX -Color is deprecated. Use Write-Ansi instead.'
            $InputString = "`e{0}$InputString" -f $Script:Ansi__Map[$Color.ToString()]
        }

        [Hashtable]$WaSplat = @{
            String    = $InputString + ' ' * $PadLength
            NoNewline = !$Newline.IsPresent
        }
        
        [Console]::SetCursorPosition($X, [Console]::CursorTop)
        Write-Ansi @WaSplat
    }

    Function Read-HostX {
        [CmdletBinding()]
        [OutputType([String])]

        Param ([Parameter(Position = 0)][String]$Prompt)

        $Host.UI.RawUI.FlushInputBuffer()
        Write-Log INFO 'Flushed input buffer.'

        [Console]::CursorVisible = $True

        Write-Log INFO 'Awaiting user input...'
        [String]$UserInput = If ($Prompt) {Read-Host $Prompt} Else {Read-Host}

        Write-Log INFO "User input received: '$UserInput'"
        
        [Console]::CursorVisible = $False

        Return $UserInput
    }

    Function Protect-Variables      {If ($GLOBAL:PROTECTED) {Throw 'The object is already initialized'} Else {[String[]]$GLOBAL:PROTECTED = (Get-Variable).Name + 'PROTECTED'}}
    Function Update-ProtectedVars   {If ($GLOBAL:PROTECTED) {Add-ProtectedVars (Get-UnprotectedVars)}}
    Function Get-UnprotectedVars    {If ($GLOBAL:PROTECTED) {Return [String[]](Get-Variable -Exclude $GLOBAL:PROTECTED).Name}}
    Function Remove-UnprotectedVars {If ($GLOBAL:PROTECTED) {Switch (Get-UnprotectedVars) {$Null {Return} Default {Remove-Variable $_ -EA 0}}}}
    Function Unprotect-Variables    {If ($GLOBAL:PROTECTED) {Remove-Variable PROTECTED -Scope Global}}
    Function Add-ProtectedVars      {
        [CmdletBinding()]
        Param ([Parameter(ValueFromPipeline)][String[]]$InputObject)

        If ($InputObject -And $GLOBAL:PROTECTED) {$GLOBAL:PROTECTED += $InputObject}
        $GLOBAL:PROTECTED = Select-Object -InputObject $GLOBAL:PROTECTED -Unique
    }

    Function Get-FileContent {
        [CmdletBinding(DefaultParameterSetName = 'Path')]
        [OutputType([String[]], [String], [Byte[]])]

        Param (
            [Parameter(Mandatory, ParameterSetName = 'Bytes')][Collections.Generic.List[Byte]]$FromBytes,
            [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')][IO.FileInfo]$Path,
            [Parameter(ParameterSetName = 'Path')][UInt64]$Offset = 0,
            [Parameter(ParameterSetName = 'Path')][UInt64]$Count = 0,
            [Parameter(ParameterSetName = 'Path')][Switch]$UseGc,
            [Parameter(ParameterSetName = 'Path')][Text.Encoding]$Encoding,
            [ValidateSet('CRLF', 'Windows', 'LF', 'Unix', 'CR', 'Mac', 'Any', '*')][String]$Eol = 'LF',
            [Switch]$Raw, [Switch]$AsByteArray, [Switch]$NoLog
        )

        If (!$NoLog.IsPresent) {
            Switch ($PSCmdlet.ParameterSetName) {
                'Path'  {Write-Log INFO "Received file content request for '$($Path.FullName)' (Length: $($Path.Length))."; Break}
                'Bytes' {Write-Log INFO 'Received byte array content request.'; Break}
            }
        }

        [Hashtable]$EolMap = @{
            CRLF    = "`r`n"; LF   = "`n"; CR  = "`r"
            Windows = "`r`n"; Unix = "`n"; Mac = "`r"
        }

        If ($Raw.IsPresent -And $AsByteArray.IsPresent -And !$NoLog.IsPresent) {Write-Log WARN 'Both -Raw and -AsByteArray switches are present. -Raw will be ignored.'}
        [Collections.Generic.List[Byte]]$Bytes = Switch ($PSCmdlet.ParameterSetName) {
            'Path' {
                If (!$Path.Exists) {If (!$NoLog.IsPresent) {Write-Log WARN "File '$($Path.Name)' not found. Returning null."} Return}
                [Collections.Generic.List[Byte]]$FileBytes = [Collections.Generic.List[Byte]]::New($Path.Length)
                Try {
                    If ($UseGc.IsPresent) {
                        If (!$NoLog.IsPresent) {Write-Log INFO '-UseGc: Forcing file reader fallback to Get-Content.'}
                        [String]$Source = "Gc Raw ByteStream '$($Path.Name)'"
                        Throw 'UseGc'
                    }
                    
                    [String]$Source = "ReadAllBytes '$($Path.Name)'"
                    $Offset         = [Math]::Min($Offset, $Path.Length - 1)
                    $Count          = ($Count, ($Path.Length - $Offset))[$Count -eq 0]

                    If ($Offset -le 3) {
                        If (!$NoLog.IsPresent -And $Offset -ne 0) {Write-Log INFO "Offset is within in the BOM range. Overriding Offset and Count values. (Offset: $Offset > 0; Count: $Count > $($Count + $Offset))"}
                        $Count += $Offset
                        $Offset  = 0
                    }
                    # TODO: Refactor this - Lots of unnecessary code since dropping FileStream in favor of ReadAllBytes
                    If (!$NoLog.IsPresent) {Write-Log INFO "Reading '$($Path.Length)' bytes from '$($Path.Name)' ReadAllBytes."}
                    $FileBytes = [IO.File]::ReadAllBytes($Path.FullName)

                    If (!$NoLog.IsPresent) {Write-Log INFO "Successfully read $($FileBytes.Count)/$($Path.Length) bytes"}
                    
                    If ($Offset -ne 0 -Or $Count -ne $Path.Length) {
                        [Byte[]]$Buffer = $FileBytes.GetRange($Offset, $Count)
                        If (!$NoLog.IsPresent) {Write-Log INFO "Adjusted buffer range: Offset=$Offset; Count=$Count."}
                    }
                    Else {[Byte[]]$Buffer = $FileBytes}
                }
                Catch {
                    [String]$Source = "Gc Raw ByteStream '$($Path.Name)'"
                    If ($_.Exception.Message -ne 'UseGc') {
                        If (!$NoLog.IsPresent) {
                            Write-Log ERROR "Failed to read '$($Path.Name)' bytes: $($_.Exception.Message)"
                            Write-Log INFO 'File reader fallback to Raw Get-Content ByteStream.'
                        }
                        $Source += ' (Fallback)'
                    }
                    Try {
                        If ($PSVersionTable.PSVersion.Major -lt 7) {
                            If (!$NoLog.IsPresent) {Write-Log ERROR "Failed to read '$($Path.Name)'. PowerShell $($PSVersionTable.PSVersion) does not support Get-Content ByteStream."}
                            Throw 'Get-Content ByteStream not supported.'
                        }

                        $FileBytes = Get-Content $Path.FullName -AsByteStream -Raw
                        If (!$NoLog.IsPresent) {Write-Log INFO "Successfully read '$($Path.Name)' Raw ByteStream."}

                        If ($Offset -ne 0 -Or $Count -ne $Path.Length) {
                            [Byte[]]$Buffer = $FileBytes.GetRange($Offset, $Count)
                            If (!$NoLog.IsPresent) {Write-Log INFO "Adjusted buffer range: Offset=$Offset; Count=$Count."}
                        }
                        Else {[Byte[]]$Buffer = $FileBytes}
                        Break
                    }
                    Catch {Throw $_}
                }
                Finally {$Buffer}
                Break
            }
            'Bytes' {
                If ($FromBytes.Count -lt 1) {If (!$NoLog.IsPresent) {Write-Log WARN 'No byte array provided. Returning null.'} Return}
                [String]$Source = 'Param -FromBytes <Byte[]>'
                $FromBytes
                Break
            }
        }

        If ($PSBoundParameters.ContainsKey('Encoding')) {If (!$NoLog.IsPresent) {Write-Log INFO "Using user-specified encoding: '$($Encoding.EncodingName)'."}}
        Else {
            Try {
                [PSCustomObject]$EncodingInfo = Get-FileEncoding -Bytes $Bytes
                If ($EncodingInfo.Confidence -eq 'Low') {
                    [Text.Encoding]$Encoding = [Text.UTF8Encoding]::New($False)
                    If (!$NoLog.IsPresent) {Write-Log WARN "Low confidence in detected encoding for '$Source'. Defaulting to UTF-8."}
                }
                Else {
                    [Text.Encoding]$Encoding = $EncodingInfo.Encoding
                    If (!$NoLog.IsPresent) {Write-Log INFO "Detected $Source encoding: '$($EncodingInfo.EncodingName)' (Confidence: $($EncodingInfo.Confidence))."}
                }
            }
            Catch {
                [Text.Encoding]$Encoding = [Text.UTF8Encoding]::New($False)
                If (!$NoLog.IsPresent) {Write-Log ERROR "Failed to detect encoding for '$Source': $($_.Exception.Message). Defaulting to UTF-8."}
            }
        }

        [String]$Content = $Encoding.GetString($Bytes)
        If (!$NoLog.IsPresent) {Write-Log INFO "Decoded byte array to '$($Encoding.EncodingName)' string (Code Page: $($Encoding.CodePage))."}

        If ($EolMap.ContainsKey($Eol)) {
            [String]$PreEolConversion = $Content
            $Content = [Regex]::Replace($Content, '\r\n|\r|\n', $EolMap[$Eol])
            If ($PreEolConversion -cne $Content -And !$NoLog.IsPresent) {Write-Log INFO "Converted line endings to $Eol."}
        }

        If (!$NoLog.IsPresent)      {Write-Log INFO "$($Bytes.Count) bytes read from '$Source'."}

        If ($AsByteArray.IsPresent) {Return [Byte[]]$Encoding.GetBytes($Content)}
        If ($Raw.IsPresent)         {Return [String]$Content}
        Else                        {Return [String[]]($Content -Split "\r\n|\n|\r")}
    }

    Function Set-Utf8Content {
        [CmdletBinding()]
        [OutputType([Void])]

        Param (
            [Parameter(Mandatory, Position = 0)][IO.FileInfo]$Path,
            [Parameter(Position = 1)][Collections.Generic.List[String]]$String,
            [ValidateSet(
                'CRLF',    'LF',   'CR',
                'Windows', 'Unix', 'Mac',
                '\r\n',    '\n',   '\r',
                "`r`n",    "`n",   "`r"
            )][String]$Eol = 'LF',
            [Switch]$Append,
            [Switch]$NoNewline,
            [Switch]$PassThru,
            [Switch]$NoLog
        )

        [Text.UTF8Encoding]$Utf8 = [Text.UTF8Encoding]::New($False)

        If (!$NoLog.IsPresent) {Write-Log INFO "Received data write request of approx. $($Utf8.GetBytes(($String -Join '')).Count) bytes for '$($Path.FullName)'."}

        [Hashtable]$EolMap = @{
            CRLF    = "`r`n"; LF   = "`n"; CR   = "`r"
            Windows = "`r`n"; Unix = "`n"; Mac  = "`r"
            '\r\n'  = "`r`n"; '\n' = "`n"; '\r' = "`r"
            "`r`n"  = "`r`n"; "`n" = "`n"; "`r" = "`r"
        }
        
        [String]$JoinedString = $String -Join $EolMap[$Eol]
        If (!$NoNewline.IsPresent) {$JoinedString += $EolMap[$Eol]}
        
        [Byte[]]$Bytes = $Utf8.GetBytes($JoinedString)
        
        If ($Append.IsPresent) {[IO.File]::AppendAllText($Path.FullName, $Utf8.GetString($Bytes), $Utf8)}
        Else                   {[IO.File]::WriteAllBytes($Path.FullName, $Bytes)}
        
        If (!$NoLog.IsPresent)   {Write-Log INFO "$($Bytes.Count) bytes written to '$($Path.Name)'."}
        If ($PassThru.IsPresent) {Return $Bytes}
    }

    Function Format-AndExportErrorData {
        [CmdletBinding()]
        [OutputType([String])]

        Param ([Parameter(Mandatory)][Management.Automation.ErrorRecord]$Exception)

        [String]$Timestamp = [DateTime]::Now.ToString('yyyy.MM.dd HH:mm:ss.fff')
        [String]$Message   = $Exception.Exception.Message
        [String]$Details   = $Exception.ErrorDetails.Message
        [String[]]$LogData = @(
            "[$Timestamp] FATAL ERROR",
            "$($Exception.InvocationInfo.PositionMessage)",
            "$($Exception.PSObject.Properties.Value -Join "`n")",
            "$('-' * 100)"
        )
        If ($Global:SessionLog) {Set-Utf8Content $Global:SessionLog $LogData -Append -NoLog}

        Return ($Details, $Message)[$Message.Length -gt $Details.Length]
    }

    Function Get-FileEncoding {
        [CmdletBinding()]
        [OutputType([PSCustomObject])]

        Param (
            [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')]
            [ValidateScript({$_.Exists})]
            [IO.FileInfo]$Path,

            [Parameter(Mandatory, Position = 0, ParameterSetName = 'Bytes')]
            [Byte[]]$Bytes,
            
            [Parameter(Position = 1, ParameterSetName = 'Path')]
            [UInt32]$SampleSize = 1MB
        )

        Function Test-ValidUtf8 {
            [OutputType([Bool])]

            Param ([Byte[]]$Data)

            # UTF-8 (No BOM, ThrowOnInvalidBytes)
            [Text.UTF8Encoding]$Utf8Strict = [Text.UTF8Encoding]::New($False, $True)

            Try   {[Void]$Utf8Strict.GetString($Data); Return $True}
            Catch {Return $False}
        }

        Function Get-AsciiRatio {
            [OutputType([Double])]

            Param ([Byte[]]$Data)

            If ($Data.Count -eq 0) {Return 1.0}
            [Double]$Ratio = ($Data | Where-Object {$_ -lt 128}).Count / $Data.Count

            Return $Ratio
        }

        Function Test-Binaryish {
            [OutputType([Bool])]

            Param ([Byte[]]$Data)

            If ($Data.Count -eq 0) {Return $False}
            
            [Double]$NullRatio = $Data.Where({$_ -eq 0}).Count / $Data.Count
            [Double]$CtrlRatio = $Data.Where({$_ -lt 9 -Or ($_ -gt 13 -And $_ -lt 32)}).Count / $Data.Count

            Return ($NullRatio -ge 0.3 -Or $CtrlRatio -ge 0.3)
        }

        Function Test-Utf16Pattern {
            [OutputType([String])]

            Param ([Byte[]]$Data)

            If ($Data.Count -lt 4) {Return $Null}

            [UInt16]$EvenZero = 0
            [UInt16]$OddZero  = 0

            For ([UInt32]$Index = 0; $Index -lt $Data.Count; $Index++) {
                If ($Data[$Index] -eq 0) {If ($Index % 2 -eq 0) {$EvenZero++} Else {$OddZero++}}
            }

            [UInt32]$Pairs = [Math]::Floor($Data.Count / 2)
            If ($Pairs -eq 0) {Return $Null}

            [Double]$EvenRatio = $EvenZero / $Pairs
            [Double]$OddRatio  = $OddZero  / $Pairs

            If ($EvenRatio -ge 0.4 -Or $OddRatio -ge 0.4) {
                If ($EvenRatio -gt $OddRatio) {Return 'UTF-16 LE'}
                Else                          {Return 'UTF-16 BE'}
            }

            Return $Null
        }

        Function Test-Utf32Pattern {
            [OutputType([String])]

            Param ([Byte[]]$Data)

            If ($Data.Count -lt 8) {Return $Null}

            [UInt16]$Groups = [Math]::Floor($Data.Count / 4)
            If ($Groups -lt 2) {Return $Null}

            [UInt16]$ZeroTriplets = 0

            For ([UInt16]$Group = 0; $Group -lt $Groups; $Group++) {

                [UInt32]$Index  = $Group * 4
                [UInt16]$Zeroes = 0

                If ($Data[$Index] -eq 0)     {$Zeroes++}
                If ($Data[$Index + 1] -eq 0) {$Zeroes++}
                If ($Data[$Index + 2] -eq 0) {$Zeroes++}
                If ($Data[$Index + 3] -eq 0) {$Zeroes++}
                If ($Zeroes -ge 3)           {$ZeroTriplets++}
            }
            If ($ZeroTriplets / $Groups -gt 0.25) {Return 'UTF-32'}

            Return $Null
        }

        Function Resolve-Bom {
            [OutputType([String])]

            Param ([Byte[]]$Data)

            [String]$HexString = ''
            ForEach ($Byte in $Data[0..4]) {$HexString += ([UInt16]$Byte).ToString('X2')}

            If ($Data.Count -ge 3 -And $HexString.StartsWith('2B2F76'))   {Return 'UTF-7'}
            If ($Data.Count -ge 3 -And $HexString.StartsWith('EFBBBF'))   {Return 'UTF-8 BOM'}
            If ($Data.Count -ge 2 -And $HexString.StartsWith('FFFE'))     {Return 'UTF-16 LE BOM'}
            If ($Data.Count -ge 2 -And $HexString.StartsWith('FEFF'))     {Return 'UTF-16 BE BOM'}
            If ($Data.Count -ge 4 -And $HexString.StartsWith('FFFE0000')) {Return 'UTF-32 LE BOM'}
            If ($Data.Count -ge 4 -And $HexString.StartsWith('0000FEFF')) {Return 'UTF-32 BE BOM'}

            Return $Null
        }

        If ($PSCmdlet.ParameterSetName -eq 'Path') {Write-Log INFO "Received file encoding analysis request for '$($Path.Name)'."}
        Else                                       {Write-Log INFO 'Received byte array encoding analysis request.'}

        [Collections.Generic.Dictionary[String, Text.Encoding]]$EncodingMap = [Collections.Generic.Dictionary[String, Text.Encoding]]::New()
        $EncodingMap.Add('UTF-32 BE BOM', [Text.UTF32Encoding]::New($True, $True))
        $EncodingMap.Add('UTF-32 LE BOM', [Text.UTF32Encoding]::New($False, $True))
        $EncodingMap.Add('UTF-32 BE',     [Text.UTF32Encoding]::New($True, $False))
        $EncodingMap.Add('UTF-32 LE',     [Text.UTF32Encoding]::New($False, $False))
        $EncodingMap.Add('UTF-16 BE BOM', [Text.UnicodeEncoding]::New($False, $True))
        $EncodingMap.Add('UTF-16 LE BOM', [Text.UnicodeEncoding]::New($True, $True))
        $EncodingMap.Add('UTF-16 BE',     [Text.UnicodeEncoding]::New($False, $False))
        $EncodingMap.Add('UTF-16 LE',     [Text.UnicodeEncoding]::New($True, $False))
        $EncodingMap.Add('UTF-8 BOM',     [Text.UTF8Encoding]::New($True))
        $EncodingMap.Add('UTF-8',         [Text.UTF8Encoding]::New($False))
        $EncodingMap.Add('UTF-7',         [Text.UTF7Encoding]::New())
        $EncodingMap.Add('ASCII',         [Text.ASCIIEncoding]::New())
        $EncodingMap.Add('ANSI',          [Text.Encoding]::Default)

        If     ($PSCmdlet.ParameterSetName -eq 'Bytes') {[Byte[]]$Buffer = $Bytes}
        ElseIf (!$Path.Exists)                          {Write-Log WARN "File '$($Path.Name)' not found. Returning null."; Return}
        ElseIf ($Path.Length -eq 0) {
            Write-Log INFO "File '$($Path.Name)' is empty. Assuming 'ASCII' encoding with High confidence."
            Return [PSCustomObject]@{
                Path         = $Path
                EncodingName = 'ASCII'
                Encoding     = $EncodingMap['ASCII']
                Confidence   = 'High'
                Details      = 'Empty file.'
            }
        }
        Else {
            [IO.FileStream]$FileStream = [IO.File]::OpenRead($Path.FullName)
            Try {
                [UInt32]$BufferSize = [Math]::Min($SampleSize, [Int]$FileStream.Length)
                [Byte[]]$Buffer     = [Byte[]]::New($BufferSize)
                [Void]$FileStream.Read($Buffer, 0, $BufferSize)
                Write-Log INFO "Read $BufferSize bytes from '$($Path.Name)' for encoding analysis."
            }
            Catch {
                Write-Log ERROR "Failed to read bytes from '$($Path.Name)' for encoding analysis: $($_.Exception.Message)"
                Throw $_
            }
            Finally {$FileStream.Dispose()}
        }
        
        [String]$Preamble = Resolve-Bom $Buffer
        If ($Preamble) {
            Write-Log INFO "Identified BOM signature in '$($Path.Name)'. Assumed encoding: '$Preamble'; Confidence: High."
            Return [PSCustomObject]@{
                Path         = $Path
                EncodingName = $Preamble
                Encoding     = $EncodingMap[$Preamble]
                Confidence   = 'High'
                Details      = 'Identified BOM signature.'
            }
        }

        If (Test-Binaryish $Buffer) {
            Write-Log INFO "Detected high number of NUL/control bytes in '$($Path.Name)'. Assumed encoding: Unknown/Binary/Mixed; Confidence: Low:"
            Return [PSCustomObject]@{
                Path         = $Path
                EncodingName = 'Unknown/Binary/Mixed'
                Encoding     = $Null
                Confidence   = 'Low'
                Details      = 'Detected high number of NUL/control bytes.'
            }
        }

        [String]$Utf32Guess = Test-Utf32Pattern $Buffer
        If ($Utf32Guess) {
            Write-Log INFO "Detected repeating 3-of-4 NUL-byte pattern in '$($Path.Name)'. Assumed encoding: '$Utf32Guess'; Confidence: Medium."
            Return [PSCustomObject]@{
                Path         = $Path
                EncodingName = $Utf32Guess
                Encoding     = $EncodingMap[$Utf32Guess]
                Confidence   = 'Medium'
                Details      = 'Detected repeating 3-of-4 NUL-byte pattern indicating UTF-32 encoding.'
            }
        }

        [String]$Utf16Guess = Test-Utf16Pattern $Buffer
        If ($Utf16Guess) {
            Write-Log INFO "Detected every-other-byte NUL pattern in '$($Path.Name)'. Assumed encoding: '$Utf16Guess'; Confidence: Medium."
            Return [PSCustomObject]@{
                Path         = $Path
                EncodingName = $Utf16Guess
                Encoding     = $EncodingMap[$Utf16Guess]
                Confidence   = 'Medium'
                Details      = 'Detected every-other-byte NUL pattern indicating UTF-16 encoding.'
            }
        }

        [Bool]$IsUtf8       = Test-ValidUtf8 $Buffer
        [Double]$AsciiRatio = Get-AsciiRatio $Buffer

        If ($IsUtf8) {
            If ($AsciiRatio -ge 1.0) {
                Write-Log INFO "All bytes < 0x80 in '$($Path.Name)'. Assumed encoding: 'ASCII'; Confidence: High."
                Return [PSCustomObject]@{
                    Path         = $Path
                    EncodingName = 'ASCII'
                    Encoding     = $EncodingMap['ASCII']
                    Confidence   = 'High'
                    Details      = 'All bytes < 0x80; ASCII subset.'
                }
            }
            Else {
                Write-Log INFO "Successfully performed strict UTF-8 decoding of all byte sequences in '$($Path.Name)'. Assumed encoding: 'UTF-8'; Confidence: Medium."
                Return [PSCustomObject]@{
                    Path         = $Path
                    EncodingName = 'UTF-8'
                    Encoding     = $EncodingMap['UTF-8']
                    Confidence   = 'Medium'
                    Details      = 'Passes strict UTF-8 decoding without errors.'
                }
            }
        }

        [Text.Encoding]$Ansi = $EncodingMap['ANSI']
        [Int]$CodePage       = $Ansi.CodePage
        [String]$Name        = $Ansi.EncodingName

        Write-Log INFO "No UTF-16/32 patterns or valid UTF-8 detected in '$($Path.Name)'. Assumed encoding: 'ANSI (Code Page: $CodePage; $Name)'; Confidence: $(('Medium', 'Low')[$AsciiRatio -gt 0.95])."
        Return [PSCustomObject]@{
            Path         = $Path
            EncodingName = "ANSI (Code Page: $CodePage; $Name)"
            Encoding     = $Ansi
            Confidence   = ('Medium', 'Low')[$AsciiRatio -gt 0.95]
            Details      = "Not valid UTF-8, no UTF-16/32 patterns detected. Single-byte code page likely."
        }
    }

    Function Write-Log {
        [CmdletBinding()]
        [OutputType([Void])]

        Param (
            [Parameter(Mandatory, Position = 0)][String]$Type,
            [Parameter(Position = 1)][String]$Message = ''
        )

        [String]$EntryPrefix = "[$([DateTime]::Now.ToString('yyyy.MM.dd HH:mm:ss.fff'))] " + $Type.PadRight(6) + ': '

        [Management.Automation.CallStackFrame[]]$CallStack = Get-PSCallStack
        [String]$Source = "$($CallStack[1].FunctionName) : "
        $EntryPrefix += '    ' * [Math]::Max(0, $CallStack.Count - 4)

        [String[]]$LogData = ($EntryPrefix + $Source + $Message) -Split "`n" -Join "`n$(' ' * (4 + $EntryPrefix.Length))" -Split "`n"

        Set-Utf8Content $Global:SessionLog $LogData -Append -NoLog
    }

    Function Measure-TransferRate {
        [CmdletBinding()]
        [OutputType([String])]

        Param (
            [Parameter(Mandatory, Position = 0)][Double]$Duration,
            [Parameter(Mandatory, Position = 1)][UInt32]$Bytes,
            [ValidateSet('B/s', 'kB/s', 'MB/s', 'GB/s')][String]$Unit
        )

        [Double]$BytesPerSecond = $Bytes / $Duration

        If ($PSBoundParameters.ContainsKey('Unit')) {
            [String]$UnitSymbol    = $Unit.ToLower().Replace('b', 'B').Replace('m', 'M').Replace('g', 'G')
            [Double]$ConvertedRate = Switch ($UnitSymbol) {
                'B/s'  {$BytesPerSecond}
                'kB/s' {$BytesPerSecond / 1kB}
                'MB/s' {$BytesPerSecond / 1MB}
                'GB/s' {$BytesPerSecond / 1GB}
            }
        }
        Else {[Double]$ConvertedRate, [String]$UnitSymbol = ((($BytesPerSecond / 1MB), 'MB/s'), (($BytesPerSecond / 1kB), 'kB/s'))[$BytesPerSecond -lt 1MB]}

        Return "$(([Math]::Round($ConvertedRate, 2), [Math]::Round($ConvertedRate))[$UnitSymbol -eq 'B/s']) $UnitSymbol"
    }
    
    Function Get-ModRepoFile {
        [CmdletBinding(DefaultParameterSetName = 'NoIWR')]
        [OutputType([Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject], [Object[]])]

        Param (
            [Parameter(Mandatory, Position = 0)][String]$File,
            [Parameter(ParameterSetName = 'NoIWR', Position = 1)][Byte]$X,
            [Parameter(ParameterSetName = 'NoIWR', Position = 2)][String]$State,
            [Parameter(ParameterSetName = 'NoIWR', Position = 3)][String]$Hash,
            [Parameter(Mandatory, ParameterSetName = 'IWR')][Switch]$UseIwr,
            [Parameter(ParameterSetName = 'IWR')][Switch]$Save,
            [String]$Repository = $Global:RepositoryUrl,
            [UInt16]$Timeout    = 15000
        )

        Trap {
            Write-Log ERROR "$($_.Exception.Message)"

            Try {$CryptoProvider.Dispose()} Catch {}
            Try {$FileStream.Dispose()}     Catch {}
            Try {$DownloadStream.Dispose()} Catch {}
            Try {$HttpClient.Dispose()}     Catch {}

            Throw $_
        }

        Write-Log INFO "Received download request of '$File' from '$Repository' ('$Repository/$File')."

        If ($Global:OfflineMode) {
            Write-Log ERROR "$($Global:ScriptDetails['ShortTitle']) is running in Offline Mode. Unable to download file '$File'."
            Throw 'Offline mode is enabled. Unable to download files.'
        }

        [Uri]$Uri = "$Repository/$File"

        If ($PSCmdlet.ParameterSetName -eq 'IWR') {
            Write-Log INFO "Invoke-WebRequest | Initializing WebRequest for download of '$Uri'."
            [Hashtable]$IwrSplat = @{Uri = $Uri; TimeoutSec = $Timeout}

            If ($PSVersionTable.PSVersion.Major -lt 6) {$IwrSplat['UseBasicParsing'] = $True}
            If ($Save.IsPresent)                       {$IwrSplat['OutFile']         = $File}

            Write-Log INFO "Invoke-WebRequest | Downloading '$Uri' $(('into memory.', "to '$File'.")[$Save.IsPresent])."
            
            Try     {Return Invoke-WebRequest @IwrSplat}
            Catch   {Write-Log ERROR "Invoke-WebRequest | Failed to download file: $($_.Exception.Message)"; Throw $_}
            Finally {Write-Log INFO "Invoke-WebRequest | Successfully downloaded '$Uri'."}
        }

        Write-Log INFO "HttpClient | Initializing HTTP client for download of '$File' from '$Repository'."
        [Net.Http.HttpClient]$HttpClient = [Net.Http.HttpClient]::New()
        $HttpClient.Timeout              = [TimeSpan]::FromMilliseconds($Timeout)
        $HttpClient.DefaultRequestHeaders.Add('User-Agent', $Global:ScriptDetails['ShortTitle'])

        [Net.Http.HttpResponseMessage]$RepoResponse = $HttpClient.GetAsync($Uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

        If (!$RepoResponse.IsSuccessStatusCode) {
            Write-Log ERROR "HttpClient | Failed to download file:`n$($RepoResponse.StatusCode)"
            Throw "Failed to download file: $($RepoResponse.StatusCode)"
        }

        [UInt64]$DownloadSize = $RepoResponse.Content.Headers.ContentLength

        [UInt32]$BufferSize = [Math]::Pow(2, [Math]::Floor([Math]::Log([Math]::Min($DownloadSize, [GC]::GetTotalMemory($False) / 10), 2)))
        [Byte[]]$Buffer     = [Byte[]]::New($BufferSize)
        Write-Log INFO "HttpClient | Ready to transfer $DownloadSize bytes to '$File'."
        
        [Security.Cryptography.SHA1CryptoServiceProvider]$CryptoProvider = [Security.Cryptography.SHA1CryptoServiceProvider]::New()
        Write-Log INFO 'CryptoProvider | Ready for blockwise SHA1 computation.'

        [Diagnostics.Stopwatch]$Interval = [Diagnostics.Stopwatch]::New()
        [IO.FileStream]$FileStream       = [IO.FileStream]::New($File, [IO.FileMode]::Create)
        [IO.Stream]$DownloadStream       = $RepoResponse.Content.ReadAsStreamAsync().Result
        
        Write-Log INFO "Download started. Block size: $BufferSize"

        $Interval.Start()

        [UInt64]$BytesRead       = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
        [UInt64]$BytesDownloaded = $BytesRead

        [UInt32]$Unit, [String]$Symbol, [Byte]$Decimals = Switch ($DownloadSize) {
            {$_ -lt 1000kB} {1kB, 'kB', 0; Break}
            {$_ -lt 1000MB} {1MB, 'MB', 0; Break}
            {$_ -ge 1000MB} {1GB, 'GB', 2; Break}
        }
        [String]$ConvertedDownload = "$([Math]::Round($DownloadSize / $Unit, $Decimals)) $Symbol"
        [UInt64]$IntervalBytes, [Double]$ConvertedBytes, [String]$TransferRate = 0, 0, '0 kB/s'

        While ($BytesRead -gt 0) {

            $FileStream.Write($Buffer, 0, $BytesRead)

            [Void]$CryptoProvider.TransformBlock($Buffer, 0, $BytesRead, $Null, $Null)
            
            $BytesRead        = $DownloadStream.Read($Buffer, 0, $Buffer.Length)
            $BytesDownloaded += $BytesRead
            $ConvertedBytes   = [Math]::Round($BytesDownloaded / $Unit, $Decimals)

            If ($Interval.ElapsedMilliseconds -ge $Global:DrawFrequency) {
                $TransferRate  = Measure-TransferRate $Interval.Elapsed.TotalSeconds ($BytesDownloaded - $IntervalBytes)
                $IntervalBytes = $BytesDownloaded
                $Interval.Restart()
            }

            [Console]::SetCursorPosition($X, [Console]::CursorTop)
            Write-Host -NoNewline -ForegroundColor Green ("║ $State " + "$ConvertedBytes".PadLeft(5) + "/$ConvertedDownload ($TransferRate)").PadRight(48)
            Write-Host -NoNewline ' ║'
        }

        $Interval.Stop()

        If ($BytesDownloaded -eq 0) {
            Write-Log ERROR "HttpClient | Download failed: No data received.`nBD=$BytesDownloaded,BR=$BytesRead,DS=$DownloadSize,BS=$BufferSize"
            Throw "Download failed: BD=$BytesDownloaded,BR=$BytesRead,DS=$DownloadSize,BS=$BufferSize"
        }

        [Void]$CryptoProvider.TransformFinalBlock($Buffer, 0, 0)
        [String]$FileHash = [BitConverter]::ToString($CryptoProvider.Hash) -Replace '-', ''
        Write-Log INFO "CryptoProvider | Block transformation complete. SHA1 Hash: $FileHash"

        If ('Hash' -In $PSBoundParameters.Keys -And $FileHash -ne $Hash) {
            Write-Log ERROR "HttpClient | Download failed: FileHash mismatch for '$File'`nExpected: $Hash`nActual:   $FileHash"
            Throw 'Download failed: Hash mismatch'
        }

        Write-Log INFO "HttpClient | Download completed. $BytesDownloaded bytes ($ConvertedDownload) transferred."

        $DownloadStream.Dispose()
        $CryptoProvider.Dispose()
        $FileStream.Dispose()
        $HttpClient.Dispose()
        
        Return $ConvertedDownload, $BytesDownloaded, $FileHash
    }

    Function Test-PSHostCompatibility {
        [CmdletBinding()]
        [OutputType([Bool])]
        
        [Bool]$IsCompatible = $Host.UI.SupportsVirtualTerminal
        If (!$IsCompatible) {Write-Log ERROR "PSHost compatibility check: FAIL -- $($Host.Name) | Incompatible."}
        Else                {Write-Log INFO "PSHost compatibility check: PASS -- $($Host.Name) | Compatible."}

        Return $IsCompatible
    }

    Function Test-ModActive {
        [CmdletBinding()]
        [OutputType([Bool])]

        Param ([Parameter(Mandatory)][String]$Mod)

        Write-Log INFO 'Received mod usage status request.'

        If (!$Global:GameLogPath.Exists -Or $Global:GameProcess -NotIn (Get-Process).Name) {Return $False}

        [Regex]$MountedPattern   = ' \: \[mod_package_manager\] Mod ".+" has been mounted\. \(package_name\: ' + $Mod + ','
        [Regex]$UnmountedPattern = ' \: \[(zip|hash)fs\] ' + $Mod + '\.(scs|zip)\: Unmounted\.?'
        
        ForEach ($Line in Get-FileContent $Global:GameLogPath) {
            If ($Line -Match $MountedPattern)   {[Bool]$IsLoaded = $True}
            If ($Line -Match $UnmountedPattern) {[Bool]$IsLoaded = $False}
        }
        Write-Log INFO "Mod '$Mod' is $(('not ', '')[$IsLoaded])loaded."

        Return $IsLoaded
    }

    Function Get-StringHash {
        [CmdletBinding(DefaultParameterSetName = 'String')]
        [OutputType([String])]

        Param (
            [Parameter(Mandatory, ParameterSetName = 'String', Position = 0)]
            [String[]]$String,

            [Parameter(Mandatory, ParameterSetName = 'Bytes', Position = 0)]
            [Byte[]]$Bytes,

            [Parameter(Position = 1)]
            [ValidateSet('CRC32', 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5')]
            [String]$Algorithm = 'SHA256',

            [Parameter(ParameterSetName = 'String')]
            [Text.Encoding]$Encoding = [Text.UTF8Encoding]::New($False)
        )

        If ($PSBoundParameters.ContainsKey('String')) {[Byte[]]$Bytes = $Encoding.GetBytes($String -Join "`n")}

        If ($Algorithm -eq 'CRC32') {
            Return ([WindowsAPI]::RtlComputeCrc32(0, $Bytes, $Bytes.Count).ToString('X8'))
        }
        Else {
            [Hashtable]$GfhSplat = @{InputStream = [IO.MemoryStream]::New($Bytes); Algorithm = $Algorithm}
            Return (Get-FileHash @GfhSplat).Hash
        }
    }

    Function Test-FileHash {
        [CmdletBinding()]
        [OutputType([Bool])]

        Param (
            [Parameter(Position = 0)][IO.FileInfo]$File,
            [Parameter(Mandatory, Position = 1)][String]$Hash,
            [Parameter(Position = 2)][UInt64]$Size
        )

        Write-Log INFO "Received FileHash test request for '$($File.FullName)' with Hash: $Hash$(('', " and Size: $Size")[$PSBoundParameters.ContainsKey('Size')])."
        If (!$File.Exists) {
            Write-Log INFO "Test FAILED : Cannot find File '$($File.Name)'."
            Return $False
        }
        If ($Size -And $File.Length -ne $Size) {
            Write-Log INFO "Test FAILED : FileSize Mismatch for File '$($File.Name)'`nExpected: $Size, Actual:   $($File.Length)."
            Return $False
        }

        Try {
            [UInt64]$Buffer        = [Math]::Pow(2, [Math]::Floor([Math]::Log([Math]::Min($File.Length, [GC]::GetTotalMemory($False) / 4), 2)))
            [IO.FileStream]$Stream = [IO.FileStream]::New($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, $Buffer)

            [String]$ComputedHash = [BitConverter]::ToString($Global:CryptoProvider.ComputeHash($Stream)) -Replace '-', ''
            If ($ComputedHash -ne $Hash) {
                Write-Log INFO "Test FAILED : Computed FileHash Mismatch for File '$($File.Name)'`nExpected: $Hash`nActual:   $ComputedHash"
                Return $False
            }
            Else {
                Write-Log INFO "Test PASSED : Computed FileHash Match for File '$($File.Name)'"
                Return $True
            }
        }
        Catch   {
            Write-Log ERROR "Test FAILED : Failed to compute FileHash for File '$($File.Name)':`n$($_.Exception.Message)"
            Return $False
        }
        Finally {$Stream.Dispose()}
    }

    Function Test-ArrayNullOrEmpty {
        [CmdletBinding()]
        [OutputType([Bool])]

        Param ([AllowEmptyCollection()][Object[]]$Array)

        If ($Null -eq $Array) {Return $True}

        Return ([Math]::Max($Array.IndexOf(''), $Array.IndexOf($Null)) -ne -1)
    }

    Function Test-GameConfiguration {
        # TODO: Not yet implemented
        [CmdletBinding()]
        [OutputType([Void])]

        Param ([IO.FileInfo]$ConfigPath = $Global:GameConfigPath)

        [Hashtable]$ConfigData = @{}

        ForEach ($Line in Get-FileContent $ConfigPath) {
            If ($Line -NotMatch '^uset ') {Continue}
            $Line = $Line -Replace '(?<=^)uset (?=.*$)', ''
            [String]$Name, [String]$Value = $Line -Replace '"', '' -Split ' ', 2
            $ConfigData[$Name]            = $Value
        }
    }
    
    Function Wait-WriteAndExit {
        [CmdletBinding()]
        [OutputType([String])]

        Param ([String]$InputObject, [Switch]$Restart)

        Write-Log INFO 'Received wait and exit request.'

        Write-Host -ForegroundColor Red $InputObject
        
        Unprotect-Variables
        [Void](Read-KeyPress)

        If ($Restart.IsPresent) {
            Write-Log INFO 'Executing restart routine...'
            $Global:ScriptRestart = $True
            [Void]$Global:ScriptRestart
            Return 'Restart'
        }
        If ($Null -ne $Global:SessionLog) {
            Write-Log INFO 'Opening log file and exiting.'
            Invoke-Item $Global:SessionLog.FullName
        }
        Else {Write-Log INFO 'Exiting.'}

        Exit
    }

    Function Read-KeyPress {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        [OutputType([Byte])]

        Param (
            [Parameter(Position = 0)][String]$Prompt,
            [Parameter()][Alias('Fg')][ConsoleColor]$ForegroundColor = [Console]::ForegroundColor,
            [Parameter()][Alias('Bg')][ConsoleColor]$BackgroundColor = [Console]::BackgroundColor,

            [Parameter(ParameterSetName = 'Timeout', Mandatory)][UInt16]$Timeout,
            [Parameter(ParameterSetName = 'Timeout')][Char]$DefaultKey,
            [Parameter(ParameterSetName = 'Timeout')][Double]$RefreshRate = 100,
            [Parameter(ParameterSetName = 'Timeout')][ValidatePattern('^[^\r\n]+$')][String]$TimerAt,
            
            [Parameter()][Switch]$NoNewline,
            [Parameter()][Switch]$Clear
        )

        Write-Log INFO 'Received key press input request.'
        
        If ($PSBoundParameters.ContainsKey('Prompt')) {
            If ($PSVersionTable.PSVersion.Major -lt 7) {$Prompt = [Regex]::Replace($Prompt, '\r\n|\r|\n', "`n")}
            Else                                       {$Prompt = $Prompt.ReplaceLineEndings("`n")}
            [Bool]$PromptIsMultiLine = ($Prompt -Split "`n").Count -gt 1
            If ($PSBoundParameters.ContainsKey('TimerAt')) {
                [String]$InitPrompt = $Prompt
                $Prompt             = [Regex]::Replace($InitPrompt, [Regex]::Escape($TimerAt), $Timeout)
                If ($PromptIsMultiLine) {[UInt16[]]$Len = $Prompt -Split "`n" | ForEach-Object {$_.Length}}
                Else                    {[UInt16]$Len   = $Prompt.Length}
            }
            [Hashtable]$_Splat = @{
                ForegroundColor = $ForegroundColor
                BackgroundColor = $BackgroundColor
                NoNewline       = $NoNewline.IsPresent
            }
            [Hashtable]$ClearSplat  = $_Splat
            [Hashtable]$PromptSplat = $_Splat

            $ClearSplat['Object']  = $Prompt -Replace '[^\n]', ' '
            $PromptSplat['Object'] = $Prompt

            [Hashtable]$InitPos = @{X = [Console]::CursorLeft; Y = [Console]::CursorTop}

            Write-Host @PromptSplat
        }

        $Host.UI.RawUI.FlushInputBuffer()
        Write-Log INFO 'Flushed input buffer.'

        If ($PSCmdlet.ParameterSetName -eq 'Timeout') {
            Write-Log INFO "Awaiting key press. $Timeout second timeout..."

            [Double]$Duration = 0
            [UInt32]$SecsLeft = $Timeout + 1
            [DateTime]$Start  = [DateTime]::Now

            While ($Duration -le $Timeout) {
                If ($PSBoundParameters.ContainsKey('Prompt') -And $PSBoundParameters.ContainsKey('TimerAt')) {
                    [UInt32]$Diff = Limit-Range ([Math]::Ceiling($Timeout - $Duration)) 0 $Timeout
                    If ($Diff -ne $SecsLeft) {
                        $Prompt                = [Regex]::Replace($InitPrompt, [Regex]::Escape($TimerAt), "$Diff")
                        $PromptSplat['Object'] = $Prompt
                        If ($PromptIsMultiLine) {
                            [UInt16[]]$nLen = $Prompt -Split "`n" | ForEach-Object {$_.Length}
                            If ("$nLen" -ne "$Len") {
                                [String[]]$Clear      = For ($i = 0; $i -lt $Len.Count; $i++) {$Len[$i] = [Math]::Max($Len[$i], $nLen[$i]); ' ' * $Len[$i]}
                                $ClearSplat['Object'] = $Clear -Join "`n"
                            }
                        }
                        Else {[UInt16]$nLen = $Prompt.Length}

                        If ("$nLen" -ne "$Len") {
                            [String[]]$Clear      = For ($i = 0; $i -lt $Len.Count; $i++) {$Len[$i] = [Math]::Max($Len[$i], $nLen[$i]); ' ' * $Len[$i]}
                            $ClearSplat['Object'] = $Clear -Join "`n"

                            [Console]::SetCursorPosition($InitPos.X, $InitPos.Y)
                            Write-Host @ClearSplat
                        }
                        [Console]::SetCursorPosition($InitPos.X, $InitPos.Y)
                        Write-Host @PromptSplat

                        $SecsLeft = $Diff
                    }
                }
                If ($Host.UI.RawUI.KeyAvailable) {[Byte]$KeyCode = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown').VirtualKeyCode; Break}
                Start-Sleep -Milliseconds $RefreshRate
                $Duration = ([DateTime]::Now - $Start).TotalSeconds
            }
            [Byte]$KeyPress = If ($Null -eq $KeyCode) {Write-Log INFO "Timed out. Using default keypress: $DefaultKey"; $DefaultKey} Else {Write-Log INFO "Keypress received: $KeyCode"; $KeyCode}
        }
        Else {
            Write-Log INFO 'Awaiting key press...'
            [Byte]$KeyPress = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown').VirtualKeyCode
            Write-Log INFO "Keypress received: $KeyPress"
        }

        If ($Clear.IsPresent -And $PSBoundParameters.ContainsKey('Prompt')) {
            [UInt16[]]$nLen = $PromptSplat.Object -Split "`n" | ForEach-Object {$_.Length}
            If ("$nLen" -ne "$Len") {
                [String[]]$Clear      = For ($i = 0; $i -lt $Len.Count; $i++) {$Len[$i] = [Math]::Max($Len[$i], $nLen[$i]); ' ' * $Len[$i]}
                $ClearSplat['Object'] = $Clear -Join "`n"
            }
            [Console]::SetCursorPosition($InitPos.X, $InitPos.Y)
            Write-Host @ClearSplat
            [Console]::SetCursorPosition($InitPos.X, $InitPos.Y)
        }
        
        $Host.UI.RawUI.FlushInputBuffer()
        Write-Log INFO 'Flushed input buffer.'

        Return $KeyPress
    }

    Function Set-ForegroundWindow {
        [CmdletBinding(DefaultParameterSetName = 'PID')]
        [OutputType([Void])]

        Param (
            [Parameter(ParameterSetName = 'Self', Mandatory)]
            [Switch]$Self,

            [Parameter(ParameterSetName = 'Self')]
            [Parameter(ParameterSetName = 'PID')]
            [UInt32]$Id = $Pid,

            [Parameter(ParameterSetName = 'Name', Mandatory)]
            [Parameter(ParameterSetName = 'Name_WHnd', Mandatory)]
            [Parameter(ParameterSetName = 'Name_Title', Mandatory)]
            [Parameter(ParameterSetName = 'Name_Both', Mandatory)]
            [String]$Name,
            
            [Parameter(ParameterSetName = 'Name_WHnd', Mandatory)]
            [Parameter(ParameterSetName = 'Name_Both', Mandatory)]
            [IntPtr]$Handle,
            
            [Parameter(ParameterSetName = 'Name_Title', Mandatory)]
            [Parameter(ParameterSetName = 'Name_Both', Mandatory)]
            [String]$Title
        )

        $ParamSets    = $PSCmdlet.MyInvocation.MyCommand.ParameterSets.Name
        Write-Log DEBUG "`$ParamSets DATA TYPE: '$($ParamSets.GetType().FullName)'"
        [Management.Automation.WildcardPattern]$TitlePattern = [Management.Automation.WildcardPattern]::New($Title, 2 -bor 4) # Options - 0=None, 1=Compiled, 2=IgnoreCase, 4=CultureInvariant
        [Void]$TitlePattern # Suppresses false unused variable warning. Used in Default case of Switch ($PSCmdlet.ParameterSetName) statement.
        If (!$Handle) {[IntPtr]$Handle = [IntPtr]::Zero}

        [String]$Msg        = 'Received set foreground window request for '
        [String[]]$NameEval = @('($_.MainWindowHandle -ne $Handle)', '')

        [String]$Filter, [String]$Info = Switch ($PSCmdlet.ParameterSetName) {
            'Self'  {@('', "$_ (PID $Id)."); Break}
            'PID'   {@('', "process ID $Id."); Break}
            'Name'  {@($NameEval[0], "$($NameEval[1]) process name '$Name'."); Break}
            Default {
                $NameEval = Switch ($_) {
                    'Name_WHnd'  {@("!$($NameEval[0])", " (WHnd: $Handle)."); Break}
                    'Name_Title' {@("$($NameEval[0]) -And `$TitlePattern.IsMatch(`$_.MainWindowTitle)", " (Title: $Title)."); Break}
                    'Name_Both'  {@("!$($NameEval[0]) -And `$TitlePattern.IsMatch(`$_.MainWindowTitle)", " (WHnd: $Handle, Title: $Title).")
                    Default      {Throw 'Invalid parameter set name.'}
                }}
                $NameEval[1] = "process name '$Name'." + $NameEval[1]
                $NameEval; Break
            }
        }
        Write-Log INFO ($Msg + $Info)
        Write-Log INFO "ParameterSets: $($ParamSets -Join ', '))"

        [ScriptBlock]$FilterScript = [ScriptBlock]::Create($Filter)
        Write-Log INFO "Set FilterScript: $Filter"

        Try {
            [Diagnostics.Process]$Target = Switch ($PSCmdlet.ParameterSetName) {
                {$_ -Match '^(PID)|(Self)$'} {[Diagnostics.Process]::GetProcessById($Id)[0]; Break}
                {$_ -Match '^Name'}          {([Diagnostics.Process]::GetProcessesByName($Name) | Where-Object $FilterScript)[0]; Break}
            }
        }
        Catch {
            Write-Log ERROR "Failed to fetch target process: $($_.Exception.Message)"
            Write-Log ERROR 'Request cancelled.'
        }

        [UInt32]$TargetPid  = $Target.Id
        [IntPtr]$TargetWhnd = $Target.MainWindowHandle
        [String]$TargetName = $Target.Name
        Write-Log INFO "Fetched target process information: Name '$TargetName', PID: $TargetPid, WHnd: $TargetWhnd."

        [Void]$Global:wScriptShell.AppActivate($TargetPid)
        [Void][WindowsAPI]::SetForegroundWindow($TargetWhnd)

        If ([WindowsAPI]::GetForegroundWindow() -eq $TargetWhnd) {Write-Log INFO "Activated PID $TargetPid and set foreground window to handle '$TargetWhnd'."}
        Else                                                     {Write-Log ERROR "Failed to set foreground window to handle '$TargetWhnd'."}
    }

    Function ConvertFrom-ActiveModEntry {
        [CmdletBinding()]
        [OutputType([Hashtable])]

        Param (
            [Parameter(Position = 0)][String]$Locator,
            [Parameter(Position = 1)][String]$Name
        )

        Write-Log INFO "Received mod source conversion request for '$Locator'."

        [String]$Type, [String]$Hex = $Locator -Split '\.', 2
        $Type = ('Local', 'Workshop')[$Type -eq 'mod_workshop_package']

        [String]$Converted = Switch ($Type) {
            'Local'    {"$($Global:GameModDirectory.FullName)\$Locator.scs"; Break}
            'Workshop' {"$($Global:WorkshopDirectory.FullName)\" + [String][UInt32]"0x$Hex"; Break}
            Default    {Throw "Invalid mod source type '$_'."}
        }
        Write-Log INFO "Converted '$Locator' >> '$Converted'"
        
        Return [Hashtable]@{
            Name       = $Name
            Type       = $Type
            Source     = $Locator
            SourcePath = $Converted
            SourceName = [IO.Path]::GetFileName($Converted)
        }
    }

    Function Convert-ProfileFolderName {
        [CmdletBinding()]
        [OutputType([String])]

        Param ([String]$Directory = $Global:ActiveProfile)

        Write-Log INFO 'Received profile folder conversion request.'

        [Char[]]$Converted = For ([UInt16]$Index = 0; $Index -lt $Directory.Length; $Index += 2) {[Char][Byte]"0x$($Directory.Substring($Index, 2))"}
        Write-Log INFO "Converted profile folder name '$Directory' to '$($Converted -Join '')'."
        
        Return $Converted -Join ''
    }

    Function ConvertTo-PlainTextProfileUnit {
        [CmdletBinding()]
        [OutputType([Void])]

        Param (
            [IO.FileInfo]$File    = $Global:ProfileUnit,
            [IO.FileInfo]$OutFile = $Global:TempProfileUnit,
            [Switch]$OnFile
        )

        Write-Log INFO 'Received profile format conversion request.'

        [IO.FileInfo]$UnitDecoder = Get-GameUnitDecoder
        [String]$DecodeCommand    = "& '$($UnitDecoder.FullName)'" + (" '$($File.FullName)' '$($OutFile.FullName)'", " --on_file -i '$($File.FullName)'")[$OnFile.IsPresent]
        [Object]$DecoderResult    = Invoke-Expression $DecodeCommand

        Write-Log INFO "Profile unit decoder finished with exit code $LASTEXITCODE`n($DecoderResult).`nCommand: $DecodeCommand"

        Switch ($LASTEXITCODE) {
            0       {Break}
            1       {Break}
            Default {Throw $DecoderResult}
        }
        If ((Get-ProfileUnitFormat $OutFile) -eq 'Binary') {Throw 'Profile unit decoder failed to convert to plaintext profile text format.'}
    }

    Function Test-WorkshopModInstalled {
        [CmdletBinding()]
        [OutputType([Bool])]

        Param ([Parameter(Mandatory)][IO.DirectoryInfo]$ModFolder)

        Write-Log INFO 'Received Workshop mod install status request.'

        [Bool]$Result = $False

        If ($ModFolder.Exists) {
            If ($ModFolder.EnumerateFileSystemInfos().Count -eq 0) {Write-Log INFO "Workshop mod folder '$($ModFolder.FullName)' exists but is empty."}
            Else                                                   {$Result = $True}
        }

        Write-Log INFO "Test for Workshop mod '$ModFolder' returned $Result."

        Return $Result
    }

    Function Get-SteamLaunchOptions {
        [CmdletBinding()]
        [OutputType([String])]

        Param ([Parameter(Position = 0)][UInt32]$AppId = $Global:GameAppId)

        Write-Log INFO "Received Steam launch options get request for AppID $AppId."

        #FIXME: Automatically get correct userdata directory
        [Collections.Generic.List[String]]$VdfLines = Get-FileContent 'K:\GAMES\Steam\userdata\78196472\config\localconfig.vdf'
        [Bool]$SearchingAppId  = $False
        [Int]$Stack            = 0
        [Regex]$AppIdPattern   = '^"' + $AppId + '"$'
        
        ForEach ($Line in $VdfLines) {
            [String]$Trimmed = $Line.Trim()
            
            If ([String]::IsNullOrWhiteSpace($Trimmed)) {Continue}
            If ($Trimmed -Match $AppIdPattern)          {$SearchingAppId = $True; Continue}

            If ($SearchingAppId) {
                If ($Trimmed -eq '{')                                           {$Stack++}
                If ($Trimmed -eq '}')                                           {$Stack--; If ($Stack -eq 0) {Break}}
                If ($Trimmed -Match '^"LaunchOptions"[ \t]+"((?:[^"]|\\")*)"$') {Return $Matches[1]}
            }
        }
    }

    Function Get-SteamRootDirectory {
        [CmdletBinding()]
        [OutputType([IO.DirectoryInfo])]

        Param ()

        If ($Env:Os -Match 'Windows') {
            [String]$RegKey              = 'HKLM:\SOFTWARE' + ('\', '\WOW6432Node\')[[Environment]::Is64BitOperatingSystem] + 'Valve\Steam'
            [IO.DirectoryInfo]$SteamRoot = Get-ItemPropertyValue $RegKey InstallPath

            If (!$SteamRoot.Exists) {
                Write-Log ERROR "Unable to locate Steam Root Directory in Registry Key '$RegKey'. (Query result: '$($SteamRoot.FullName)')."
                Throw [IO.DirectoryNotFoundException]::New("Unable to locate Steam Root Directory in Registry Key '$RegKey'.")
            }
            Else {Write-Log INFO "Retrieved Steam Root Directory '$($SteamRoot.FullName)' from Registry Key '$RegKey'."}
        }
        Else {
            [IO.DirectoryInfo]$SteamRoot = "$Env:Home/.steam/steam"

            If (!$SteamRoot.Exists) {
                Write-Log ERROR "Unable to locate Steam Root Directory '$($SteamRoot.FullName)'."
                Throw [IO.DirectoryNotFoundException]::New("Unable to locate Steam Root Directory '$($SteamRoot.FullName)'.")
            }
        }

        Return $SteamRoot
    }

    Function Get-GameDirectory {
        [CmdletBinding(DefaultParameterSetName = 'Both')]
        [OutputType([IO.DirectoryInfo], [IO.DirectoryInfo[]])]

        Param (
            [Parameter(Mandatory, ParameterSetName = 'GameRoot')][Switch]$Root,
            [Parameter(Mandatory, ParameterSetName = 'Workshop')][Switch]$Workshop,
            [Parameter(Mandatory, ParameterSetName = 'Both')][Switch]$Both
        )

        Switch ($PSCmdlet.ParameterSetName) {
            'GameRoot' {Write-Log INFO "Received $Global:GameNameShort ($Global:GameAppId) Game Root Directory Lookup request."; Break}
            'Workshop' {Write-Log INFO "Received $Global:GameNameShort ($Global:GameAppId) Workshop Directory Lookup request."; Break}
            'Both'     {Write-Log INFO "Received $Global:GameNameShort ($Global:GameAppId) Game Root + Workshop Directory Lookup request."; Break}
            Default    {Throw [Management.Automation.ParameterBindingException]::New("Invalid parameter set name '$_'.")}
        }

        [String]$Os                = ('Linux', 'Windows')[$Env:Os -Match 'Windows']
        [Regex]$PathSearchPattern  = ('(?i)(?<="path"\s+")[a-z]\:(?:\\\\.+)+(?=")', '(?i)(?<="path"\s+")(?:\/\/.+)+(?=")')[$Os -eq 'Linux']
        [Regex]$PathReplacePattern = ('\\\\', '\/\/')[$Os -eq 'Linux']
        [Regex]$AppIdSearchPattern = '(?<=")' + $Global:GameAppId + '(?="\s+"\d+")'
        [Regex]$InstallDirPattern  = '(?<="installdir"\s+")[^"]+(?=")'
        Write-Log INFO "Initialized search patterns for $Os."

        [IO.DirectoryInfo]$SteamDir = Get-SteamRootDirectory
        
        [IO.FileInfo]$LibVdf = [IO.Path]::Combine($SteamDir.FullName, 'SteamApps', 'libraryfolders.vdf')

        If (!$LibVdf.Exists) {
            Write-Log ERROR "Unable to locate Steam Library VDF '$($LibVdf.FullName)'."
            Throw [IO.FileNotFoundException]::New("Unable to locate Steam Library VDF '$($LibVdf.FullName)'.")
        }
        Else {Write-Log INFO "Performing $Global:GameNameShort SteamApps Directory lookup in Steam Library VDF '$($LibVdf.FullName)'."}

        [String[]]$LibraryData       = Get-FileContent $LibVdf
        [IO.DirectoryInfo]$SteamApps = ForEach ($Line in $LibraryData) {
            If ($Line -Match $PathSearchPattern)  {[String]$Path = $Matches[0] -Replace $PathReplacePattern, [IO.Path]::DirectorySeparatorChar; Continue}
            If ($Line -Match $AppIdSearchPattern) {[IO.Path]::Combine($Path, 'SteamApps'); Break}
        }

        If (!$SteamApps.Exists) {
            Write-Log ERROR "Failed to locate $Global:GameNameShort SteamApps Directory in Steam Library VDF '$($LibVdf.FullName)'. (Segment: '$Path'; Lookup result: '$($SteamApps.FullName)')"
            Throw [IO.DirectoryNotFoundException]::New("Unable to locate $Global:GameNameShort SteamApps Directory in Steam Library VDF '$($LibVdf.FullName)'.")
        }
        Else {Write-Log INFO "Located $Global:GameNameShort SteamApps Directory at: '$($SteamApps.FullName)'."}

        [IO.DirectoryInfo]$WorkshopDir = [IO.Path]::Combine($SteamApps.FullName, 'workshop', 'content', $Global:GameAppId)

        If (!$WorkshopDir.Exists) {
            Write-Log ERROR "Unable to locate $Global:GameNameShort Workshop Directory '$($WorkshopDir.FullName)'."
            If (!$Root.IsPresent) {Throw [IO.DirectoryNotFoundException]::New("Unable to locate $Global:GameNameShort Workshop Directory '$($WorkshopDir.FullName)'.")}
        }
        Else {Write-Log INFO "Successfully Located $Global:GameNameShort Workshop Direcory at: '$($WorkshopDir.FullName)'."}
        
        # If the user provided -Workshop, return the workshop directory
        If ($Workshop.IsPresent) {Return $WorkshopDir}

        # Otherwise the user must have provided -Root, so we locate and return the game's root/install directory
        [IO.FileInfo]$AppManifestAcf = [IO.Path]::Combine($SteamApps.FullName, "appmanifest_$Global:GameAppid.acf")

        If (!$AppManifestAcf.Exists) {
            Write-Log ERROR "Unable to locate $Global:GameNameShort App Manifest ACF '$($AppManifestAcf.FullName)'."
            If (!$Workshop.IsPresent) {Throw [IO.FileNotFoundException]::New("Unable to locate $Global:GameNameShort App Manifest ACF '$($AppManifestAcf.FullName)'.")}
        }
        Else {Write-Log INFO "Performing Game Root Directory Lookup in $Global:GameNameShort App Manifest ACF ('$($AppManifestAcf.FullName)')."}

        [String[]]$AppCacheData = Get-FileContent $AppManifestAcf
        ForEach ($Line in $AppCacheData) {If ($Line -Match $InstallDirPattern) {[String]$InstallDir = [IO.Path]::Combine($SteamApps.FullName, 'common', $($Matches[0])); Break}}
        
        [IO.DirectoryInfo]$RootDir = $InstallDir

        If (!$RootDir.Exists) {
            Write-Log ERROR "Unable to locate $Global:GameNameShort Game Root Directory '$($RootDir.FullName)'."
            If (!$Workshop.IsPresent) {Throw [IO.DirectoryNotFoundException]::New("Unable to locate $Global:GameNameShort Game Root Directory '$($RootDir.FullName)'.")}
        }
        Else {Write-Log INFO "Successfully Located $Global:GameNameShort Game Root Directory at '$($RootDir.FullName)'."}

        If ($Root.IsPresent) {Return $RootDir}

        Return [IO.DirectoryInfo[]]@($RootDir, $WorkshopDir)
    }

    Function Get-ProfileUnitFormat {
        [CmdletBinding()]
        [OutputType([String])]

        Param ([IO.FileInfo]$Target = $Global:TempProfileUnit)

        Write-Log INFO "Received Format detection request for '$($Target.FullName)'."

        [Collections.Generic.List[Byte]]$UnitData = [IO.File]::ReadAllBytes($Target.FullName)
        [String]$UnitFormat                       = ('Text', 'Binary')[$UnitData.Contains([Byte]0)]

        Switch ($UnitFormat) {
            'Binary' {Write-Log INFO "Null-byte detected in '$($Target.Name)' contents. Assuming binary format."; Break}
            'Text'   {Write-Log INFO "No null-bytes detected in '$($Target.Name)' contents. Assuming text format."; Break}
            Default  {
                Write-Log ERROR "Unable to determine format of '$($Target.Name)' - Unexpected format '$UnitFormat'"
                Throw "Unable to determine format of '$($Target.Name)' - Unexpected format '$UnitFormat'"
            }
        }

        Return $UnitFormat
    }

    Function Get-GameUnitDecoder {
        [CmdletBinding()]
        [OutputType([IO.FileInfo])]

        Param ([String]$DecFile = $Global:RepositoryInfo.DecFile)

        Write-Log INFO "Received Game Unit Decoder '$DecFile' request."

        [IO.FileInfo]$Path = "$Env:Temp\$DecFile"
        [String]$Checksum  = (Get-ModRepoFile $Global:RepositoryInfo.DecHash -UseIwr).Content
        Write-Log INFO "Expected FileHash for '$DecFile' is: '$Checksum'."

        If (!$Path.Exists) {
            Write-Log INFO "Decoder not found at '$($Path.FullName)'. Downloading from repository."
            If ($Global:OfflineMode) {
                Write-Log ERROR "$($Global:ScriptDetails['ShortTitle']) is running in Offline Mode. Unable to download file '$DecFile'."
                Throw 'Offline mode is enabled. Unable to download files.'
            }

            [IO.File]::WriteAllBytes($Path.FullName, [Byte[]](Get-ModRepoFile $DecFile -UseIwr).Content)
            Write-Log INFO "Game Unit Decoder downloaded and saved to '$($Path.FullName)'."
        }

        If (!(Test-FileHash $Path.FullName $Checksum)) {
            Write-Log ERROR "'$DecFile' failed to validate - FileHash mismatch. The file will be deleted."

            $Path.Delete()

            Throw "Failed to validate '$DecFile' - Checksum mismatch"
        }
        Write-Log INFO 'Game Unit Decoder is ready.'

        Return $Path
    }

    Function Get-ModData {
        [CmdletBinding()]
        [OutputType([Hashtable])]

        Param ([String[]]$RawData)

        Write-Log INFO 'Received mod data parse request.'

        If (!$RawData) {Write-Log WARN 'Nothing to parse. Returning @{}.'; Return @{}}

        [Hashtable]$ParsedData = @{}
        [String[]]$Data        = ($RawData, ($RawData[0] -Split "`n"))[$RawData.Count -eq 1 -And [Char[]]$RawData[0] -Contains "`n"]

        ForEach ($Entry in $Data) {
            If ($Entry -Match '^ active_mods: \d+$') {Continue}

            [String]$Priority               = Switch (($Entry -Split '\[|\]', 3)[1]) {{$_ -As [UInt16] -eq $_} {$_} Default {Continue}}
            [String]$Source, [String]$Name  = Switch ((($Entry -Split '\[\d+\]: ', 2)[-1] -Split '\|', 2).Trim('"')) {{$_ -As [String[]] -eq $_} {$_}}
            $ParsedData["active_$Priority"] = ConvertFrom-ActiveModEntry $Source $Name
        }
        Write-Log INFO "Parsed $($ParsedData.Keys.Count) mod data entries."

        Return $ParsedData
    }

    Function Install-CoreMod { # TODO: Not yet implemented
        [CmdletBinding()]
        Param ()
        Return
    }

    Function Read-PlainTextProfileUnit {
        [CmdletBinding()]
        [OutputType([String[]], [String[][]])]

        Param (
            [ValidateSet('Mods', 'Data', 'All')][String]$Return = 'All',
            [Switch]$Raw,
            [Switch]$Direct
        )

        Write-Log INFO 'Received Profile Data request.'

        [Bool]$Parse        = $False
        [String[]]$UnitMods = @()
        [String[]]$UnitData = @()
        [IO.FileInfo]$File  = ($Global:TempProfileUnit, $Global:ProfileUnit)[$Direct.IsPresent]
        Write-Log INFO "$(('Using TempProfileUnit', "'-Direct' specified - Using ProfileUnit")[$Direct.IsPresent]) as source profile ('$($File.FullName)')."

        ForEach ($Line in Get-FileContent $File) {
            If ($Parse -And $Line -Match '^ customization: \d+$') {
                $Parse     = $False
                $UnitData += '<MODLIST_INSERTION_POINT>'
            }
            ElseIf ($Line -Match '^ active_mods: \d+$') {$Parse = $True}

            If ($Parse) {$UnitMods += $Line} Else {$UnitData += $Line}
        }
        Write-Log INFO "Parsed $($UnitMods.Count) active mod entries. Returning $Return."

        If ($Raw.IsPresent) {
            [String]$UnitMods = $UnitMods -Join "`n"
            [String]$UnitData = $UnitData -Join "`n"
        }
        Return (($UnitMods, $UnitData), $UnitMods, $UnitData)[('All', 'Mods', 'Data').IndexOf($Return)]        
    }

    Function Edit-ProfileLoadOrder {
        [CmdletBinding()]
        [OutputType([Void])]

        Param ([IO.FileInfo]$ProfileUnit = $Global:ProfileUnit)

        Write-Log INFO "Reveiced Load order configuration request for '$($ProfileUnit.Name)'."

        Write-Host ('║ Configuring load order...'.PadRight($UIRowLine.Length - 1) + '║')

        If ($Global:GameProcess -In (Get-Process).Name) {
            Write-Log WARN 'Game is running. Aborted load order configuration.'
            Write-Host -NoNewline '║ '
            Write-Host -NoNewline -ForegroundColor Yellow "$Global:GameName must be closed in order to apply load order.".PadRight($UIRowLine.Length - 3)
            Write-Host '║'
            Return
        }
        Else {Write-Log INFO 'Profile Unit is clear. Proceeding with load order configuration.'}

        Write-Host -NoNewline '║    '
        Write-Host -NoNewline -ForegroundColor Green "$Global:LoadOrder - $Global:ActiveModsCount active mods".PadRight($UIRowLine.Length - 6)
        Write-Host '║'

        Write-Log INFO 'Preparing Profile reconfiguration.'
        [String]$ProfileFormat = Get-ProfileUnitFormat $ProfileUnit

        If ($ProfileFormat -ne 'Text') {
            Write-Host -NoNewline ('║'.PadRight($UIRowLine.Length - 1) + '║')
            [Console]::SetCursorPosition(5, [Console]::CursorTop)
            Write-Host -NoNewline ('Decoding profile...'.PadRight(35))
            ConvertTo-PlainTextProfileUnit
            Write-Host -ForegroundColor Green 'OK'
        }

        [String[]]$ProfileMods, [String[]]$ProfileData = Read-PlainTextProfileUnit All -Direct:($ProfileFormat -eq 'Text')
        [String]$RawProfileMods                        = $ProfileMods -Join "`n"
        [UInt16]$ProfileModsCount                      = ($ProfileMods[0] -Split ':', 2)[-1].Trim()

        If ($RawProfileMods -cne $Global:LoadOrderText) {
            Write-Log INFO "Profile Unit mod list does not match active load order ($ProfileModsCount > $Global:ActiveModsCount). Proceeding."

            If ($Global:ProfileBackups) {
                Write-Host -NoNewline ('║'.PadRight($UIRowLine.Length - 1) + '║')
                [Console]::SetCursorPosition(5, [Console]::CursorTop)
                Write-Host -NoNewline ('Creating profile backup...'.PadRight(35))
                
                [IO.FileInfo]$Backup = Backup-ProfileUnit

                Write-Host -ForegroundColor Green "OK - $($Backup.Name)"
            }
            Else {Write-Log INFO 'Profile backups are disabled - Skipping profile backup.'}

            Write-Host -NoNewline ('║'.PadRight($UIRowLine.Length - 1) + '║')
            [Console]::SetCursorPosition(5, [Console]::CursorTop)
            Write-Host -NoNewline ('Applying load order...'.PadRight(35))
            Write-Log INFO "Applying active load order ($Global:LoadOrder) to profile '$($ProfileUnit.Name)'."

            If ($ProfileFormat -ne 'Text') {ConvertTo-PlainTextProfileUnit -OnFile}
            [String]$ProfileRaw = $ProfileData -Join "`n" -Replace '<MODLIST_INSERTION_POINT>', $Global:LoadOrderText
            Set-Utf8Content $ProfileUnit $ProfileRaw -NoNewline

            Write-Log INFO "Load order applied successfully. $ProfileModsCount > $Global:ActiveModsCount"
            Write-Host -ForegroundColor Green "OK - $ProfileModsCount > $Global:ActiveModsCount"
        }
        Else {
            Write-Log INFO 'Load order already applied.'
            Write-Host -NoNewline ('║'.PadRight($UIRowLine.Length - 1) + '║')
            [Console]::SetCursorPosition(5, [Console]::CursorTop)
            Write-Host -ForegroundColor Green 'Already applied'
        }

        Write-Log INFO 'Checking Workshop subscriptions.'
        [Collections.Generic.List[String]]$MissingWorkshopMods = [Collections.Generic.List[String]]::New()
        ForEach ($Item in $Global:LoadOrderData.GetEnumerator()) {
            [Hashtable]$Current = $Item.Value
            If ($Current.Type -ne 'Workshop') {Continue}

            If (!(Test-WorkshopModInstalled $Current.SourcePath)) {

                Write-Log WARN "Missing workshop subscription: $($Current.Name)"
                Write-Host -NoNewline ('║'.PadRight($UIRowLine.Length - 1) + '║')
                [Console]::SetCursorPosition(5, [Console]::CursorTop)
                Write-Host -ForegroundColor Yellow ('MISSING WORKSHOP SUBSCRIPTION: ' + $Current.Name)

                $MissingWorkshopMods.Add($Current.SourceName)
            }
            Else {Write-Log INFO "Workshop mod '$($Current.Name)' OK."}
        }
        If ($MissingWorkshopMods) {
            Write-Host -NoNewline ('║'.PadRight($UIRowLine.Length - 1) + '║')
            [Console]::SetCursorPosition(2, [Console]::CursorTop)
            Do {[Byte]$UserInput = Read-KeyPress 'Open Workshop item page in Steam? [Y/N]' -Clear} Until ($UserInput -In [Byte[]][Char[]]'YN')
            
            Switch ($UserInput) {
                ([Byte][Char]'Y') {
                    ForEach ($Mod in $MissingWorkshopMods) {
                        Write-Host -NoNewline ('║'.PadRight($UIRowLine.Length - 1) + '║')
                        [Console]::SetCursorPosition(2, [Console]::CursorTop)
                        Start-SteamWorkshopPage $Mod
                        [Void](Read-KeyPress 'Press any key to continue...' -Clear)
                    }
                }
                ([Byte][Char]'N') {Break}
            }
        }
    }

    Function Backup-ProfileUnit {
        [CmdletBinding()]
        [OutputType([IO.FileInfo])]

        Param ([IO.FileInfo]$ProfileUnit = $Global:ProfileUnit)

        Write-Log INFO 'Received profile backup request.'

        [String]$Name            = 'profile_' + [DateTime]::Now.ToString('yy-MM-dd_HHmmss')
        [IO.FileInfo]$BackupFile = $Global:ProfileUnit.CopyTo("$($Global:ProfilePath.FullName)\$Name.bak")

        Write-Log INFO "Profile backup created: $($BackupFile.Name)"

        Return $BackupFile
    }

    Function Export-LoadOrder {
        [CmdletBinding()]
        [OutputType([Void])]

        Param ([IO.FileInfo]$ProfileUnit = $Global:ProfileUnit)

        Write-Log INFO 'Received active load order export request.'

        [IO.FileInfo]$SaveTarget = Get-FilePathByDialog -Save 'Save load order as...' 'Load order file (*.order)|*.order|All files (*.*)|*.*' 'MyLoadOrder.order'

        #TODO: Implement checks for successful export
        If (![String]::IsNullOrWhiteSpace($SaveTarget)) {
            Try {
                Write-Log INFO "Preparing active profile ('$Global:ActiveProfileName') for load order export."
                [String]$ProfileFormat = Get-ProfileUnitFormat $ProfileUnit

                If ($ProfileFormat -ne 'Text') {ConvertTo-PlainTextProfileUnit}

                [String]$ProfileMods = Read-PlainTextProfileUnit Mods -Raw -Direct:($ProfileFormat -eq 'Text')
                Write-Log INFO "Writing load order of $(($ProfileMods -Split "`n").Count) mods to '$($SaveTarget.FullName)'."
                Set-Utf8Content $SaveTarget $ProfileMods -NoNewline

                Write-Log INFO 'Verifying export.'
                [String]$SavedData           = Get-FileContent $SaveTarget -Raw
                [String[]]$FormatTestResults = Test-LoadOrderFormat $SavedData -ContinueOnError -ReturnInfo

                If ($FormatTestResults)          {Throw "$($FormatTestResults -Join "`n")"}
                If ($SavedData -ne $ProfileMods) {Throw 'Failed to export load order'}

                Write-Log INFO "Load order for active profile '$Global:ActiveProfileName' successfully exported to '$($SaveTarget.FullName)'"
                [Void][Windows.MessageBox]::Show("Success!`n`nExported load order from active profile `"$Global:ActiveProfileName`"`nto:`n$($SaveTarget.FullName)", 'Export successful', 0, 64)
            }
            Catch {
                Write-Log ERROR "An error occurred while exporting the load order of profile '$Global:ActiveProfileName': $($_.Exception.Message)"
                Format-AndExportErrorData $_
                [Void][Windows.MessageBox]::Show("An error occurred while exporting the load order from profile`n`"$Global:ActiveProfileName`"`n$($_.Exception.Message)", 'Export failed', 0, 16)
            }
        }
    }

    Function Move-SelfToModDirectory {
        [CmdletBinding()]
        [OutputType([Bool])]

        Param ()

        Write-Log INFO 'Received self-move request.'

        #TODO: Fix this
        # ^ ?????? fix what?
        [IO.DirectoryInfo]$SelfPath = $MyInvocation.MyCommand.Path
        [String]$SelfName           = [IO.Path]::GetFileName($SelfPath)
        [IO.FileInfo]$ModPath       = "$($Global:GameModDirectory.FullName)\$SelfName"

        Try {
            If (!$ModPath.Exists) {
                $SelfPath.MoveTo($ModPath.FullName)
                Write-Log INFO "Successfully moved self ('$($SelfPath.FullName)\$SelfName') to mod directory '$($ModPath.FullName)'"
            }
        
            [Console]::SetCursorPosition(1, 10)
            Write-HostX 1 -Color Yellow (' ' * [Math]::Max(0, [Console]::BufferWidth - 1))

            [Console]::SetCursorPosition(1, 10)
            Write-Host -ForegroundColor Black -BackgroundColor Yellow (' ' * [Math]::Max(0, [Console]::BufferWidth - 1))

            Write-Log INFO 'Executing script from new directory.'
            Start-Process (Get-Process -Id $Pid).MainModule.ModuleName -ArgumentList "-ExecutionPolicy Bypass -File `"$($ModPath.FullName)`""

            Write-Log INFO 'Exiting session.'
            Return $True
        }
        Catch {
            Write-Log ERROR "Failed to move self to mod directory: $($_.Exception.Message)"
            Return $False
        }
    }

    Function Import-LoadOrder {
        [CmdletBinding()]
        [OutputType([IO.FileInfo], [String])]

        Param ()

        Write-Log INFO 'Received load order import request.'

        Write-Log INFO 'Displaying file selection dialog.'
        [IO.FileInfo]$InFile = Get-FilePathByDialog -Open 'Import load order' 'Load order file (*.order)|*.order|All files (*.*)|*.*'
        Clear-Host

        If ($InFile) {
            Write-Log INFO "File '$($InFile.FullName)' selected for import."
            Return $InFile
        }
        Else {
            Write-Log INFO 'No file selected for import. Selecting current load order for import.'
            Return $Global:LoadOrder
        }
    }

    Function Select-Profile {
        [CmdletBinding()]
        [OutputType([String])]

        Param ([Switch]$AllowEsc)

        Write-Log INFO 'Received profile selection request.'

        [String[]]$AllProfiles = (Get-ChildItem "$($Global:GameRootDirectory.FullName)\profiles" -Directory).Name | Sort-Object Length

        Write-Log INFO 'Displaying profile selection menu.'

        Clear-Host
        Write-Host ' SELECT PROFILE'
        Write-Host ($Global:UiLine * [Console]::BufferWidth)

        If (!$AllProfiles) {
            Write-Log WARN 'No profiles detected. Aborting profile selection.'
            Throw 'No profiles detected! Disable ''Use Steam Cloud'' for the profile(s) you want to use.'
        }
        If ($AllProfiles.Count -eq 1) {
            Set-ActiveProfile $AllProfiles[0]
            [String]$ProfileName = Convert-ProfileFolderName $AllProfiles[0]

            Write-Log INFO "Singular profile detected. Profile '$($AllProfiles[0])' ($ProfileName) automatically applied as active profile."
            Write-Host -ForegroundColor Green "$Global:GameNameShort Profile '$ProfileName' was automatically selected as the active profile."
            Start-Sleep 2

            Return $AllProfiles[0]
        }

        [UInt16]$LongestDir                               = $AllProfiles[-1].Length + 3
        [Byte]$Selected                                   = (0, $AllProfiles.IndexOf($Global:ActiveProfile))[$Global:ActiveProfile -In $AllProfiles]
        [String]$PreviousProfile                          = $Global:ActiveProfile
        [Management.Automation.Host.Coordinates]$StartPos = $Host.UI.RawUI.CursorPosition

        Do {
            $Host.UI.RawUI.CursorPosition = $StartPos
            [Byte]$Iteration              = 0

            ForEach ($Directory in $AllProfiles) {
                [String]$Name     = Convert-ProfileFolderName $Directory
                [Bool]$IsSelected = $Iteration -eq $Selected

                Write-Host -NoNewline ' '
                Write-HostX 0 -Color ('DarkGray', 'Green')[$IsSelected] (' ' + ('   ', '>> ')[$IsSelected] + $Directory.PadRight($LongestDir) + "$Name ") -Newline
                $Iteration++
            }
            Write-Ansi "`n * Use the <cyan>[UP]</cyan> and <cyan>[DOWN]</cyan> keys to select an $Global:GameNameShort profile.`n   Press <cyan>[ENTER]</cyan> to confirm your selection" -NoNewline
            <#Write-Host -NoNewline -ForegroundColor Cyan '[UP]'
            Write-Host -NoNewline ' and '
            Write-Host -NoNewline -ForegroundColor Cyan '[DOWN]'
            Write-Host -NoNewline " keys to select an $Global:GameNameShort profile.`n   Press "
            Write-Host -NoNewline -ForegroundColor Cyan '[ENTER]'
            Write-Host -NoNewline ' to confirm your selection'#>
            If ($AllowEsc.IsPresent) {
                Write-Ansi ", or <cyan>[ESC]</cyan> to cancel."
                <#Write-Host -NoNewline ', or '
                Write-Host -NoNewline -ForegroundColor Cyan '[ESC]'
                Write-Host ' to cancel.'#>
            }
            Else {Write-Host '.'}

            [String]$SelectedProfile = $AllProfiles[$Selected]

            Do {
                [Bool]$UpdateSelection = $False
                Switch (Read-KeyPress) {
                    13 { # [ENTER]
                        Clear-Host
                        If ($SelectedProfile -ne $PreviousProfile) {
                            Set-ActiveProfile $SelectedProfile
                            Return $SelectedProfile
                        }
                        Return
                    }
                    27 { # [ESC]
                        If (!$AllowEsc.IsPresent) {Continue}
                        Clear-Host
                        Return
                    }
                    38 { # [UP]
                        If ($Selected -gt 0) {$Selected--} Else {[Console]::Beep(1000, 150)}
                        $UpdateSelection = $True
                        Break
                    }
                    40 { # [DOWN]
                        If ($Selected -lt $AllProfiles.Count - 1) {$Selected++} Else {[Console]::Beep(1000, 150)}
                        $UpdateSelection = $True
                        Break
                    }
                    Default {Continue}
                }
            } Until ($UpdateSelection)
        } While ($True)
    }

    Function Get-ActiveProfile {
        [CmdletBinding()]
        [OutputType([String])]

        Param ()

        Write-Log INFO 'Received active profile request.'

        [UInt16]$TargetIndex   = ($Global:DataIndices.ActiveProfile.Index, $Global:DataIndices.ActiveAtsProfile.Index)[$Global:TargetGame -eq 'ATS']
        [String]$StoredProfile = Read-EmbeddedValue $TargetIndex

        If ($StoredProfile -eq '***GAME_PROFILE_PLACEHOLDER***' -Or [String]::IsNullOrWhiteSpace($StoredProfile) -Or ![IO.Directory]::Exists("$($Global:GameRootDirectory.FullName)\profiles\$StoredProfile")) {$StoredProfile = Select-Profile}
        
        Return $StoredProfile
    }

    Function Set-ActiveProfile {
        [CmdletBinding()]
        [OutputType([Void])]

        Param ([Parameter(Mandatory)][String]$Directory)

        Write-Log INFO 'Received active profile change request.'

        [UInt16]$TargetIndex = ($Global:DataIndices.ActiveProfile.Index, $Global:DataIndices.ActiveATSProfile.Index)[$Global:TargetGame -eq 'ATS']
        If ($Directory -ne $Global:ActiveProfile) {
            Write-EmbeddedValue $TargetIndex $Directory
            Write-Log INFO "Active profile changed from '$Global:ActiveProfile' to '$Directory'. Executing script restart routine."

            $GLOBAL:ScriptRestart = $True
            [Void]$GLOBAL:ScriptRestart
        }
    }

    Function Start-DefaultWebBrowser { # This function is deprecated and will be removed in a future version
        [CmdletBinding()]
        [OutputType([Void])]

        Param ([Parameter(Mandatory)][String]$Uri)

        [String]$BrowserName = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice).ProgId
        If ($BrowserName -eq 'AppXq0fevzme2pys62n3e0fbqa7peapykr8v') {Start-Process Microsoft-Edge:$Uri}
        Else {
            [Void](New-PSDrive HKCR Registry HKEY_CLASSES_ROOT -Scope Global -EA 0)
            [String]$BrowserPath = [Regex]::Match((Get-ItemProperty HKCR:\$BrowserName\shell\open\command).'(default)', '\".+?\"')

            Start-Process $BrowserPath $Uri
        }
    }

    Function Start-SteamWorkshopPage {
        [CmdletBinding()]
        [OutputType([Void])]

        Param ([Parameter(Mandatory)][String]$FileId)

        Start-Process "steam://url/CommunityFilePage/$FileId"

        Write-Log INFO "Opened Steam Workshop page for '$FileId'."
    }

    Function Show-LandingScreen {
        [CmdletBinding()]
        [OutputType([Void])]
        
        Param ([UInt16]$Timeout = 3)

        Write-Host ($Global:UiLine * [Console]::BufferWidth)
        Write-Host "`n$Global:UiTab$($Global:ScriptDetails.Title)`n"
        Write-Host "$Global:UiTab$($Global:ScriptDetails.Version), Updated $($Global:ScriptDetails.VersionDate)"
        Write-Host "$Global:UiTab$($Global:ScriptDetails.Copyright) - $($Global:ScriptDetails.Author)`n"

        [Void](Read-KeyPress ' Continuing in <n> seconds. Press any key to skip...' -TimerAt '<n>' -Timeout $Timeout -Clear)
    }

    Function Invoke-Menu {
        [CmdletBinding()]
        [OutputType([String])]

        Param ([Switch]$Saved)

        Write-Log INFO 'Received menu display request.'
        
        [Byte]$UiLineWidth      = 100
        [String]$SetAndContinue = '; Update-ProtectedVars; $Save = $False; Continue'
        [String]$OrderRunText   = 'Update active mods'
        [String]$AllRunText     = 'Update all mods'
        If ($Global:ValidateInstall) {
            $OrderRunText += ' + verify integrity'
            $AllRunText   += ' + verify integrity'
        }
        If ($Global:DeleteDisabled)  {$OrderRunText += " + delete $Global:DdSel inactive mods"}
        If ($Global:NoProfileConfig) {
            $OrderRunText += ' + skip load order config'
            $AllRunText   += ' + skip load order config'
        }
        If ($Global:StartGame) {
            $OrderRunText += " + launch $Global:GameNameShort"
            $AllRunText   += " + launch $Global:GameNameShort"
            If ($Global:StartSaveEditor -And $Global:TsseTool.Installed) {
                $OrderRunText += " + launch $($Global:TsseTool.Name)"
                $AllRunText   += " + launch $($Global:TsseTool.Name)"
            }
            ElseIf ($Global:StartSaveEditor -And !$Global:TsseTool.Installed) {
                Write-Log WARN "Override triggered for option '$StartSaveEditor' (Launch $($Global:TsseTool.Name)): $($Global:TsseTool.Name) is not installed."
                $Global:StartSaveEditor = $False
            }
        }
        [Byte]$ActiveDataPadding = ("Active $Global:GameNameShort profile: ", 'Active load order: ' | Sort-Object Length)[-1].Length
        [String]$UiSeparator     = $Global:UiTab + $Global:UiLine * $UiLineWidth
        [Console]::SetCursorPosition(0, 0)
        Write-Log INFO 'Formatted menu entries and options.'

        Write-Log INFO 'Displaying menu header.'

        [String]$MenuHeadTxt = "    $($Global:ScriptDetails.Title)   $($Global:ScriptDetails.Version)"
        $MenuHeadTxt         = $MenuHeadTxt + (' ' * ($UiSeparator.Length - $MenuHeadTxt.Length))
        Write-Ansi " <Cyan><BBlu>$MenuHeadTxt" -Indent 1

        Write-HostFancy $UiSeparator

        Write-Ansi ("`n$Global:UiTab" + "Active $Global:GameNameShort profile: ".PadRight($ActiveDataPadding) + "<Green>$Global:ActiveProfileName<R>")
        
        Write-Ansi ("$Global:UiTab" + 'Active load order: '.PadRight($ActiveDataPadding) + "<Green>$Global:LoadOrder<R>")

        Write-HostFancy "`n$UiSeparator`n"

        Write-HostFancy " $Global:UiTab[PGUP]    Show $(('secondary', 'primary')[$Global:MenuToggle]) menu options" -Fg ('DarkCyan', 'White')[$Global:MenuToggle]
        
        If (!$Global:MenuToggle) {
            Write-Log INFO 'Displaying primary menu options.'

            Write-HostFancy "`n$UiSeparator`n"

            Write-HostFancy " $Global:UiTab[1]       Launch $Global:GameName upon completion`n" -Fg ([Console]::ForegroundColor, 'Green')[$Global:StartGame]
            Write-HostFancy " $Global:UiTab[$((' ', 2)[$Global:TsseTool.Installed])]       Launch $($Global:TsseTool.Name) with $Global:GameName" -Fg ('DarkGray', ([Console]::ForegroundColor, 'Green')[$Global:StartSaveEditor])[$Global:TsseTool.Installed]

            Write-HostFancy "`n$UiSeparator`n"

            Write-HostFancy " $Global:UiTab[3]       Delete$((' managed', ' ALL', ' managed')[$Global:DdSel]) mods not in the active load order ([TAB] will override this option)`n" -Fg ([Console]::ForegroundColor, 'DarkGray')[$Global:OfflineMode]
            Write-HostFancy " $Global:UiTab[4]       Verify game file integrity (Forces Steam Workshop mod updates)`n"
            Write-HostFancy " $Global:UiTab[5]       Skip profile load order configuration ([SPACE] will override this option)" -Fg ([Console]::ForegroundColor, 'DarkGray')[$Global:OfflineMode]
           
            Write-HostFancy "`n$UiSeparator`n"

            Write-HostFancy " $Global:UiTab[6]       Save current options $(('', '[SAVED]')[$Saved.IsPresent])" -Fg ([Console]::ForegroundColor, 'Green')[$Saved.IsPresent]

            Write-HostFancy "`n$UiSeparator`n"
        }
        Else {
            Write-Log INFO 'Displaying secondary menu options.'

            Write-HostFancy "`n$UiSeparator`n" -Fg DarkCyan

            Write-HostFancy "      $Global:UiTab[1]       Switch to $(('ETS2', 'ATS')[$Global:GameNameShort -eq 'ETS2']) mode`n" -Fg DarkCyan

            Write-HostFancy "      $Global:UiTab[2]       Change repository URL`n" -Fg DarkCyan
            Write-HostFancy "      $Global:UiTab[3]       $(('Enable', 'Disable')[$Global:ProfileBackups]) automatic profile backups" -Fg DarkCyan

            Write-HostFancy "`n$UiSeparator`n" -Fg DarkCyan

            Write-HostFancy "      $Global:UiTab[4]       $(('Enable', 'Disable')[$Global:LogRetention]) log retention`n" -Fg DarkCyan
            Write-HostFancy "      $Global:UiTab[5]       Set log retention time (Current: $(("$Global:LogRetentionDays days", 'Retain most recent only')[$Global:LogRetentionDays -eq 0]))" -Fg ('DarkGray', 'DarkCyan')[$Global:LogRetention]
            
            Write-HostFancy "`n$UiSeparator`n" -Fg DarkCyan

            Write-HostFancy "      $Global:UiTab[6]       Set draw frequency for transfer rate display (Current: $Global:DrawFrequency ms)" -Fg DarkCyan

            Write-HostFancy "`n$UiSeparator`n" -Fg DarkCyan
        }

        Write-HostFancy " $Global:UiTab[7]       Export load order from active profile`n"
        Write-HostFancy " $Global:UiTab[8]       Import custom load order"

        Write-HostFancy "`n$UiSeparator`n"

        Write-HostFancy " $Global:UiTab[9]       Change load order`n" -Fg ([Console]::ForegroundColor, 'DarkGray')[$Global:OfflineMode]
        Write-HostFancy " $Global:UiTab[0]       Change profile"

        Write-HostFancy "`n$UiSeparator`n"

        Write-HostFancy " $Global:UiTab[ESC]     Exit"

        Write-HostFancy "`n$UiSeparator`n"

        Write-HostFancy " $Global:UiTab[SPACE]   Configure profile load order ONLY`n"
        Write-HostFancy " $Global:UiTab[ENTER]   $OrderRunText" -Fg ([Console]::ForegroundColor, 'DarkGray')[$Global:OfflineMode]
        Write-HostFancy " $Global:UiTab[TAB]     $AllRunText" -Fg ([Console]::ForegroundColor, 'DarkGray')[$Global:OfflineMode]
        Write-HostFancy "`n$UiSeparator"

        If ($Global:DeleteDisabled) {Write-HostFancy "`n   $($Global:UiTab)WARNING: Deleted mods must be reaquired if reactivated in the future." -Fg Yellow}

        While ($True) {
            [Byte]$Choice = Read-KeyPress
            # KEY    CODE  DESCRIPTION
            # PGUP  / 33 - Toggle primary/secondary menu
            #--------------------- PRIMARY MENU
            # TAB   / 9  - Execute (Update all mods)
            # ENTER / 13 - Execute (Update based on load order only)
            # ESC   / 27 - Exit
            # SPACE / 32 - No update
            # 0     / 48 - Change profile
            # 1     / 49 - Start game
            # 2     / 50 - Start save editor
            # 3     / 51 - Delete inactive mods
            # 4     / 52 - Validate install
            # 5     / 53 - Skip load order config
            # 6     / 54 - Save options
            # 7     / 55 - Export load order
            # 8     / 56 - Import load order
            # 9     / 57 - Change load order
            #--------------------- SECONDARY MENU
            # 1     / 49 - Switch target game
            # 2     / 50 - Set Repository URL
            # 3     / 51 - Toggle auto backups
            # 4     / 52 - Toggle log retention
            # 5     / 53 - Set log retention time
            # 6     / 54 - Set draw frequency
            Switch ($Choice) {
                33 { # [PGUP]
                    Write-Log INFO "$_ : [PGUP] ('Toggle primary/secondary menu') selected."
                    Return '$Global:MenuToggle = !$Global:MenuToggle' + $SetAndContinue
                }
                9 { # [TAB]
                    Write-Log INFO "$_ : [TAB] ('Execute (Update all)') selected."
                    If ($Global:OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                    Return '$Global:UpdateAll = $True; Update-ProtectedVars; Break'
                }
                13 { # [ENTER]
                    Write-Log INFO "$_ : [ENTER] ('Execute (Update active)') selected."
                    If ($Global:OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                    Return 'Break'
                }
                27 { # [ESC]
                    Write-Log INFO "$_ : [ESC] ('Exit') selected."
                    Return 'Exit'
                }
                32 { # [SPACE]
                    Write-Log INFO "$_ : [SPACE] ('Configure load order only') selected."
                    If ($Global:OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                    Return '$Global:NoUpdate = $True; Update-ProtectedVars; Break'
                }
                48 { # [0]
                    If (!$Global:MenuToggle) {
                        Write-Log INFO "$_ : [0] ('Change profile') selected."
                        If (!(Select-Profile -AllowEsc)) {Return 'Continue'}
                        Else {Return 'Unprotect-Variables; $GLOBAL:ScriptRestart = $True; Return "Menu"'}
                    }
                    Else {Write-Log WARN "Aborted: No action for '$_' in secondary menu."; Break}
                }
                49 { # [1]
                    If (!$Global:MenuToggle) {
                        Write-Log INFO "$_ : [1] ('Start game') selected."
                        Return '$Global:StartGame = !$Global:StartGame' + $SetAndContinue
                    }
                    Else {
                        Write-Log INFO "$_ : [1] ('Switch target game') selected."
                        Return [String](@(
                            '$Global:TargetGame = ("ATS", "ETS2")[$Global:TargetGame -eq "ATS"]',
                            'Write-EmbeddedValue $Global:DataIndices.TargetGame.Index $Global:TargetGame',
                            'Unprotect-Variables',
                            '$Global:ScriptRestart = $True',
                            'Return "Menu"'
                        ) -Join '; ')
                    }
                }
                50 { # [2]
                    If (!$Global:MenuToggle) {
                        If (!$Global:TsseTool.Installed) {
                            Write-Log WARN "Aborted: Choice invalid as $($Global:TsseTool.Name) is not installed."
                            Return '$Global:StartSaveEditor = $False' + $SetAndContinue
                        }
                        Write-Log INFO "$_ : [2] ('Start save editor') selected."
                        Return '$Global:StartSaveEditor = $Global:StartGame -And !$Global:StartSaveEditor' + $SetAndContinue
                    }
                    Else {
                        Write-Log INFO "$_ : [2] ('Set Repository URL') selected."
                        Return '$Global:RepositoryUrl, $Global:RepositoryInfo, $_X = Set-RepositoryUrl -AllowCancel' + $SetAndContinue
                    }
                }
                51 { # [3]
                    If (!$Global:MenuToggle) {
                        Write-Log INFO "$_ : [3] ('Delete inactive mods') selected."
                        If ($Global:OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                        Return '$Global:DdSel = ($Global:DdSel + 1) % 3; $Global:DeleteDisabled = $Global:DdSel -ne 0;' + $SetAndContinue
                    }
                    Else {
                        Write-Log INFO "$_ : [3] ('Toggle auto backups') selected."
                        Return '$Global:ProfileBackups = !$Global:ProfileBackups' + $SetAndContinue
                    }
                }
                52 { # [4]
                    If (!$Global:MenuToggle) {
                        Write-Log INFO "$_ : [4] ('Validate install') selected."
                        Return '$Global:ValidateInstall = !$Global:ValidateInstall' + $SetAndContinue
                    }
                    Else {
                        Write-Log INFO "$_ : [4] ('Toggle log retention') selected."
                        Return '$Global:LogRetention = !$Global:LogRetention' + $SetAndContinue
                    }
                }
                53 { # [5]
                    If (!$Global:MenuToggle) {
                        Write-Log INFO "$_ : [5] ('Skip load order config') selected."
                        If ($Global:OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                        Return '$Global:NoProfileConfig = !$Global:NoProfileConfig' + $SetAndContinue
                    }
                    Else {
                        Write-Log INFO "$_ : [5] ('Set log retention time') selected."
                        Return '$Global:LogRetentionDays = Set-LogRetentionTime' + $SetAndContinue
                    }
                }
                54 { # [6]
                    If (!$Global:MenuToggle) {
                        Write-Log INFO "$_ : [6] ('Save options') selected."
                        Return 'Write-AllEmbeddedValues; $Save = $True; Continue'
                        Write-AllEmbeddedValues
                    }
                    Else {
                        Write-Log INFO "$_ : [6] ('Set draw frequency') selected."
                        Return '$Global:DrawFrequency = Set-DrawFrequency' + $SetAndContinue
                    }
                }
                55 { # [7]
                    If (!$Global:MenuToggle) {
                        Write-Log INFO "$_ : [7] ('Export load order') selected."
                        Return 'Export-LoadOrder; Continue'
                        Export-LoadOrder
                    }
                    Else {Write-Log WARN "Aborted: No action for '$_' in secondary menu."; Break}
                }
                56 { # [8]
                    If (!$Global:MenuToggle) {
                        Write-Log INFO "$_ : [8] ('Import load order') selected."
                        Return '$Global:LoadOrder = Set-ActiveLoadOrder (Import-LoadOrder)' + $SetAndContinue
                        Import-LoadOrder
                    }
                    Else {Write-Log WARN "Aborted: No action for '$_' in secondary menu."; Break}
                }
                57 { # [9]
                    If (!$Global:MenuToggle) {
                        Write-Log INFO "$_ : [9] ('Change load order') selected."
                        If ($Global:OfflineMode) {Write-Log WARN "Aborted: Choice invalid in offline mode."; Break}
                        Return '$Global:LoadOrder = Set-ActiveLoadOrder (Select-LoadOrder)' + $SetAndContinue
                        Select-LoadOrder
                        Set-ActiveLoadOrder
                    }
                    Else {Write-Log WARN "Aborted: No action for '$_' in secondary menu."; Break}
                }
                Default {Write-Log INFO "Invalid menu choice: '$_'"; Break} # Invalid choice
            }
            [Console]::Beep(1000, 150)
        }
    }

    Function Confirm-Choice { #TODO: This function is currently unused and is subject to removal in a future version
        [CmdletBinding()]
        [OutputType([Bool])]

        Param (
            [Parameter(Mandatory, Position = 0)][String]$Prompt,
            [Parameter(Position = 1)][ConsoleColor]$ForegroundColor = [Console]::ForegroundColor
        )
        
        Write-Host -ForegroundColor $ForegroundColor $Prompt
        While ($True) {
            Switch (Read-KeyPress) {
                ([Byte][Char]'N') {Return $False} # 78
                ([Byte][Char]'Y') {Return $True}  # 89
                Default           {Break}         # Invalid
            }
            [Console]::Beep(1000, 150)
        }
    }

    Function Set-RepositoryUrl {
        [CmdletBinding()]
        [OutputType([Object[]])]

        Param ([Switch]$AllowCancel)

        Write-Log INFO 'Received Repository URL set request.'

        [IntPtr]$ParentHwnd = (Get-Process -Id $Pid).MainWindowHandle
        If ($ParentHwnd -eq [IntPtr]::Zero) {$ParentHwnd = [WindowsAPI]::GetForegroundWindow()}

        [Windows.Forms.NativeWindow]$Owner = [Windows.Forms.NativeWindow]::new()
        $Owner.AssignHandle($ParentHwnd)

        [Windows.Forms.Form]$RepositoryUrlForm = @{
            Text          = $Global:ScriptDetails.ShortTitle + ' - Set Repository URL'
            Size          = [Drawing.Size]::New(400, 150)
            StartPosition = [Windows.Forms.FormStartPosition]::CenterParent
            ShowInTaskbar = $False
        }
        [Windows.Forms.Label]$Label = @{
            Text     = 'Enter mod repository URL:'
            AutoSize = $True
            Location = [Drawing.Point]::New(10, 5)
            Font     = [Drawing.Font]::New('Segoe UI', 10)
        }
        $RepositoryUrlForm.Controls.Add($Label)

        [Windows.Forms.TextBox]$TextBox = @{
            Size     = [Drawing.Size]::New(300, 20)
            Location = [Drawing.Point]::New(10, 30)
        }
        $RepositoryUrlForm.Controls.Add($TextBox)
        $TextBox.Add_GotFocus({
            If ($TextBox.Text -eq 'Repository URL') {
                $TextBox.Text      = ''
                $TextBox.ForeColor = [Drawing.Color]::Black
            }
        })
        $TextBox.Add_LostFocus({
            If ([String]::IsNullOrWhiteSpace($TextBox.Text)) {
                $TextBox.Text      = 'Repository URL'
                $TextBox.ForeColor = [Drawing.Color]::Gray
            }
        })

        [Windows.Forms.Button]$OkButton = @{
            Text         = 'OK'
            #Size         = [Drawing.Size]::New(75, 25)
            Location     = [Drawing.Point]::New(100, 80)
            DialogResult = [Windows.Forms.DialogResult]::OK
        }
        $RepositoryUrlForm.Controls.Add($OkButton)

        [Windows.Forms.Button]$CancelButton = @{
            Text         = 'Cancel'
            #Size         = [Drawing.Size]::New(75, 25)
            Location     = [Drawing.Point]::New(280, 80)
            DialogResult = [Windows.Forms.DialogResult]::Cancel
        }
        $RepositoryUrlForm.Controls.Add($CancelButton)

        [Windows.Forms.Button]$TestButton = @{
            Text     = 'Test'
            Size     = [Drawing.Size]::New(75, 25)
            Location = [Drawing.Point]::New(190, 80)
        }
        $RepositoryUrlForm.Controls.Add($TestButton)
        $TestButton.Add_Click({
            [String]$TestUrl = $TextBox.Text
            Write-Log INFO "Repository URL test initiated for '$TestUrl'. Validating."
            Try   {
                [Void](Get-RepositoryInfo -RepoURL $TestUrl -EA 1)
                Write-Log INFO "Repository URL test successful."
                [Void][Windows.MessageBox]::Show("A valid repository was found for the provided URL.`nYou may now press 'OK' to set this URL.", 'Valid repository URL', 0, 64)
            }
            Catch {
                Write-Log ERROR "Repository URL test failed: $($_.Exception.Message)."
                [Void][Windows.MessageBox]::Show("No valid repository found for the provided URL.`nPlease try again.", 'Invalid repository URL', 0, 16)
            }
        })

        $RepositoryUrlForm.AcceptButton = $OkButton
        $RepositoryUrlForm.CancelButton = $CancelButton

        [Void]$RepositoryUrlForm.Add_Shown({
            $RepositoryUrlForm.Activate()
            $RepositoryUrlForm.Topmost = $True
            $TextBox.Focus()
        })

        While ($True) {

            Try {
                Write-Log INFO 'Displaying Repository URL input form.'
                [Windows.Forms.DialogResult]$DialogResult = $RepositoryUrlForm.ShowDialog($Owner)
            }
            Finally {$Owner.ReleaseHandle()}

            If ($DialogResult -eq [Windows.Forms.DialogResult]::OK) {
                [String]$NewUrl = $TextBox.Text
                Write-Log INFO "Repository URL input received: '$NewUrl'. Validating."
                Try   {
                    [PSCustomObject]$RepositoryInfo = Get-RepositoryInfo -RepoUrl $NewUrl -EA 1
                    Break
                }
                Catch {
                    $TextBox.Text = ''
                    Write-Log ERROR "Invalid repository URL: $($_.Exception.Message)."
                    [Void][Windows.MessageBox]::Show("No valid repository found for the provided URL.`nPlease try again.", 'Invalid repository URL', 0, 16)
                }
            }
            ElseIf ($DialogResult -eq [Windows.Forms.DialogResult]::Cancel) {
                Write-Log INFO 'Repository URL input cancelled by user.'
                If ($AllowCancel.IsPresent) {Return $Global:RepositoryUrl, $Global:RepositoryInfo, 'Cancelled by user.'}
                Wait-WriteAndExit 'Cannot continue without a valid repository URL.'
            }
            Else {Continue} # Invalid dialog result
        }

        Write-EmbeddedValue $Global:DataIndices.RepositoryUrl.Index $NewUrl
        Write-Log INFO "Repository URL set to '$NewUrl'"

        Try {
            Switch ($RepositoryInfo | ConvertTo-Json -Compress) {
                {[String]::IsNullOrWhiteSpace($_)} {Throw 'No repository data.'}
                Default                            {[String]$OfflineData = $_; Break}
            }
            Write-EmbeddedValue $Global:DataIndices.OfflineData.Index $OfflineData
            Write-Log INFO "Updated offline repository information: $OfflineData"
            [String]$CacheUpdate = 'OK'
        }
        Catch {[String]$CacheUpdate = $_.Exception.Message}

        Return $NewUrl, $RepositoryInfo, $CacheUpdate
    }

    Function Write-HostFancy { #TODO: "This function will be deprecated in a future version"(TM)
        [CmdletBinding()]
        [OutputType([Void])]

        Param (
            [Parameter(Position = 0)][String[]]$String  = @(''),
            [Parameter(Position = 1)][UInt16]$Speed     = 0,
            [Alias('Fg')][ConsoleColor]$ForegroundColor = [Console]::ForegroundColor,
            [Alias('Bg')][ConsoleColor]$BackgroundColor = [Console]::BackgroundColor,
            [Alias('Nn')][Switch]$NoNewline
        )

        [String[]]$Text   = $String -Join "`n" -Split "`n"
        [Hashtable]$Splat = @{
            ForegroundColor = $ForegroundColor
            BackgroundColor = $BackgroundColor
            NoNewline       = $NoNewline.IsPresent
        }
        ForEach ($Line in $Text) {
            Write-Host @Splat ($Line + ' ' * [Math]::Max(0, [Console]::BufferWidth - $Line.Length - [Console]::CursorLeft))
            Start-Sleep -Milliseconds ($Speed, 0)[[String]::IsNullOrWhiteSpace($Line)]
        }
    }

    Function Clear-HostFancy {
        [CmdletBinding()]
        [OutputType([Void])]

        Param (
            [Parameter(Position = 0)][UInt16]$Lines = 10,
            [Parameter(Position = 1)][UInt16]$From  = 0,
            [Parameter(Position = 2)][UInt16]$Speed = 50,
            [Switch]$NoReturn
        )

        [Hashtable]$Splat = @{
            Object          = ' ' * [Console]::BufferWidth
            ForegroundColor = [Console]::ForegroundColor
            BackgroundColor = [Console]::BackgroundColor
        }
        [Console]::SetCursorPosition(0, $From)
        For ([UInt16]$Y = 0; $Y -lt $Lines - 1; $Y++) {
            Write-Host @Splat
            Start-Sleep -Milliseconds $Speed
        }
        If (!$NoReturn.IsPresent) {[Console]::SetCursorPosition(0, $From)}
    }

    Function Get-PersistentStorage {
        [CmdletBinding()]
        [OutputType([Collections.Generic.List[String]])]

        Param (
            [IO.FileInfo]$File = $Global:ScriptPath,
            [String]$Eof       = '#PERSIST_END',
            [String]$Bof
        )

        Write-Log INFO 'Received persistent storage request.'

        [Collections.Generic.List[String]]$Data = @()
        [Text.UTF8Encoding]$Utf8Encoding        = [Text.UTF8Encoding]::New($False)
        [Bool]$InRange                          = !$PSBoundParameters.ContainsKey('Bof')

        If ($PSVersionTable.PSVersion.Major -lt 7) {
            Try {
                [IO.StreamReader]$Reader = [IO.StreamReader]::New($File.FullName, $Utf8Encoding)

                Write-Log INFO "Initialized StreamReader synchronous enumerator for '$($File.FullName)'."

                If ($InRange) {Write-Log INFO "Performing synchronous enumeration until EOF token '$Eof'."}
                Else          {Write-Log INFO "Performing synchronous enumeration until EOF token '$Eof'. Ignoring data preceding BOF token '$Bof'."}

                While ($Reader.Peek() -ne -1) {
                    [String]$Line = $Reader.ReadLine()
                    If     ($Line -eq '')   {Continue}
                    ElseIf (!$InRange)      {$InRange = $Line -eq $Bof}
                    ElseIf ($Line -eq $Eof) {Break}
                    Else                    {$Data.Add($Line)}
                }
                Write-Log INFO "Enumeration halted on $($Data.Count): Current='$Line'"
            }
            Catch   {Write-Log ERROR "Failed to read persistent storage: $($_.Exception.Message)"; Throw $_}
            Finally {
                If ($Null -ne $Reader) {$Reader.Dispose()}
                Write-Log INFO 'Disposed StreamReader.'
            }
        }
        Else {
            Try {
                [Threading.CancellationTokenSource]$Cancellation    = [Threading.CancellationTokenSource]::New()
                [Collections.Generic.IAsyncEnumerable[String]]$Enum = [IO.File]::ReadLinesAsync($File.FullName, $Utf8Encoding, $Cancellation.Token)
                [Collections.Generic.IAsyncEnumerator[String]]$Feed = $Enum.GetAsyncEnumerator($Cancellation.Token)

                Write-Log INFO "Initialized cancellation token and asynchronous enumerator for '$($File.FullName)'."

                If ($InRange) {Write-Log INFO "Performing asynchronous enumeration until EOF token '$Eof'."}
                Else          {Write-Log INFO "Performing asynchronous enumeration until EOF token '$Eof'. Ignoring data preceding BOF token '$Bof'."}

                While ($Feed.MoveNextAsync().AsTask().Result -And !$Cancellation.IsCancellationRequested) {
                    [String]$Line = $Feed.Current
                    If     ($Line -eq '')   {Continue}
                    ElseIf (!$InRange)      {$InRange = $Line -eq $Bof}
                    ElseIf ($Line -eq $Eof) {$Cancellation.Cancel()}
                    Else                    {$Data.Add($Line)}
                }
                Write-Log INFO "Enumeration halted on $($Data.Count): IsCancellationRequested=$($Cancellation.IsCancellationRequested); Current='$Line'"
            }
            Catch   {Write-Log ERROR "Failed to read persistent storage: $($_.Exception.Message)"; Throw $_}
            Finally {
                If ($Null -ne $Feed)         {[Void]$Feed.DisposeAsync()}
                If ($Null -ne $Cancellation) {$Cancellation.Dispose()}
                Write-Log INFO 'Disposed feed and cancellation token.'
            }
        }
        If ($Data.Count -eq 0) {
            Write-Log ERROR "Failed to read persistent storage: No data was read using EOF '$Eof'$(('', " + BOF '$Bof'")[$PSBoundParameters.ContainsKey('Bof')])."
            Throw 'Failed to read persistent storage: No data was read.'
        }
        Write-Log INFO "Retrieved $($Data.Count) entries:`n$($Data -Join "`n")"
        
        Return $Data
    }

    Function Set-PersistentStorage {
        [CmdletBinding()]
        [OutputType([Void])]

        Param (
            [Parameter(Mandatory, Position = 0)][Collections.Generic.List[String]]$Data,
            [Parameter(Position = 1)][IO.FileInfo]$File = $Global:ScriptPath,
            [String]$Eof = '#PERSIST_END',
            [String]$Bof
        )

        Write-Log INFO 'Received persistent storage write request.'

        [Collections.Generic.List[String]]$FileContents = Get-FileContent $File
        Write-Log INFO "Loaded '$($File.FullName)'."

        [Int]$BofIndex = If ($PSBoundParameters.ContainsKey('Bof')) {$FileContents.IndexOf($Bof)} Else {0}
        If ($BofIndex -eq -1) {
            Write-Log WARN "BOF token '$Bof' not detected in '$($File.Name)'. Using start index 0. Inserting token at index 0 of provided data."
            $Data.Insert(0, $Bof)
            $BofIndex = 0
        }

        [Int]$EofIndex = $FileContents.IndexOf($Eof)
        If ($EofIndex -eq -1) {
            $Data.Add($Eof)
            Write-Log WARN "Failed to retrieve existing storage: EOF token '$Eof' not detected in '$($File.Name)'. Appending token to provided storage data."
            Write-Log WARN 'Attempting to retrieve existing storage by line matching. EOF: ''<#'''
            [Int]$EofIndex = $FileContents.IndexOf('<#')
            If ($EofIndex -eq -1) {
                Write-Log ERROR "Failed to retrieve existing storage: EOF token '<#' not detected in '$($File.Name)'. Aborting operation."
                Throw "Failed to retrieve existing storage: EOF token '<#' not detected in '$($File.Name)'."
            }
            Else {
                [Collections.Generic.List[String]]$_Storage = $FileContents.GetRange(0, $EofIndex)
                For ([UInt32]$Index = $_Storage.Count - 1; $Index -ge 0; $Index--) {If ($_Storage[$Index] -NotMatch '^#(NUM|DEC|STR)_[a-z]+=.+;$') {$_Storage.RemoveAt($Index)} Else {Break}}
                If ($_Storage.Count -eq 0) {
                    Write-Log ERROR 'Failed to retrieve existing storage: No valid data detected in storage range. Aborting operation.'
                    Throw 'Failed to retrieve existing storage: No valid data detected in storage range.'
                }
                Write-Log INFO 'Detected storage data by line matching.'
                [Collections.Generic.List[String]]$ExistingStorage = $_Storage
            }
        }
        Else {[Collections.Generic.List[String]]$ExistingStorage = $FileContents.GetRange($BofIndex, $EofIndex)}

        Write-Log INFO "Existing storage: $BofIndex..$($ExistingStorage.Count)/$($FileContents.Count) entries."

        If ((Get-StringHash $ExistingStorage) -eq (Get-StringHash $Data)) {
            Write-Log INFO 'No changes detected in provided persistent storage. Aborting operation.'
            Return
        }

        $FileContents.RemoveRange($BofIndex, $ExistingStorage.Count)
        $FileContents.InsertRange($BofIndex, $Data)
        
        Write-Log INFO "Removed old storage range $BofIndex..$($ExistingStorage.Count). Inserted new storage range: $BofIndex..$($Data.Count)"

        Set-Utf8Content $File $FileContents -NoNewline

        Write-Log INFO 'Successfully updated persistent storage data.'
    }

    Function Read-EmbeddedValue {
        [CmdletBinding()]
        [OutputType([Int64], [Double], [String])]

        Param (
            [Parameter(Mandatory, Position = 0)][UInt32]$Index,
            [Parameter(Position = 1)][Collections.Generic.List[String]]$CustomData
        )
        
        Write-Log INFO 'Received embedded value read request.'

        If ($PSBoundParameters.ContainsKey('CustomData')) {
            [Collections.Generic.List[String]]$ScriptData = $CustomData
            Write-Log INFO 'Reading embedded value from provided custom data.'
        }
        Else {[Collections.Generic.List[String]]$ScriptData = $Global:StoredData}

        [String]$Info,   [String]$RawValue = $ScriptData[$Index].Substring(0, $ScriptData[$Index].IndexOf(';')).Substring(1) -Split '=', 2
        [String]$Format, [String]$Name     = $Info -Split '_', 2

        Switch ($Format) {
            'NUM'   {[Int64]$Value  = $RawValue}
            'DEC'   {[Double]$Value = $RawValue}
            Default {[String]$Value = $RawValue}
        }
        Write-Log INFO "Read embedded value: '$Name' > '$Value'"
        Return $Value
    }

    Function Read-AllEmbeddedValues {
        [CmdletBinding()]
        [OutputType([Hashtable])]

        Param (
            [Hashtable]$DataIndices = $Global:DataIndices,
            [Collections.Generic.List[String]]$CustomData
        )
        
        Write-Log INFO 'Received read request of all embedded values.'
        If ($PSBoundParameters.ContainsKey('CustomData')) {
            [Collections.Generic.List[String]]$ScriptData = $CustomData
            Write-Log INFO 'Reading embedded values from provided custom data.'
        }
        Else {[Collections.Generic.List[String]]$ScriptData = $Global:StoredData}
        
        $DataIndices['ScriptVersion'] = [Hashtable]@{Index = 0; Type = [String]}
        [Hashtable]$ReadData          = @{}
        [String[]]$Pairs              = @()

        ForEach ($Key in $DataIndices.Keys) {
            [String]$ScriptLine              = $ScriptData[$DataIndices.$Key.Index]
            [String]$Info, [String]$RawValue = $ScriptLine -Split '=', 2
            $Info = $Info.Substring(1)
            $RawValue = $RawValue.Substring(0, $RawValue.Length - 1)
            [String]$Format, [String]$Name   = $Info -Split '_', 2
            Switch ($Format) {
                'NUM'   {[Int64]$Value  = $RawValue}
                'DEC'   {[Double]$Value = $RawValue}
                Default {[String]$Value = $RawValue}
            }
            $Pairs += "$($Key.PadRight(16))> '$Value'"
            $ReadData[$Key] = $Value
        }
        Write-Log INFO "All embedded values read ($($ReadData.Keys.Count)):`n$($Pairs -Join "`n")"
        Return $ReadData
    }

    Function New-EmbeddedValue {
        [CmdletBinding()]
        [OutputType([String])]

        Param (
            [Parameter(Mandatory, Position = 0)][String]$SourceData,
            [Parameter(Mandatory, Position = 1)][String]$Value
        )
        
        Write-Log INFO "Received new embedded value reqiest of '$Value'."

        $Value = Switch ($Value) {
            'True'  {'1'}
            'False' {'0'}
            Default {$_}
        }
        [String]$DataKey = $SourceData.Substring(0, $SourceData.IndexOf('='))

        Write-Log INFO "New embedded value: $("'$DataKey'".PadRight(19))> '$Value'"

        Return "$DataKey=$Value;"
    }

    Function Write-EmbeddedValue {
        [CmdletBinding()]
        [OutputType([Void])]

        Param (
            [Parameter(Mandatory, Position = 0)][UInt32]$Index,
            [Parameter(Mandatory, Position = 1)][String]$Value
        )

        Write-Log INFO "Received embedded value write request: '$Value' at index $Index."

        [Collections.Generic.List[String]]$ScriptData = Get-PersistentStorage
        $ScriptData[$Index] = New-EmbeddedValue $ScriptData[$Index] $Value
        
        Set-PersistentStorage $ScriptData
        Write-Log INFO "Embedded value written: '$Value'"
    }

    Function Write-AllEmbeddedValues {
        [CmdletBinding()]
        [OutputType([Void])]

        Param ()
        
        Write-Log INFO 'Received write request for all embedded values.'

        [Collections.Generic.List[String]]$ScriptData = Get-PersistentStorage
        [String[]]$Pairs = @()

        ForEach ($Key in $Global:DataIndices.Keys) {
            [String]$Value = Get-Variable "$Key" -ValueOnly -Scope Global
            [UInt32]$Index = $Global:DataIndices.$Key.Index
            $Pairs        += "'$Key' > '$Value'"

            $ScriptData[$Index] = New-EmbeddedValue $ScriptData[$Index] $Value
        }
        Set-PersistentStorage $ScriptData
        Write-Log INFO "All embedded values written ($($Pairs.Count)):`n$($Pairs -Join "`n")"
    }

    Function Set-DrawFrequency {
        [CmdletBinding()]
        [OutputType([UInt16])]

        Param ()

        Write-Log INFO 'Received draw frequency set request.'

        While ($True) {
            [UInt16]$NewDrawFrequency = $Null
            [Console]::Clear()
            Write-HostFancy ($Global:ScriptDetails.ShortTitle + ' - Set Draw Frequency')
            Write-Ansi (@(
                'Select the frequency at which the console UI updates during operations:',
                '',
                '  [1] Slower (2000 ms)',
                '  [2] Slow (1000 ms)',
                '  [3] Normal (500 ms)',
                '  [4] Fast (250 ms)',
                '  [5] Faster (100 ms)',
                '  [6] Fastest (0 ms)',
                '',
                'Use keys [1] through [6] to select an option, or [ESC] to cancel.'
            ) -Join "`n")

            $NewDrawFrequency = Switch (Read-KeyPress) {
                49 {Write-Log INFO 'New draw frequency selected: Slower (2000 ms).'; 2000; Break} # [1]
                50 {Write-Log INFO 'New draw frequency selected: Slow   (1000 ms).'; 1000; Break} # [2]
                51 {Write-Log INFO 'New draw frequency selected: Normal  (500 ms).'; 500;  Break} # [3]
                52 {Write-Log INFO 'New draw frequency selected: Fast    (250 ms).'; 250;  Break} # [4]
                53 {Write-Log INFO 'New draw frequency selected: Faster  (100 ms).'; 100;  Break} # [5]
                54 {Write-Log INFO 'New draw frequency selected: Fastest   (0 ms).'; 0;    Break} # [6]
                Default {[Console]::Beep(1000, 150); Continue} # Invalid
            }
            If ($Null -ne $NewDrawFrequency) {Break}
        }
        Write-EmbeddedValue $Global:DataIndices.DrawFrequency.Index $NewDrawFrequency
        Write-Log INFO "Draw frequency updated to $NewDrawFrequency ms"
    }

    Function Switch-GrammaticalNumber {
        [CmdletBinding(DefaultParameterSetName = 'Auto')]
        [OutputType([String], [String[]])]

        Param (
            [Parameter(Mandatory, Position = 0, ValueFromPipeline)][String]$Word,
            [Parameter(Position = 1, ParameterSetName = 'Count')][Int64[]]$Count,
            [Parameter(ParameterSetName = 'Singular')][Alias('S')][Switch]$Singularize,
            [Parameter(ParameterSetName = 'Plural')][Alias('P')][Switch]$Pluralize
        )

        Write-Log INFO 'Received grammatical number switch request.'

        If (!$Global:PluralizerService) {
            Write-Log ERROR 'Pluralization service is unavailable.'
            Throw 'Pluralization service is unavailable'
        }

        [String]$ParamSet = $PSCmdlet.ParameterSetName
        [String]$Plural   = $Global:PluralizerService.Pluralize($Word)
        [String]$Singular = $Global:PluralizerService.Singularize($Word)

        If ($ParamSet -eq 'Count' -And $Count.Count -gt 1) {[String[]]$Return = ForEach ($Instance in $Count) {($Plural, $Singular)[[Math]::Abs($Instance) -eq 1]}}
        Else {[String]$Return = Switch ($ParamSet) {
            'Auto'     {($Plural, $Singular)[$Global:PluralizerService.IsSingular($Word)]; Break}
            'Count'    {($Plural, $Singular)[[Math]::Abs($Count[0]) -eq 1]; Break}
            'Singular' {$Singular; Break}
            'Plural'   {$Plural; Break}
            Default    {$Word; Break}
        }}
        Write-Log INFO "Grammatical number switched: '$Word' > '$Return'"

        Return $Return
    }

    Function Get-ContrastingColor {
        [CmdletBinding(DefaultParameterSetName = 'ForColor')]
        [OutputType([ConsoleColor])]

        Param (
            [Parameter(Mandatory, Position = 0, ParameterSetName = 'ForColor')]
            [Parameter(Position = 0, ParameterSetName = 'ForBackground')]
            [Parameter(Position = 0, ParameterSetName = 'ForForeground')]
            [ConsoleColor]$Color,
            [Parameter(Mandatory, ParameterSetName = 'ForBackground')][Switch]$ForBackground,
            [Parameter(Mandatory, ParameterSetName = 'ForForeground')][Switch]$ForForeground
        )

        Write-Log INFO "Received contrasting color request for '$Color'."

        [ConsoleColor]$Contrast = Switch ($Color) {
            'Black'   {[ConsoleColor]::White}
            'DarkGray'{[ConsoleColor]::White}
            'White'   {'Black'}
            Default    {'DarkGray'}
        }
        Write-Log INFO "Contrasting color for '$Color': '$Contrast'"

        Return $Contrast
    }

    Function Get-EnglishCulture {
        [CmdletBinding()]
        [OutputType([CultureInfo])]

        Param ([Switch]$Set)

        Write-Log INFO 'Received optimal English culture request.'
        # Default: 1033, en-US (English, United States)

        [CultureInfo]$CurrentCulture = [CultureInfo]::CurrentCulture
        Write-Log INFO "Current culture: LCID $($CurrentCulture.LCID) - $($CurrentCulture.Name) ($($CurrentCulture.DisplayName))"

        [String[]]$EngCultures = ([CultureInfo]::GetCultures([Globalization.CultureTypes]::AllCultures) | Where-Object {$_.Name -Like 'en-*'}).Name | Select-Object -Unique
        Write-Log INFO "Collected $($EngCultures.Count) EN culture candidates."

        [CultureInfo]$OptimalCulture = [CultureInfo]::GetCultureInfo(('en-US', $CurrentCulture.Name)[$CurrentCulture.Name -In $EngCultures])
        Write-Log INFO "Optimal EN culture: LCID $($OptimalCulture.LCID) - $($OptimalCulture.Name) ($($OptimalCulture.DisplayName))"

        If ($Set.IsPresent -And $CurrentCulture -ne $OptimalCulture) {
            [CultureInfo]::CurrentCulture = $OptimalCulture
            $CurrentCulture = [CultureInfo]::CurrentCulture
            Write-Log INFO "Set Session culture: LCID $($OptimalCulture.LCID) - $($OptimalCulture.Name) ($($OptimalCulture.DisplayName))"
        }
        Return $OptimalCulture
    }

    Function Get-LoadOrderData {
        [CmdletBinding()]
        [OutputType([Hashtable], [String], [Object[]])]

        Param (
            [String]$Name = $Global:LoadOrder,
            [Switch]$Data,
            [Switch]$Raw
        )

        Write-Log INFO "Received load order data request for '$Name'."

        If     ([IO.Path]::GetExtension($Name) -eq '.order') {Write-Log INFO "Load order data source: $Name (LOCAL)";    [String]$Content = Get-FileContent $Name -Raw} 
        ElseIf (!$Global:OfflineMode)                        {Write-Log INFO "Load order data source: $Name.cfg (REPO)"; [String]$Content = Get-FileContent -FromBytes (Get-ModRepoFile "$Name.cfg" -UseIwr).Content -Raw}
        Else                                                 {Write-Log ERROR "Load order data unavailable: Unable to reach data source for $Name.cfg (REPO)."; Throw [ApplicationException]::New('Unavailable. (Offline mode)')}

        If (!(Test-LoadOrderFormat $Content -ShowInfo -ContinueOnError)) {Throw 'Invalid load order data'}
        [Hashtable]$LoadOrderData = Get-ModData $Content

        Write-Log INFO "Successfully imported load order data from '$Name'"

        If     ($Data.IsPresent -And $Raw.IsPresent)  {Return $LoadOrderData, $Content}
        ElseIf ($Data.IsPresent -And !$Raw.IsPresent) {Return $LoadOrderData}
        ElseIf (!$Data.IsPresent -And $Raw.IsPresent) {Return $Content}
        Else                                          {Return}
    }

    Function Remove-InactiveMods {
        [CmdletBinding()]
        [OutputType([Void])]

        Param ()

        Write-Log INFO 'Received inactive mod removal request.'

        [UInt16]$DeletedTargets      = 0
        [UInt64]$OldSize             = 0
        [IO.FileInfo[]]$EnabledFiles = ForEach ($Key in $Global:LoadOrderData.Keys | Where-Object {$Global:LoadOrderData[$_].Type -ne 'Workshop'}) {[IO.Path]::GetFileName($Global:LoadOrderData[$Key].SourcePath)}
        [IO.FileInfo[]]$Targets      = ForEach ($File in Get-ChildItem *.scs -File) {$OldSize += $File.Length; If ($File -NotIn $EnabledFiles -And (($File.Name -In $Global:OnlineData.PSObject.Properties.Name -And $Global:DdSel -eq 1) -Or $Global:DdSel -eq 2)) {$File}}

        If (!$Targets) {
            Write-Log INFO 'No mods to delete.'
            Write-Host ('║ No mods to delete.'.PadRight($UIRowLine - 1) + '║')
            Return
        }
        Else {Write-Log INFO "Detected $($Targets.Count) inactive $(Switch-GrammaticalNumber 'mod' $Targets.Count) for deletion."}

        [Byte]$TargetPadding = ($Targets.Name | Sort-Object Length)[-1].Length + 8

        Write-Host ("║ Deleting $($Targets.Count) inactive $(Switch-GrammaticalNumber 'mod' $Targets.Count):".PadRight($UIRowLine - 1) + '║')

        ForEach ($Target in $Targets) {
            Write-Host -NoNewline (('║   ' + "'$($Target.Name)'...".PadRight($TargetPadding)).PadRight($UIRowLine - 1) + '║')
            
            Try {
                $Target.Delete()
                $DeletedTargets++

                Write-Log INFO "Deleted inactive mod '$($Target.FullName)'"
                [Console]::SetCursorPosition($TargetPadding, [Console]::CursorTop)
                Write-Host -NoNewline -ForegroundColor Green 'Deleted'
            }
            Catch {
                Write-Log WARN "Failed to delete mod '$($Target.FullName)': $($_.Exception.Message)"
                Write-Host -NoNewline -ForegroundColor Red "Failed to delete. See $($Global:SessionLog.Name).".PadRight($UIRowLine - $TargetPadding - 3)
                Write-Host '║'
            }
        }
        [String]$DeletionResult = Switch ($OldSize - (Get-ItemPropertyValue *.scs Length | Measure-Object -Sum).Sum) {
            {[Math]::Abs($_) -lt 1024}   {"$_ B"; Break}
            {[Math]::Abs($_) -lt 1024kB} {"$([Math]::Round($_ / 1kB, 1)) kB"; Break}
            {[Math]::Abs($_) -lt 1024MB} {"$([Math]::Round($_ / 1MB, 1)) MB"; Break}
            {[Math]::Abs($_) -ge 1024MB} {"$([Math]::Round($_ / 1GB, 2)) GB"; Break}
        }
        $DeletionResult = "Deleted $DeletedTargets inactive $(Switch-GrammaticalNumber 'mod' $DeletedTargets) ($DeletionResult)"
        Write-Log INFO $DeletionResult
        Write-Host -NoNewline ('║'.PadRight($UIRowLine - 1) + "║`n" + '║ ')
        Write-Host -NoNewline -ForegroundColor Green $DeletionResult.PadRight($UIRowLine - 2)
        Write-Host '║'
    }

    Function Select-LoadOrder {
        [CmdletBinding()]
        [OutputType([String])]

        Param ()

        Write-Log INFO 'Received load order selection request.'

        If (!$Global:AllLoadOrders -Or $Global:AllLoadOrders.Count -le 1) {
            Write-Log WARN 'No load orders detected. Aborting selection and using the current load order.'
            Return $Global:LoadOrder
        }

        Write-Log INFO 'Displaying load order selection prompt.'

        Clear-Host
        Write-Host ' SELECT MOD LOAD ORDER'
        Write-Host ($Global:UiLine * [Console]::BufferWidth)

        [Byte]$Selected                                   = (0, $Global:AllLoadOrders.IndexOf($Global:LoadOrder))[$Global:LoadOrder -In $Global:AllLoadOrders]
        [String]$PreviousLoadOrder                        = $Global:LoadOrder
        [Management.Automation.Host.Coordinates]$StartPos = $Host.UI.RawUI.CursorPosition

        Do {
            $Host.UI.RawUI.CursorPosition = $StartPos
            [Byte]$Iteration              = 0

            ForEach ($Order in $Global:AllLoadOrders) {
                [Bool]$IsSelected = $Iteration -eq $Selected

                Write-Host -NoNewline ' '
                Write-HostX 0 -Color ('DarkGray', 'Green')[$IsSelected] (' ' + ('   ', '>> ')[$IsSelected] + "$Order ") -Newline

                $Iteration++
            }
            
            Write-Ansi "`n * Use the <cyan>[UP]</cyan> and <cyan>[DOWN]</cyan> keys to select a load order.`n * Press <cyan>[ENTER]</cyan> to confirm your selection, or <cyan>[ESC]</cyan> to cancel.`n"
            <#Write-Host -NoNewline "`n * Use the "
            Write-Host -NoNewline -ForegroundColor Cyan '[UP]'
            Write-Host -NoNewline ' and '
            Write-Host -NoNewline -ForegroundColor Cyan '[DOWN]'
            Write-Host -NoNewline " keys to select a load order.`n * Press "
            Write-Host -NoNewline -ForegroundColor Cyan '[ENTER]'
            Write-Host -NoNewline ' to confirm your selection, or '
            Write-Host -NoNewline -ForegroundColor Cyan '[ESC]'
            Write-Host ' to cancel.'#>

            [String]$SelectedLoadOrder = $Global:AllLoadOrders[$Selected]
            Write-Log INFO "Selection set: '$SelectedLoadOrder'"

            Do {
                [Bool]$UpdateSelection = $False
                Switch (Read-KeyPress) {
                    13 { # [ENTER]
                        [String]$ConfirmedSelection = ($PreviousLoadOrder, $SelectedLoadOrder)[$SelectedLoadOrder -ne $PreviousLoadOrder]
                        Write-Log INFO "Selection confirmed: '$ConfirmedSelection'"
                        Clear-Host
                        Return $ConfirmedSelection
                    }
                    27 { # [ESC]
                        Write-Log INFO "Selection cancelled. Reverting to previous value: '$PreviousLoadOrder'"
                        Clear-Host
                        Return $PreviousLoadOrder
                    }
                    38 { # [UP]
                        If ($Selected -gt 0) {$Selected--} Else {[Console]::Beep(1000, 150)}
                        $UpdateSelection = $True
                        Break
                    }
                    40 { # [DOWN]
                        If ($Selected -lt $Global:AllLoadOrders.Count - 1) {$Selected++} Else {[Console]::Beep(1000, 150)}
                        $UpdateSelection = $True
                        Break
                    }
                    Default {Continue}
                }
            } Until ($UpdateSelection)
        } While ($True)
    }

    Function Set-ActiveLoadOrder {
        [CmdletBinding()]
        [OutputType([String])]

        Param ([Parameter(Mandatory)][String]$LoadOrder)

        If ($LoadOrder -ne $Global:LoadOrder) {
            Write-EmbeddedValue $Global:DataIndices.LoadOrder.Index $LoadOrder
            Write-Log INFO "Active load order changed from '$Global:LoadOrder' to '$LoadOrder'"

            Return $LoadOrder
        }
        Return $Global:LoadOrder
    }

    Function Get-LoadOrderList {
        [CmdletBinding()]
        [OutputType([String[]])]

        Param ()

        If ($Global:OfflineMode) {
            Write-Log WARN 'Can''t fetch load orders in offline mode'
            Return [String[]]@($Global:LoadOrder)
        }
        [String[]]$LoadOrderList = (Get-ModRepoFile $Global:RepositoryInfo.$Global:GameNameShort.Orders -UseIwr).Content | ConvertFrom-Json
        Write-Log INFO "Fetched available load orders ($($LoadOrderList.Count)) from master server"

        Return $LoadOrderList
    }

    Function Test-LoadOrderFormat {
        [CmdletBinding()]
        [OutputType([Bool], [String[]])]

        Param (
            [Parameter(Position = 0)][String]$Content,
            [Switch]$ShowInfo,
            [Switch]$ContinueOnError,
            [Switch]$ReturnInfo
        )

        Write-Log INFO 'Received load order format validation request.'

        [Regex]$HeaderValidationExpr = '(?-i)^ ?active_mods: ?\d+$(?i)'
        [Regex]$FormatValidationExpr = '(?-i)^ ?active_mods\[\d+\]: ?"(?:mod_workshop_package\.00000000[0-9A-F]{8}|[\w\- ]+)\|.+"$'
        [Regex]$TotalValueExpr       = '(?<=(?-i)^ ?active_mods(?i): ?)\d+(?=$)'
        [Regex]$IndexValueExpr       = '(?<=(?-i)^ ?active_mods(?i)\[)\d+(?=\]:)'

        [Hashtable]$WhxSplat = @{
            X       = 0
            Color   = [ConsoleColor]::Red
            Newline = $True
        }
        [Byte]$IndexModifier = 2
        [Bool]$IsValid       = $True
        [String[]]$Failures  = @()

        Try {
            [String]$Header, [String]$RawData = $Content -Split "`n", 2
            [String[]]$Data                   = $RawData -Split "`n"

            # Check header
            If ($Header -NotMatch $HeaderValidationExpr) {
                [String]$FailureMessage = "$Name : Invalid header format '$Header'"
                $Failures += $FailureMessage

                Write-Log ERROR $FailureMessage
                If ($ShowInfo.IsPresent)        {Write-HostX @WhxSplat $FailureMessage}
                If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
            }
            # Match expected entries with actual entries
            [UInt16]$ExpectedCount = Switch ([Regex]::Match($Header, $TotalValueExpr).Value) {
                {[UInt16]::TryParse($_, [Ref]$Null)} {[UInt16]::Parse($_); Break}
                Default {
                    [String]$FailureMessage = "$Name : Can't parse header mod count '$_' from '$Header'"
                    $Failures += $FailureMessage

                    Write-Log ERROR $FailureMessage
                    If ($ShowInfo.IsPresent)        {Write-HostX @WhxSplat $FailureMessage}
                    If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
                }
            }
            If ($Data.Count -ne $ExpectedCount) {
                [String]$FailureMessage = "$Name : Invalid mod count. Expected '$ExpectedCount', got '$($Data.Count)'"
                $Failures += $FailureMessage

                Write-Log ERROR $FailureMessage
                If ($ShowInfo.IsPresent)        {Write-HostX @WhxSplat $FailureMessage}
                If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
            }

            # Check formatting and indices
            For ([UInt16]$Index = 0; $Index -lt $Data.Count; $Index++) {

                [UInt16]$Line       = $Index + $IndexModifier
                [String]$Entry      = $Data[$Index]
                [UInt16]$EntryIndex = Switch ([Regex]::Match($Entry, $IndexValueExpr).Value) {
                    {[UInt16]::TryParse($_, [Ref]$Null)} {[UInt16]::Parse($_); Break}
                    Default {
                        [String]$FailureMessage = "$Name ($Line): Can't parse entry index '$_' from '$Entry'"
                        $Failures += $FailureMessage

                        Write-Log ERROR $FailureMessage
                        If ($ShowInfo.IsPresent)        {Write-HostX @WhxSplat $FailureMessage}
                        If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
                    }
                }

                If ($EntryIndex -ne $Index) {
                    [String]$FailureMessage = "$Name ($Line): Expected index $Index but received $EntryIndex"
                    $Failures += $FailureMessage

                    Write-Log ERROR $FailureMessage
                    If ($ShowInfo.IsPresent)        {Write-HostX @WhxSplat $FailureMessage}
                    If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
                }

                If ($Entry -NotMatch $FormatValidationExpr) {
                    [String]$FailureMessage = "$Name ($Line): Malformed entry '$Entry'"
                    $Failures += $FailureMessage

                    Write-Log ERROR $FailureMessage
                    If ($ShowInfo.IsPresent)        {Write-HostX @WhxSplat $FailureMessage}
                    If ($ContinueOnError.IsPresent) {$IsValid = $False} Else {Throw [ApplicationException]::New($FailureMessage)}
                }
            }
        }
        Catch {
            If ($_.Exception -IsNot [ApplicationException]) {
                [String]$FailureMessage = "$Name : " + $_.Exception.Message
                $Failures += $FailureMessage

                Write-Log ERROR $FailureMessage
                If ($ShowInfo.IsPresent) {Write-HostX @WhxSplat $FailureMessage}
            }
            Return ($False, $Failures)[$ReturnInfo.IsPresent]
        }
        If (!$IsValid) {Write-Log ERROR "$Name : INVALID - Failed to validate load order format"}
        Else           {Write-Log INFO "$Name : SUCCESS - Successfully validated load order format"}

        Return ($IsValid, $Failures)[$ReturnInfo.IsPresent]
    }

    Function Get-FilePathByDialog {
        [CmdletBinding(DefaultParameterSetName = 'Open')]
        [OutputType([IO.FileInfo], [Void])]

        Param (
            [Parameter(Position = 0)][String]$Title     = 'Select file',
            [Parameter(Position = 1)][String]$Filter    = 'All files (*.*)|*.*',
            [Parameter(Position = 2)][String]$File      = '',
            [Parameter(Position = 3)][String]$Directory = $Global:GameRootDirectory.Fullname,
            [Parameter(Mandatory, ParameterSetName = 'Open')][Switch]$Open,
            [Parameter(Mandatory, ParameterSetName = 'Save')][Switch]$Save,
            [Parameter(ParameterSetName = 'Open')][Switch]$MultiSelect,
            [Parameter(ParameterSetName = 'Save')][Switch]$NoOverwritePrompt,
            [Parameter(ParameterSetName = 'Save')][Switch]$CreatePrompt,
            [Parameter(ParameterSetName = 'Save')][Switch]$NoPathCheck
        )

        Write-Log INFO 'Received file dialog request.'

        If ($Save.IsPresent) {[Windows.Forms.SaveFileDialog]$Browser = @{
            CheckPathExists  = !$NoPathCheck.IsPresent
            CreatePrompt     = $CreatePrompt.IsPresent
            OverwritePrompt  = !$NoOverwritePrompt.IsPresent
            FileName         = $File
            InitialDirectory = $Directory
            Filter           = $Filter
            Title            = $Title
        }}
        Else {[Windows.Forms.OpenFileDialog]$Browser = @{
            FileName         = $File
            InitialDirectory = $Directory
            Filter           = $Filter
            Multiselect      = $MultiSelect.IsPresent
            Title            = $Title
        }}
        Write-Log INFO "Initialized $($PSCmdlet.ParameterSetName)FileDialog '$Title'"

        Write-Log INFO "Displaying $($PSCmdlet.ParameterSetName)FileDialog '$Title'"
        [String]$DialogInteraction = $Browser.ShowDialog()

        Write-Log INFO "$($PSCmdlet.ParameterSetName)FileDialog interaction: '$DialogInteraction', FileName: '$($Browser.FileName)'"
        If ($DialogInteraction -eq 'OK') {Return [IO.FileInfo]$Browser.FileName}
    }

    Function Assert-TsseNamingScheme {
        [CmdletBinding()]
        [OutputType([String])]

        Param ()

        Write-Log INFO 'Searching for TS SE Tool directory.'
        [String]$RootName           = $Global:TsseTool.RootDirectory.Name
        [String]$Executable         = $Global:TsseTool.Executable.Name
        [IO.FileInfo[]]$Executables = Get-ChildItem -Path $Global:GameRootDirectory.FullName -Filter $Executable -File -Recurse -Depth 2 | Sort-Object LastWriteTime -Descending

        If ($Executables.Count -eq 0) {
            Write-Log WARN "    No executables found in '$($Global:GameRootDirectory.FullName)'. Using '$RootName'"
            Return $RootName
        }

        [IO.DirectoryInfo]$Target = $Executables[0].Directory

        If ([String]::IsNullOrWhiteSpace($Target)) {Write-Log WARN "    Unable to locate TS SE Tool directory. Using '$RootName'"; Return $RootName}
        If ($Target.Name -eq $RootName)            {Write-Log INFO "    Success: '$RootName'"; Return $RootName}
        Write-Log INFO "    Success: '$($Target.FullName)'"
        Try {
            Rename-Item $Target.FullName $RootName
            Write-Log INFO "Renamed '$($Target.FullName)' to '$RootName'"
            Return $RootName
        }
        Catch {
            Write-Log WARN "Failed to rename '$($Target.FullName)' to '$RootName':`n$($_.Exception.Message)"
            Return $Target.Name
        }
    }

    Function Get-RepositoryInfo {
        [CmdletBinding()]
        [OutputType([PSCustomObject])]

        Param (
            [String]$RepoUrl = $Global:RepositoryUrl,
            [String]$Game    = $Global:GameNameShort
        )

        Try   {[PSCustomObject]$RepoData = (Get-ModRepoFile information.json -Repository $RepoUrl -UseIwr).Content | ConvertFrom-Json}
        Catch {
            Write-Log WARN "Failed to retrieve repository information:`n$($_.Exception.Message)"
            Throw "Unable to communicate with master server '$RepoUrl':`n    '$($_.Exception.Message)"
        }
        [UInt16]$Longest      = ($RepoData.PSObject.Properties.Name | Sort-Object Length)[-1].Length
        [String[]]$RepoLogMsg = ForEach ($Name in $RepoData.PSObject.Properties.Name) {$Name + (' ' * ($Longest - $Name.Length)) + ' = ' + $RepoData.$Name}

        Write-Log INFO "Retrieved repository information from '$RepoUrl':`n$($RepoLogMsg -Join "`n")"
        Return $RepoData
    }

    Function Remove-ExpiredLogs {
        [CmdletBinding()]
        [OutputType([UInt16])]

        Param ([SByte]$Days = $Global:LogRetentionDays)

        Write-Log INFO 'Received log deletion request.'

        $Days = Limit-Range $Days -1 ([SByte]::MaxValue)
        If ($Days -eq -1) {Write-Log INFO 'Log deletion is disabled'; Return 0}

        [DateTime]$Threshold      = [DateTime]::Now.AddDays($Days * -1)
        [IO.FileInfo[]]$TextFiles = Get-ChildItem "$($Global:GameModDirectory.FullName)\*.txt" -File
        [IO.FileInfo[]]$LogFiles  = ForEach ($File in $TextFiles) {
            If ([Regex]::IsMatch($File.Name, "^$Global:SessionId\.log\.txt$")) {Continue}
            If ([Regex]::IsMatch($File.Name, '^[A-F0-9]{8}\.log\.txt$'))       {If ($Days -eq 0 -Or $File.LastWriteTime -lt $Threshold) {$File}}
        }

        If ($LogFiles.Count -eq 0) {Write-Log INFO 'No old logs to delete'; Return 0}
        Else                       {Write-Log INFO "Detected $($LogFiles.Count) expired $(Switch-GrammaticalNumber 'log' $LogFiles.Count) for deletion"}

        [UInt16]$DeletionCount = 0

        ForEach ($Log in $LogFiles) {
            Try {
                [Double]$DaysPastRetention = [Math]::Round(($Threshold - $Log.LastWriteTime).TotalDays, 3)
                $Log.Delete()
                $DeletionCount++
                Write-Log INFO "Deleted log '$($Log.Name)' (Expired by $DaysPastRetention days)"
            }
            Catch {Write-Log WARN "Failed to delete log '$($Log.Name)' (Expired by $DaysPastRetention days): $($_.Exception.Message)"}
        }

        If ($DeletionCount -lt $LogFiles.Count) {Write-Log WARN "Failed to delete $($LogFiles.Count - $DeletionCount) log(s)"}

        Return $DeletionCount
    }

    Function Set-LogRetentionTime {
        # WIP
        [CmdletBinding()]
        [OutputType([SByte])]

        Param ([SByte]$Days)

        # TODO: Remove when finished
        Return $Global:LogRetentionDays

        Write-Log INFO 'Received log retention time update request.'

        $Days = Limit-Range $Days -1 ([SByte]::MaxValue)
        If ($Days -eq $Global:LogRetentionDays) {
            Write-Log INFO "Log retention time is already set to $Days days"
            Return $Global:LogRetentionDays
        }

        Write-EmbeddedValue $Global:DataIndices.LogRetentionDays.Index $Days
        Write-Log INFO "Log retention time updated from $Global:LogRetentionDays to $Days days"

        Return $Days
    }

    Function Import-DotNetTypes {
        [CmdletBinding()]
        [OutputType([Void])]

        Param (
            [Parameter(Position = 0)][Alias('Assys')][String[]]$Assemblies,
            [Parameter(Position = 1)][Alias('TypeDefs')][String[]]$TypeDefinitions
        )

        Write-Log INFO 'Received .NET type import request.'

        [String[]]$AssemblyNames = @()
        [String[]]$TypeNames     = @()

        If ($PSBoundParameters.ContainsKey('Assemblies')) {$Assemblies | ForEach-Object {$AssemblyNames += "Assembly: $_"}}
        If ($PSBoundParameters.ContainsKey('TypeDefinitions')) {
            ForEach ($TypeDef in $TypeDefinitions) {
                [Regex]::Matches($TypeDef, '(?<= )(class|enum) (\w+)(?= \{)').Value | ForEach-Object {
                    [String]$DefType, [String]$DefName = $_ -Split ' ', 2
                    $TypeNames += [String]('TypeDef: ' + $Global:CultureTextInfo.ToTitleCase($DefType) + " $DefName")
                }
            }
        }
        [UInt16]$LongestTypeName = ($AssemblyNames + $TypeNames | Sort-Object Length)[-1].Length + 4

        If ($PSBoundParameters.ContainsKey('Assemblies')) {
            ForEach ($Assembly in $Assemblies) {
                Write-Host -NoNewline (($T__Tab * 5) + "Assembly: $Assembly...".PadRight($LongestTypeName))
                Add-Type -Assembly $Assembly
                Write-Host -ForegroundColor Green 'OK'
            }
            Write-Log INFO "Imported $($AssemblyNames.Count) assemblies."
        }

        If ($PSBoundParameters.ContainsKey('TypeDefinitions')) {
            ForEach ($TypeName in $TypeNames) {
                Write-Host -NoNewline (($T__Tab * 5) + "$TypeName...".PadRight($LongestTypeName))
                Write-Host -ForegroundColor Green 'OK'
            }
            ForEach ($TypeDef in $TypeDefinitions) {Add-Type -Language CSharp -TypeDefinition $TypeDef}
            Write-Log INFO "Imported $($TypeNames.Count) type definitions."
        }
    }
    Write-Host -ForegroundColor Green "OK - $($T__StepTimer.ElapsedMilliseconds)ms`n"

    [String]$T__SimDir              = ('Euro Truck Simulator 2', 'American Truck Simulator')[$T__Game -eq 'ATS']
    [IO.FileInfo]$Global:SessionLog = [IO.Path]::Combine([Environment]::GetFolderPath('MyDocuments'), $T__SimDir, 'mod', "$Global:SessionId.log.txt")
    
    Write-Log INFO "Session started. Session ID: $Global:SessionId"
    Write-Log INFO "Environment info:`n$(($PSVersionTable.GetEnumerator() | ForEach-Object {"$($_.Key): $($_.Value)"}) -Join "`n")"
    
    Trap {Wait-WriteAndExit ("`n`n FATAL ERROR`n " + (Format-AndExportErrorData $_))}

    Initialize-Ansi

    $ErrorActionPreference = [Management.Automation.ActionPreference]::Stop
    $ProgressPreference    = [Management.Automation.ActionPreference]::SilentlyContinue

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
    [CultureInfo]$Global:CurrentCulture             = Get-EnglishCulture -Set
    [Globalization.TextInfo]$Global:CultureTextInfo = $Global:CurrentCulture.TextInfo

    $T__StepTimer.Restart()
    Write-Host "$($T__Tab * 3)Importing assemblies"
    [String[]]$T__AssemblyList = @(
        'System.Windows.Forms',
        'System.IO.Compression.FileSystem',
        'System.Data.Entity.Design',
        'System.Net.Http',
        'PresentationCore',
        'PresentationFramework'
    )
    [String]$T__TypeDef = @(
        'using System;',
        'using System.Runtime.InteropServices;',
        'public class WindowsAPI {',
        '    [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);',
        '    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);',
        '    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();',
        '    [DllImport("ntdll.dll")] public static extern uint RtlComputeCrc32(uint dwInitial, byte[] pData, int iLen);',
        '}',
        'public enum DeleteDisabledOptions {Off = 0, ManagedOnly = 1, All = 2}',
        'public enum ModUpdateState {Installing = 0, Repairing = 1, Updating = 2, Validating = 3, Reinstalling = 4}',
        'public enum ModRepairAction {None = 0, Entry = 1, File = 2}'
    ) -Join "`n"

    Import-DotNetTypes $T__AssemblyList $T__TypeDef

    Write-Host -ForegroundColor Green "$($T__Tab * 5)$($T__StepTimer.ElapsedMilliseconds)ms`n"
    $T__StepTimer.Restart()

    Write-Host "`n$($T__Tab * 3)Initializing"
    Write-Host -NoNewline "$($T__Tab * 5)Scope constraints... "

    Protect-Variables
    Write-Host -ForegroundColor Green "OK - $($T__StepTimer.ElapsedMilliseconds)ms"
    $T__StepTimer.Restart()

    Write-Host -NoNewline "$($T__Tab * 5)Global values...     "

    [IO.FileInfo]$Global:ScriptPath = $PSCommandPath
    [String]$Global:UiLine          = [Char]0x2500
    [String]$Global:UiTab           = ' ' * 4
    [UInt16]$Global:MinWndWidth     = 120
    [UInt16]$Global:MinWndHeight    = 55
    [Bool]$Global:OfflineMode       = $False
    [Bool]$Global:ClampAvailable    = 'Clamp' -In [String[]][Math].GetMethods().Name
    [Hashtable]$Global:Ri_RenGlobal = @{Force = $True; EA = 0}
    
    [Collections.Generic.List[String]]$Global:StoredData = Get-PersistentStorage

    [Hashtable]$Global:DataIndices = @{
        # ScriptVersion  = 0  <-- Script version is ALWAYS the first embedded value (hardcoded)
        ActiveProfile    = [Hashtable]@{Index = 1; Type = [String]}
        StartGame        = [Hashtable]@{Index = 2; Type = [Bool]}
        ValidateInstall  = [Hashtable]@{Index = 3; Type = [Bool]}
        DdSel            = [Hashtable]@{Index = 4; Type = [DeleteDisabledOptions]}
        NoProfileConfig  = [Hashtable]@{Index = 5; Type = [Bool]}
        LoadOrder        = [Hashtable]@{Index = 6; Type = [String]}
        StartSaveEditor  = [Hashtable]@{Index = 7; Type = [String]}
        RepositoryUrl    = [Hashtable]@{Index = 8; Type = [String]}
        OfflineData      = [Hashtable]@{Index = 9; Type = [String]}
        LogRetentionDays = [Hashtable]@{Index = 10; Type = [SByte]}
        IsExperimental   = [Hashtable]@{Index = 11; Type = [Int]}
        TargetGame       = [Hashtable]@{Index = 12; Type = [String]}
        ProfileBackups   = [Hashtable]@{Index = 13; Type = [Bool]}
        LogRetention     = [Hashtable]@{Index = 14; Type = [Bool]}
        ActiveAtsProfile = [Hashtable]@{Index = 15; Type = [String]}
        DrawFrequency    = [Hashtable]@{Index = 16; Type = [Int]}
    }
    [Hashtable]$Global:AllGameInfo = @{
        Ets2 = [Hashtable]@{
            AppId   = 227300
            Name    = 'Euro Truck Simulator 2'
            Short   = 'ETS2'
            Process = 'eurotrucks2'
        }
        Ats = [Hashtable]@{
            AppId   = 270880
            Name    = 'American Truck Simulator'
            Short   = 'ATS'
            Process = 'amtrucks'
        }
    }

    [__ComObject]$Global:wScriptShell                                                        = New-Object -Com wScript.Shell
    [Security.Cryptography.SHA1CryptoServiceProvider]$Global:CryptoProvider                  = New-Object Security.Cryptography.SHA1CryptoServiceProvider
    [Data.Entity.Design.PluralizationServices.PluralizationService]$Global:PluralizerService = [Data.Entity.Design.PluralizationServices.PluralizationService]::CreateService($Global:CurrentCulture)
    
    [Hashtable]$Global:TitleSpecifics           = $Global:AllGameInfo[$T__Game]
    [UInt32]$Global:GameAppId                   = $Global:TitleSpecifics.AppId
    [String]$Global:GameName                    = $Global:TitleSpecifics.Name
    [String]$Global:GameNameShort               = $Global:TitleSpecifics.Short
    [String]$Global:GameProcess                 = $Global:TitleSpecifics.Process
    [IO.DirectoryInfo]$Global:GameRootDirectory = [IO.Path]::Combine([Environment]::GetFolderPath('MyDocuments'), $Global:GameName)
    [IO.FileInfo]$Global:GameLogPath            = "$($Global:GameRootDirectory.FullName)\game.log.txt"
    [IO.FileInfo]$Global:GameConfigPath         = "$($Global:GameRootDirectory.FullName)\config.cfg"
    [IO.DirectoryInfo]$Global:GameModDirectory  = "$($Global:GameRootDirectory.FullName)\mod"
    
    [IO.DirectoryInfo]$Global:GameInstallDirectory, [IO.DirectoryInfo]$Global:WorkshopDirectory = Get-GameDirectory -Both
    [Void]$Global:GameInstallDirectory # TODO: Remove the voided reference when $Global:GameInstallDirectory is referenced properly
    [IO.Directory]::SetCurrentDirectory((Set-Location $Global:GameModDirectory.FullName -PassThru))

    [Bool]$Global:NoUpdate   = $False
    [Bool]$Global:UpdateAll  = $False
    [Bool]$Global:MenuToggle = $False

    Write-Host -ForegroundColor Green "OK - $($T__StepTimer.ElapsedMilliseconds)ms"
    $T__StepTimer.Restart()

    Write-Host "$($T__Tab * 5)Persistent data"
    [Hashtable]$T__PersistentData = Read-AllEmbeddedValues

    ForEach ($T__Key in $Global:DataIndices.Keys) {
        Write-Host -NoNewline "$($T__Tab * 7)$($T__Key.PadRight(20)): "
        [String]$T__Var          = "$T__Key"
        [PSVariable]$T__SetValue = Set-Variable $T__Var ($T__PersistentData.$T__Key -As $Global:DataIndices.$T__Key.Type) -Force -PassThru -Scope Global
        
        Write-Host -ForegroundColor Green (([String]$T__SetValue.Value).Substring(0, [Math]::Min(20, ([String]$T__SetValue.Value).Length)) + '[...]')
    }

    Write-EmbeddedValue $Global:DataIndices.TargetGame.Index $Global:TargetGame

    If ($Global:LogRetention) {
        Write-Host -NoNewline "$($T__Tab * 5)Purging logs...      "
        [UInt16]$T__RemovedLogs = Remove-ExpiredLogs
        Write-Host -ForegroundColor Green "OK - $($T__StepTimer.ElapsedMilliseconds)ms - $T__RemovedLogs"
        $T__StepTimer.Restart()
    }

    [UInt32]$Global:Revision          = Limit-Range $Global:IsExperimental 0 ([UInt32]::MaxValue)
    [Bool]$Global:IsExperimental      = $Global:IsExperimental -gt -1
    [Hashtable]$Global:TitleSpecifics = $Global:AllGameInfo.$Global:TargetGame
    [UInt32]$Global:GameAppId         = $Global:TitleSpecifics.AppId
    [String]$Global:GameName          = $Global:TitleSpecifics.Name
    [String]$Global:GameNameShort     = $Global:TitleSpecifics.Short
    [String]$Global:GameProcess       = $Global:TitleSpecifics.Process

    Write-Host -ForegroundColor Green "$($T__Tab * 7)$($T__StepTimer.ElapsedMilliseconds)ms"
    $T__StepTimer.Restart()

    Write-Host -NoNewline "`n$($T__Tab * 5)Console and Environment... "

    If (!(Test-PSHostCompatibility)) {Wait-WriteAndExit (" Startup aborted - Incompatible console host.`n Current host '" + $Host.Name + "' does not support required functionality.")}

    [Console]::CursorVisible     = $False
    [Console]::Title             = "TruckSim External Mod Manager v$Global:ScriptVersion"
    [UInt16]$WndX, [UInt16]$WndY = [Console]::WindowWidth, [Console]::WindowHeight
    [UInt16]$Global:WndWidth     = ($WndX, $Global:MinWndWidth)[$WndX -lt $Global:MinWndWidth]
    [UInt16]$Global:WndHeight    = ($WndY, $Global:MinWndHeight)[$WndY -lt $Global:MinWndHeight]

    [Console]::SetWindowSize($Global:WndWidth, $Global:WndHeight)
    
    If (!$Global:GameModDirectory.Exists)                    {Wait-WriteAndExit " Startup aborted - Cannot locate the $Global:GameNameShort mod directory:`n     '$($Global:GameModDirectory.FullName)' `n Verify that $Global:GameName is correctly installed and try again."}
    If ($PSScriptRoot -ne $Global:GameModDirectory.FullName) {
        If (!(Move-SelfToModDirectory)) {Wait-WriteAndExit "Startup aborted - Invalid script location.`n Unable to fix automatically.`n '$($Global:ScriptPath.FullName)' must be manually placed in '$Global:GameModDirectory' to run."}
        Else                            {Exit}
    }
    
    Write-Host -ForegroundColor Green "OK - $($T__StepTimer.ElapsedMilliseconds)ms"
    $T__StepTimer.Restart()

    Write-Host -NoNewline "$($T__Tab * 5)Repo and Game Data...      "
    If ([String]::IsNullOrWhitespace($Global:RepositoryUrl) -Or $Global:RepositoryUrl -eq 'http://your.domain/repo') {
        Write-Log WARN 'No repository URL specified.'
       
        $T__LoadTimer.Stop()

        [String]$Global:RepositoryUrl, [PSCustomObject]$Global:RepositoryInfo, [String]$T__CacheState = Set-RepositoryUrl

        If ($T__CacheState -ne 'OK') {
            Write-Log WARN "Failed to update offline repository information: $T__CacheState"
            $Global:OfflineMode = $True
            $Global:NoUpdate    = $True

            Switch ($Global:OfflineData | ConvertFrom-Json) {
                {[String]::IsNullOrWhiteSpace($_)} {
                    Write-Log ERROR 'No offline data available. Terminating session.'
                    Wait-WriteAndExit ' Unable to retrieve repository information. No offline data available.'
                }
                Default {[PSCustomObject]$Global:RepositoryInfo = $_; Break}
            }
            Write-Host -ForegroundColor Yellow ' Unable to retrieve repository information. Using cached data. Some features may be limited or unavailable.'
            [Void](Read-KeyPress)
        }
        $T__LoadTimer.Start()
    }
    Else {
        Try {
            [PSCustomObject]$Global:RepositoryInfo = Get-RepositoryInfo
            Try {
                Switch ($Global:RepositoryInfo | ConvertTo-Json -Compress) {
                    {[String]::IsNullOrWhiteSpace($_)} {Throw 'No repository data.'}
                    Default                            {[String]$Global:OfflineData = $_; Break}
                }
                Write-EmbeddedValue $Global:DataIndices.OfflineData.Index $Global:OfflineData
                Write-Log INFO "Updated offline repository information: $Global:OfflineData"
            }
            Catch {Write-Log WARN "Failed to update offline repository information:`n$($_.Exception.Message)"; Throw $_}
        }
        Catch {
            $Global:OfflineMode = $True
            $Global:NoUpdate    = $True
            Switch ($Global:OfflineData | ConvertFrom-Json) {
                {[String]::IsNullOrWhiteSpace($_)} {
                    Write-Log ERROR 'No offline data available. Terminating session.'
                    Wait-WriteAndExit ' Unable to retrieve repository information. No offline data available.'
                }
                Default {[PSCustomObject]$Global:RepositoryInfo = $_; Break}
            }
            Write-Host -ForegroundColor Yellow ' Unable to retrieve repository information. Using cached data. Some features may be limited or unavailable.'
            [Void](Read-KeyPress)
        }
    }

    [IO.FileInfo]$Global:TempProfileUnit = "$Env:Temp\profile.sii"
    [Bool]$Global:DeleteDisabled         = $Global:DdSel -ne 0
    [String[]]$Global:AllLoadOrders      = Get-LoadOrderList
    
    If ([IO.Path]::GetExtension($Global:LoadOrder) -ne '.order' -And $Global:LoadOrder -NotIn $Global:AllLoadOrders -And !$Global:OfflineMode) {
        Write-Log WARN "The active load order '$Global:LoadOrder' is not present in the repository. Applying fallback load order."
        $Global:LoadOrder = Set-ActiveLoadOrder $Global:RepositoryInfo.$Global:GameNameShort.DefaultOrder
    }

    [Bool]$Global:ScriptRestart       = ($Global:ScriptRestart, $False)[$Null -eq $Global:ScriptRestart]
    [ScriptBlock]$Global:Exec_Restart = {If ($Global:ScriptRestart -eq $True) {Unprotect-Variables; Remove-Variable ScriptRestart -Scope Global -EA 0; Return ''}}

    Write-Host -ForegroundColor Green "OK - $($T__StepTimer.ElapsedMilliseconds)ms"
    $T__StepTimer.Restart()

    Write-Host -NoNewline "$($T__Tab * 5)TS SE Tool Information...  "
    [Hashtable]$Global:TsseTool = @{
        RootDirectory = [IO.DirectoryInfo]"$($Global:GameRootDirectory.FullName)\TS SE Tool"
        Archive       = [IO.FileInfo]$Global:RepositoryInfo.Tsse
        Executable    = [IO.FileInfo]"$($Global:GameRootDirectory.FullName)\TS SE Tool\TS SE Tool.exe"
        Name          = 'TS SE Tool'
    }
    Switch (Assert-TsseNamingScheme) {
        Default {
            $Global:TsseTool['RootDirectory'] = [IO.DirectoryInfo]"$($Global:GameRootDirectory.FullName)\$_"
            $Global:TsseTool['Executable']    = [IO.FileInfo]"$($Global:GameRootDirectory.FullName)\$_\TS SE Tool.exe"
            $Global:TsseTool['Installed']     = $Global:TsseTool.Executable.Exists
        }
    }
    Write-Host -ForegroundColor Green "OK - $($T__StepTimer.ElapsedMilliseconds)ms"
    $T__StepTimer.Restart()

    Write-Host -NoNewline "$($T__Tab * 5)Script Information...      "
    [Hashtable]$Global:ScriptDetails = @{
        Author      = 'RainBawZ'
        Copyright   = [Char]0x00A9 + [DateTime]::Now.ToString('yyyy')
        Title       = ($Null, '[Experimental] ')[$Global:IsExperimental] + "TruckSim External Mod Manager"
        ShortTitle  = 'TSExtModMan'
        Version     = "Version $Global:ScriptVersion" + ($Null, " (EXPERIMENTAL - Rev. $Global:Revision)")[$Global:IsExperimental]
        VersionDate = '2026.01.12'
        GitHub      = 'https://github.com/RainBawZ/ETS2ExternalModManager/'
        Contact     = 'Discord - @realtam'
    }
    $Global:ScriptDetails['GitHubFile']  = $Global:ScriptDetails.GitHub + 'blob/main/Client/' + ($Null, 'Experimental/')[$Global:IsExperimental] + "$($Global:ScriptDetails.ShortTitle).ps1"
    [String[]]$Global:UpdateNotes = @(
        '',
        "3.7.0$(($Null, ' (EXPERIMENTAL)')[$Global:IsExperimental])",
        '',
        '- Added experimental support for American Truck Simulator (ATS).',
        '- Added secondary menu for additional options accessible by pressing Page Up [PG UP].',
        '  * Added menu option for toggling deletion of expired logs or setting log retention time.',
        '  * Added menu option for toggling automatic profile backups.',
        '  * Added menu option for changing the mod repository URL.',
        '  * Added menu option for switching target sim.',
        '  * Added menu option for adjusting the sample/refresh rate for download speed calculations.',
        '- Added internal support for experimental versions.',
        '- Added live countdown timer for keypress prompts.',
        '- Added disk space check before downloads.',
        '- Added Repository URL selection GUI.',
        '',
        '- Fixed crash upon selecting "Import load order" from the main menu.',
        '- Fixed crash on startup for users without TS SE Tool installed.',
        '- Fixed potential crashes caused by trying to generate negative padding strings.',
        '- Fixed "Launch TS SE Tool" menu option not disabling if TS SE Tool is not installed.',
        '- Fixed uncommanded menu and prompt interactions when input was provided without an active prompt.',
        '- Fixed first-time profile selection menu starting before the script had finished loading.',
        '- Fixed repository downloader not supporting HTTPS in -UseIwr mode.',
        '- Fixed TLS 1.2 not being enforced for repository communication.',
        '- Fixed text file reader not handling non-UTF8 files correctly.',
        '- Fixed text file writer in some cases writing additional null-bytes to the end of files.',
        '',
        '- Improved overall script performance.',
        '- Improved file I/O performance.',
        '- Improved keypress prompt interactivity.',
        '- Improved loading screen layout and information.',
        '- Improved log timestamp accuracy.',
        '- Improved log formatting and readability.',
        '- Improved type definition and assembly importing.',
        '',
        '- Changed script name to "TruckSim External Mod Manager" (TSExtModMan) to reflect addition of ATS support.',
        '- Changed log entry chronology. (Reversed from bottom-to-top).'
    )
    [String[]]$Global:KnownIssues = @(
        '- Keypress prompts with timeouts often not timing out.',
        '- Script restarts instead of exiting after completion if the active profile was changed earlier in the session.',
        '- Automatic moving of the script if misplaced does not work.',
        '- Option title for inactive managed mod deletion does not reflect pending actions and is misleading.'
    )

    $T__StepTimer.Stop()
    Write-Host -ForegroundColor Green "OK - $($T__StepTimer.ElapsedMilliseconds) ms"
    
    $T__LoadTimer.Stop()
    [UInt16]$T__TotalLoadTime = $T__LoadTimer.Elapsed.TotalSeconds

    Write-Host -ForegroundColor Green "`n$($T__Tab * 4)Loading complete. ($T__TotalLoadTime sec.)"
    Write-Log INFO "Loading complete. Load time: $T__TotalLoadTime sec."

    [Void](Read-KeyPress "`n$($T__Tab * 4)Continuing in <n> seconds. Press any key to skip..." -TimerAt '<n>' -Timeout 3 -Clear)

    Get-Variable "T__*" -EA 0 | Remove-Variable -Force -EA 0

    [String]$Global:ActiveProfile         = Get-ActiveProfile
    [String]$Global:ActiveProfileName     = Convert-ProfileFolderName
    [IO.DirectoryInfo]$Global:ProfilePath = "$($Global:GameRootDirectory.FullName)\profiles\$Global:ActiveProfile"
    [IO.FileInfo]$Global:ProfileUnit      = "$($Global:ProfilePath.FullName)\profile.sii"

    Update-ProtectedVars

    . $Global:Exec_Restart

    If (!$Updated) {
        [Byte]$Padding = 15

        Clear-Host
        Write-Host " Checking $($Global:ScriptDetails.ShortVersion) version...`n"
        Write-Host (' ' + 'Installed'.PadRight($Padding) + 'Current'.PadRight($Padding) + 'Status')
        Write-Host ($Global:UiLine * [Console]::BufferWidth)
        Write-Host -NoNewline (' ' + "$Global:ScriptVersion".PadRight($Padding))

        Write-Log INFO 'SelfUpdater : Checking repository for repo-script updates.'

        Try {
            If ($Global:IsExperimental) {Throw 'Aborted. Current version is experimental.'}
            Write-Log INFO 'SelfUpdater : Fetching online repo-script content from repository as ByteStream.'
            [Byte[]]$UpdateBytes = (Get-ModRepoFile $Global:RepositoryInfo.Script -UseIwr).Content
            Write-Log INFO 'SelfUpdater : Converting repo-script ByteStream content to UTF-8 line array.'
            [String[]]$UpdateContent = Get-FileContent -FromBytes $UpdateBytes

            Write-Log INFO 'SelfUpdater : Transferring embedded preference data to repo-script data indices.'
            ForEach ($Key in $Global:DataIndices.Keys) {
                [String]$Value         = Get-Variable "$Key" -ValueOnly -Scope Global
                [UInt32]$Index         = $Global:DataIndices.$Key.Index
                $UpdateContent[$Index] = New-EmbeddedValue $UpdateContent[$Index] $Value
            }
            Write-Log INFO 'SelfUpdater : Successfully transferred preference data to repo-script data indices.'

            Write-Log INFO 'SelfUpdater : Parsing repo-script version data.'
            [String]$UpdateVersion = Switch (Read-EmbeddedValue 0 $UpdateContent) {Default {('0.0.0.0', $_)[[Bool]($_ -As [Version])]}}
            If ([Version]$UpdateVersion -gt $Global:ScriptVersion) {

                Write-Log INFO "SelfUpdater : repo-script version '$UpdateVersion' - Update available."

                [ConsoleColor]$VersionColor, [String]$VersionText, [String]$ReturnValue = (([ConsoleColor]::Green, $UpdateVersion, 'Updated'), ([ConsoleColor]::Red, 'Parsing error', 'Repaired'))[$UpdateVersion -eq '0.0']

                Write-Host -NoNewline -ForegroundColor $VersionColor $VersionText.PadRight($Padding)
                
                Write-Log INFO 'SelfUpdater : Writing repo-script content to current script file.'
                Set-Utf8Content $Global:ScriptPath $UpdateContent -NoNewline

                Write-Log INFO "SelfUpdater : Restarting to apply version '$UpdateVersion'."

                Unprotect-Variables

                Return $ReturnValue
            }
            Else {
                Write-Log INFO "SelfUpdater : repo-script version '$UpdateVersion' - Up to date."
                Write-Host -NoNewline $UpdateVersion.PadRight($Padding)
                Write-Host -ForegroundColor Green 'Up to date'
            }
            Write-Host "`n"
        }
        Catch {
            If ($_.Exception.Message -Like "*is experimental*") {
                Write-Log INFO "SelfUpdater : $($_.Exception.Message)"
                Write-Host -NoNewline -ForegroundColor Yellow '---'.PadRight($Padding)
                Switch (' ' * [Console]::CursorLeft) {Default {
                    Write-Host -ForegroundColor Yellow 'Automatic updates disabled for experimental versions.'
                    Write-Host -ForegroundColor Yellow ($_ + 'Get the latest version from GitHub:')
                    Write-Host -ForegroundColor DarkCyan ($_ + $Global:ScriptDetails.GitHubFile)
                }}

                Write-Host ($Global:UiLine * [Console]::BufferWidth)

                Write-Log INFO 'SelfUpdater : Displaying experimental version information.'

                Write-Host ("`n What's new:`n   " + ($Global:UpdateNotes -Join "`n   ") + "`n")
                If ($Global:KnownIssues) {Write-Host ("`n Known issues:`n   " + ($Global:KnownIssues -Join "`n   ") + "`n")}
                [Void](Read-KeyPress ' Press any key to continue.' -Clear)
                Clear-Host
            }
            Else {
                Write-Log ERROR "SelfUpdater : $($_.Exception.Message)"
                Write-Host -ForegroundColor Red (Format-AndExportErrorData $_)
                Write-Host "`n"
                [Void](Read-KeyPress ' Press any key to continue.' -Clear)
                Clear-Host
            }
        }
    }
    ElseIf ($Updated -ne 'Restart') {
        Write-Host ($Global:UiLine * [Console]::BufferWidth)
        Write-Log INFO 'SelfUpdater : Update complete. Displaying update information.'
        Write-Host -ForegroundColor Green $Updated
        Write-Host ("`n What's new:`n   " + ($Global:UpdateNotes -Join "`n   ") + "`n")
        If ($Global:KnownIssues) {Write-Host ("`n Known issues:`n   " + ($Global:KnownIssues -Join "`n   ") + "`n")}
        [Void](Read-KeyPress ' Press any key to continue.' -Clear)
        Clear-Host
    }

    Remove-UnprotectedVars

    If ($Updated -ne 'Restart') {
        Show-LandingScreen
        Clear-HostFancy 19 0 10
    }
    Else {Remove-Variable Updated -EA 0}
    [Bool]$Save = $False
    While ($True) {If ((Invoke-Expression (Invoke-Menu -Saved:$Save)) -eq 'Menu') {Return 'Restart'}}

    Remove-Variable Save -EA 0
    Try {
        [Hashtable]$Global:LoadOrderData, [String]$Global:LoadOrderText = Get-LoadOrderData -Raw -Data
        [UInt16]$Global:ActiveModsCount  = (($Global:LoadOrderText -Split "`n", 2)[0] -Split ':', 2)[-1].Trim()
        [String[]]$Global:ActiveModFiles = $Global:LoadOrderData.GetEnumerator() | ForEach-Object {[IO.Path]::GetFileName($_.Value.SourcePath) | Where-Object {[IO.Path]::GetExtension($_) -eq '.scs'}}
        Update-ProtectedVars
        Write-Log INFO 'ModUpdateInit : Collected Load Order and active mod data. '
    }
    Catch [ApplicationException] {}

    [Byte]$ActiveDataPadding = ("Active $Global:GameNameShort profile: ", 'Active load order: ' | Sort-Object Length)[-1].Length
    [Byte]$UiLineWidth       = 100
    [String]$UiSeparator     = $Global:UiTab + $Global:UiLine * $UiLineWidth
    [String]$MenuHeadTxt     = "    $($Global:ScriptDetails.Title)   v$($Global:ScriptDetails.Version)"
    $MenuHeadTxt             = $MenuHeadTxt + (' ' * ($UiSeparator.Length - $MenuHeadTxt.Length))
    Clear-Host
    Write-Ansi " <Cyan><BBlu>$MenuHeadTxt" -Indent 1
    Write-Host ($Global:UiLine * [Console]::BufferWidth)

    If ($Global:NoUpdate) {
        Edit-ProfileLoadOrder

        Write-Host -ForegroundColor Green "`n Done`n"
        Write-Log INFO 'Session complete. Waiting for user input.'
        [Void](Read-KeyPress)
        Unprotect-Variables

        Write-Log INFO 'Exiting session.'

        Return
    }

    Write-Log INFO 'ModUpdateInit : Preparing mod update routine.'

    [PSCustomObject]$Global:OnlineData = [PSCustomObject]::New()

    [Byte]$Failures             = 0
    [Byte]$Invalids             = 0
    [Byte]$Successes            = 0
    [Byte]$LongestName          = 5
    [Byte]$TotalMods            = 0
    [Byte]$ModCounter           = 0
    [Byte]$L_LongestVersion     = 11
    [Byte]$E_LongestVersion     = 9
    [Int64]$DownloadedData      = 0
    [String[]]$NewVersions      = @()
    [String[]]$PreviousProgress = @()
    [Hashtable]$LocalMods       = @{}

    Try {
        Write-Log INFO "ModUpdateInit : Fetching version data ('$($Global:RepositoryInfo.$Global:GameNameShort.VersionData)') from repository."
        $Global:OnlineData = (Get-ModRepoFile $Global:RepositoryInfo.$Global:GameNameShort.VersionData -UseIwr).Content | ConvertFrom-Json
        Write-Log INFO 'ModUpdateInit : Version data fetched successfully.'
    }
    Catch {Wait-WriteAndExit (" Unable to fetch version data from repository. Try again later.`n Reason: " + (Format-AndExportErrorData $_))}

    If ($Global:ValidateInstall) {
        Start-Process "steam://validate/$Global:GameAppId" -
        Write-Log INFO 'ModUpdateInit : Started game file integrity check (Steam).'
        Write-Host ' Started Steam game file validation.'
        Start-Sleep 1
        Set-ForegroundWindow -Self
    }

    Update-ProtectedVars

    [String[]]$Names    = @()
    [String[]]$Versions = @('Installed')

    If ([IO.File]::Exists('versions.txt')) {
        Write-Log INFO 'ModUpdateInit : Parsing local version data from ''versions.txt'''
        [UInt64]$Line = 0
        
        ForEach ($LocalVersionData in Get-FileContent versions.txt) {
            $Line++

            [String]$Name, [Version]$Ver = ($LocalVersionData -Split '=', 3)[0..1]
            If (Test-ArrayNullOrEmpty ($Name, $Ver)) {
                Try   {Throw "versions.txt[$Line]: Invalid data"}
                Catch {[Void](Format-AndExportErrorData $_)}
                Continue
            }
            [IO.FileInfo]$FileName = "$Name.scs"
            [String]$VerStr        = $Ver.ToString()
            
            $LocalMods[$Name] = [Hashtable]@{
                FileName   = $FileName.FullName
                Version    = $Ver
                VersionStr = $VerStr
            }
            $Names    += $Name
            $Versions += "$Ver"
        }
        Write-Log INFO "ModUpdateInit : Local version data successfully parsed. Entries: $($LocalMods.Keys.Count)"
    }
    $TotalMods        = $Global:OnlineData.PSObject.Properties.Value.Count
    $LongestName      = ($Names + $Global:OnlineData.PSObject.Properties.Value.Name | Sort-Object Length)[-1].Length + 3
    $L_LongestVersion = [Math]::Max(3, ($Versions | Sort-Object Length)[-1].Length + 1)
    $E_LongestVersion = [Math]::Max('Current'.Length, ($Global:OnlineData.PSObject.Properties.Value.VersionStr | Sort-Object Length)[-1].Length + 1)
    Write-Log INFO 'ModUpdateInit : Prepared text formatting data.'

    Write-Log INFO 'ModUpdateInit : Ready.'
    If ([IO.File]::Exists('progress.tmp')) {
        $PreviousProgress = Get-FileContent progress.tmp
        Remove-Item progress.tmp -Force

        Write-Log INFO 'ModUpdate : Previous session did not complete. Resuming previous session progress.'
    }

    [String]$UIRowLine = '╟' + ($Global:UILine * 7) + '┼' + ($Global:UILine * ($LongestName + 1)) + '┼' + ($Global:UILine * ($L_LongestVersion + 1)) + '┼' + ($Global:UILine * ($E_LongestVersion + 1)) + '┼' + ($Global:UILine * 50) + '╢'
    [String]$UIRowTop  = $UIRowLine -Replace '┼', '╤' -Replace '╟', '╔' -Replace '╢', '╗' -Replace $Global:UILine, '═'
    [String]$UIRowEnd  = $UIRowLine -Replace '┼', '═' -Replace '╟', '╚' -Replace '╢', '╝' -Replace $Global:UILine, '═'
    #Write-Host "Active profile: $Global:ActiveProfileName, load order: $Global:LoadOrder".PadLeft([Console]::BufferWidth - 1) # + "`n" + $Global:ActiveProfile.PadLeft([Console]::BufferWidth - 1))
    Write-Ansi ("`n$Global:UiTab" + "Active $Global:GameNameShort profile: ".PadRight($ActiveDataPadding) + "<Green>$Global:ActiveProfileName<R>")    
    Write-Ansi ("$Global:UiTab" + 'Active load order: '.PadRight($ActiveDataPadding) + "<Green>$Global:LoadOrder<R>")
    Write-Host $UIRowTop
    Write-Host ('║ ' + 'No.'.PadRight(6) + '│ ' + 'Mod'.PadRight($LongestName) + '│ ' + 'Installed'.PadRight($L_LongestVersion) + '│ ' + 'Current'.PadRight($E_LongestVersion) + '│ ' + 'Status'.PadRight(48) + ' ║')
    Write-Host $UIRowLine

    Write-Log INFO 'ModUpdate | Starting mod update routine.'
    ForEach ($CurrentMod in $Global:OnlineData.PSObject.Properties.Value) {
        $ModCounter++
        
        $CurrentMod.Version      = [Version]$CurrentMod.Version
        [IO.FileInfo]$OldFile    = 'old_' + $CurrentMod.FileName
        [Hashtable]$LocalMod     = $LocalMods.($CurrentMod.Name)
        [ModRepairAction]$Repair = [ModRepairAction]::None # 0: None   1: Entry   2: File
        [String]$ModCountStr     = "$ModCounter".PadLeft(2) + "/$TotalMods"

        Write-Host -NoNewline ('║ ' + $ModCountStr.PadRight(6) + '│ ' + $CurrentMod.Title.PadRight($LongestName) + '│ ')

        [ModUpdateState]$Status = ([Bool]$LocalMod.Version, [IO.File]::Exists($CurrentMod.FileName) | Group-Object | Where-Object {$_.Name -eq 'True'}).Count
        Switch ($Status) {
            'Installing' {Write-Host -NoNewline '---'.PadRight($L_LongestVersion); Break}
            'Repairing'  {$Repair = ([ModRepairAction]::File, [ModRepairAction]::Entry)[![Bool]$LocalMod.Version]; Write-Host -NoNewline -ForegroundColor Red ('???', $LocalMod.VersionStr)[[Bool]$LocalMod.Version].PadRight($L_LongestVersion); Break}
            'Updating'   {Write-Host -NoNewline $LocalMod.VersionStr.PadRight($L_LongestVersion); Break}
            Default      {Write-Log WARN "'$($CurrentMod.Name)' : Unexpected ModUpdateState '$State'."; Write-Host -NoNewline '???'.PadRight($L_LongestVersion); Break}
        }
        Write-Host -NoNewline '│ '
        
        Switch ($Repair) {
            'None'  {Write-Log INFO "'$($CurrentMod.Name)' : No local problems detected."; Break}
            'Entry' {Write-Log WARN "'$($CurrentMod.Name)' : Problem detected in local version data: No corresponding version data for existing file. Entry repair required."; Break}
            'File'  {Write-Log WARN "'$($CurrentMod.Name)' : Problem detected in local mod storage: Version data references missing file. Redownload required."; Break}
            Default {Write-Log WARN "'$($CurrentMod.Name)' : Unexpected ModRepairAction '$Repair'."; Break}
        }

        [ConsoleColor]$VersionColor = ([ConsoleColor]::Green, [ConsoleColor]::White)[($LocalMod.Version -ge $CurrentMod.Version)]
        Write-Host -NoNewline -ForegroundColor $VersionColor $CurrentMod.VersionStr.PadRight($E_LongestVersion)
        Write-Host -NoNewline '│ '

        If ($CurrentMod.Name -In $PreviousProgress) {
            Write-Log INFO "'$($CurrentMod.Name)' : Skipped - Already processed."
            Write-Host -NoNewline -ForegroundColor Green 'Up to date'.PadRight(48)
            Write-Host ' ║'

            $NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='

            Continue
        }

        [UInt16]$xPos        = [Console]::CursorLeft
        [Hashtable]$WhxSplat = @{
            X       = $xPos
            Color   = [ConsoleColor]::Green
            Newline = $False
        }

        If ($LocalMod.Version -ge $CurrentMod.Version -Or $Repair -eq 'File') {

            If ($CurrentMod.FileName -NotIn $Global:ActiveModFiles -And !$Global:UpdateAll) {
                If ($Repair -eq 'File')  {Write-Log WARN "'$($CurrentMod.Name)' : Cannot perform repair - The file was skipped (not in load order)."}
                Else                     {Write-Log INFO "'$($CurrentMod.Name)' : Skipped - Not in load order."}
                Write-Host -NoNewline -ForegroundColor DarkGray 'Skipped - Not in load order'.PadRight(48)
                Write-Host ' ║'
    
                If (!$Global:DeleteDisabled) {$NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='}
    
                Continue
            }

            Write-Host -NoNewline (("$([ModUpdateState]::Validating)...", "$Status...")[$Repair -ne 'None']).PadRight(48) #[ModUpdateState]::Validating
            Write-Host -NoNewline ' ║'

            If (!(Test-FileHash $CurrentMod.FileName $CurrentMod.Hash $CurrentMod.Size)) {
                If ($Repair -eq 'None') {
                    Write-Log WARN "'$($CurrentMod.Name)' : Validation failed. Reinstalling."
                    [Console]::SetCursorPosition($xPos, [Console]::CursorTop)
                    Write-Host -NoNewline -ForegroundColor Red 'Validation failed.'.PadRight(48)
                    Write-Host -NoNewline ' ║'
                    $Status = [ModUpdateState]::Reinstalling

                    Start-Sleep 1
                }
                Try   {$LocalMod['Version'] = [Version]'0.0'}
                Catch {[Hashtable]$LocalMod = @{Version = [Version]'0.0'}}
            }
            Else {
                [String]$ResultString = ('Up to date', 'Repaired')[$Repair -ne 'None']
                Write-Log INFO "'$($CurrentMod.Name)': $ResultString"
                [Console]::SetCursorPosition($xPos, [Console]::CursorTop)
                Write-Host -NoNewline -ForegroundColor Green $ResultString.PadRight(48)
                Write-Host ' ║'

                $NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='

                If ([Bool]$Repair) {$Successes++}

                Continue
            }
        }
        If ($LocalMod.Version -lt $CurrentMod.Version -Or $Repair -eq 'Entry') {
            Try {
                [Console]::SetCursorPosition($xPos, [Console]::CursorTop)
                Write-Host -NoNewline ('Preparing...'.PadRight(48) + ' ║')
                If (!(Test-FileHash $CurrentMod.FileName $CurrentMod.Hash $CurrentMod.Size)) {

                    If ($CurrentMod.FileName -NotIn $Global:ActiveModFiles -And !$Global:UpdateAll) {
                        If ($Repair -eq 'File')  {Write-Log WARN "'$($CurrentMod.Name)' : Cannot perform repair - The file was skipped (not in load order)."}
                        Else                     {Write-Log INFO "'$($CurrentMod.Name)' : Skipped - Not in load order."}
                        [Console]::SetCursorPosition($xPos, [Console]::CursorTop)
                        Write-Host -NoNewline -ForegroundColor DarkGray 'Skipped - Not in load order'.PadRight(48)
                        Write-Host ' ║'
            
                        If (!$Global:DeleteDisabled) {$NewVersions += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='}
            
                        Continue
                    }

                    If ((Get-PSDrive ).Free -lt $CurrentMod.Size) {
                        Write-Log ERROR "'$($CurrentMod.Name)' : Insufficient disk space to perform update. Required: $([Math]::Round($CurrentMod.Size / 1MB, 2)) MB."
                        Write-Host -NoNewline -ForegroundColor Red 'Failed - Insufficient disk space.'.PadRight(48)
                        Write-Host ' ║'

                        $Failures++
                        Continue
                    }

                    If (Test-ModActive $CurrentMod.Name) {Throw [IO.IOException]::New("Close $Global:GameName to update this mod.")}

                    Write-Log INFO "'$($CurrentMod.Name)': Downloading."

                    If ([IO.File]::Exists($CurrentMod.FileName)) {
                        [UInt64]$OriginalSize = Get-ItemPropertyValue $CurrentMod.FileName Length
                        Rename-Item $CurrentMod.FileName $OldFile.Name @Ri_RenGlobal
                    }
                    Else {[UInt64]$OriginalSize = 0}

                    [String]$Result, [UInt64]$NewSize, [String]$NewHash = Get-ModRepoFile $CurrentMod.FileName $xPos $Status $CurrentMod.Hash

                    $OldFile.Refresh()
                    If ($OldFile.Exists) {$OldFile.Delete()}

                    [Console]::SetCursorPosition($xPos, [Console]::CursorTop)
                    Switch ($Status) {
                        'Installing'   {Write-Host -NoNewline -ForegroundColor Green "Installed      ($Result)".PadRight(48); Break}
                        'Repairing'    {Write-Host -NoNewline -ForegroundColor Green "Repaired       ($Result)".PadRight(48); Break}
                        'Updating'     {Write-Host -NoNewline -ForegroundColor Green "Updated        ($Result)".PadRight(48); Break}
                        'Reinstalling' {Write-Host -NoNewline -ForegroundColor Green "Reinstalled    ($Result)".PadRight(48); Break}
                        Default        {Write-Host -NoNewline -ForegroundColor Green "Unknown        ($Result)".PadRight(48); Break}
                    }
                    Write-Host ' ║'
                }
                Else {
                    If ($Repair -eq 'Entry') {Write-Log INFO "'$($CurrentMod.Name)': Entry repair successful."}
                    Write-HostX @WhxSplat 'Repaired       '.PadRight(48)
                    Write-Host ' ║'
                }

                Write-Log INFO "'$($CurrentMod.Name)': Processed successfully. $Result"
                
                Set-Utf8Content progress.tmp "$($CurrentMod.Name)" -Append

                $NewVersions    += ($CurrentMod.Name, $CurrentMod.VersionStr) -Join '='
                $DownloadedData += $NewSize - $OriginalSize
                $Successes++
            }
            Catch {
                If ($_.Exception -Is [IO.IOException]) {Write-Log WARN "'$($CurrentMod.Name)': Skipped - File in use by $Global:GameName process."}
                Else                                   {Write-Log ERROR "'$($CurrentMod.Name)': Failed - $($_.Exception.Message)"}

                Write-HostX $xPos -Color Red "Failed. See $($Global:SessionLog.Name)".PadRight(48)
                Write-Host ' ║'

                # Write-Log ERROR (Format-AndExportErrorData $_)

                $OldFile.Refresh()
                If ([IO.File]::Exists($CurrentMod.FileName)) {Remove-Item $CurrentMod.FileName @Ri_RenGlobal}
                If ($OldFile.Exists)                         {$OldFile.MoveTo($CurrentMod.FileName)}

                $NewVersions += ($CurrentMod.Name, $LocalMod.VersionStr) -Join '='
                $Failures++
            }
        }
    }
    If (!$Global:TsseTool.RootDirectory.Exists) {
        Write-Log INFO "'$($Global:TsseTool.Name)': $($Global:TsseTool.Name) not detected in '$($Global:TsseTool.RootDirectory.FullName)'. Installing."
        Write-Host -NoNewline (' ' + $Global:TsseTool.Name.PadRight($LongestName) + '---'.PadRight($L_LongestVersion))
        Write-Host -NoNewline -ForegroundColor Green '---'.PadRight($E_LongestVersion)

        [UInt16]$xPos = [Console]::CursorLeft

        Write-Host -NoNewline -ForegroundColor Green 'Installing...'
        
        [Console]::SetCursorPosition($xPos, [Console]::CursorTop)
        Try {
            Write-Log INFO "'$($Global:TsseTool.Name)': Downloading $($Global:TsseTool.Name) archive '$($Global:TsseTool.Archive.Name)'."
            [Void](Get-ModRepoFile $Global:TsseTool.Archive.Name -UseIwr -Save)
            Write-Log INFO "'$($Global:TsseTool.Name)': Downloaded archive to '$($Global:TsseTool.Archive.FullName)'."
            $Global:TsseTool.RootDirectory.Create()
            [System.IO.Compression.ZipFile]::ExtractToDirectory($Global:TsseTool.Archive.FullName, $Global:TsseTool.RootDirectory.FullName)
            Write-Log INFO "'$($Global:TsseTool.Name)': Extracted archive '$($Global:TsseTool.Archive.Name)' to directory '$($Global:TsseTool.RootDirectory.FullName)'."

            If ($Global:TsseTool.Archive.Exists) {$Global:TsseTool.Archive.Delete()}
            $Global:TsseTool['Installed'] = $True

            Write-Log INFO "'$($Global:TsseTool.Name)': Installed successfully."
            Write-Host -ForegroundColor Green 'Installed          '
        }
        Catch {
            Write-Log ERROR "'$($Global:TsseTool.Name)': Failed - $($_.Exception.Message)"
            Try {
                If ($Global:TsseTool.Archive.Exists)       {$Global:TsseTool.Archive.Delete()}
                If ($Global:TsseTool.RootDirectory.Exists) {$Global:TsseTool.RootDirectory.Delete()}
            }
            Catch {[Void](Format-AndExportErrorData $_)}
            $Failures++

            Write-Host -ForegroundColor Red 'Failed              '
        }
    }

    Write-Host ($UIRowLine -Replace '┼', '┴')
    
    Set-Utf8Content versions.txt $NewVersions -NoNewline
    Write-Log INFO 'Updated versions.txt.'

    Remove-Item progress.tmp @Ri_RenGlobal

    Write-Log INFO 'Cleared progress file.'

    If ($Global:DeleteDisabled)   {Remove-InactiveMods}
    If (!$Global:NoProfileConfig) {Edit-ProfileLoadOrder}

    Write-Log INFO 'Finishing up.'

    [String]$DownloadedStr = Switch ($DownloadedData) {
        {[Math]::Abs($_) -lt 1024}   {"$_ B"; Break}
        {[Math]::Abs($_) -lt 1024kB} {"$([Math]::Round($_ / 1kB, 1)) kB"; Break}
        {[Math]::Abs($_) -lt 1024MB} {"$([Math]::Round($_ / 1MB, 1)) MB"; Break}
        {[Math]::Abs($_) -ge 1024MB} {"$([Math]::Round($_ / 1GB, 2)) GB"; Break}
    }
    If ($DownloadedData -gt 0) {$DownloadedStr = "+$DownloadedStr"}

    [String]$TotalStr = Switch ((Get-ItemPropertyValue *.scs Length | Measure-Object -Sum).Sum) {
        {$_ -lt 1024}   {"$_ B"; Break}
        {$_ -lt 1024kB} {"$([Math]::Round($_ / 1kB, 1)) kB"; Break}
        {$_ -lt 1024MB} {"$([Math]::Round($_ / 1MB, 1)) MB"; Break}
        {$_ -ge 1024MB} {"$([Math]::Round($_ / 1GB, 2)) GB"; Break}
    }

    [ConsoleColor]$ColorA = Switch ($Null) {{$Failures -eq 0} {[ConsoleColor]::Green} {$Failures -gt 0 -And $Successes -eq 0} {[ConsoleColor]::Red} {$Failures -gt 0 -And $Successes -gt 0} {[ConsoleColor]::Yellow}}
    [ConsoleColor]$ColorB = ([ConsoleColor]::White, [ConsoleColor]::Yellow, [ConsoleColor]::Red)[[Math]::Min(2, [Math]::Ceiling($Invalids / 2))]
    [Hashtable]$TextColor = @{ForegroundColor = $ColorA}

    [String]$S_PluralMod, [String]$F_PluralMod, [String]$I_PluralMod = Switch-GrammaticalNumber 'mod' $Successes, $Failures, $Invalids

    Write-Host ('║'.PadRight($UIRowLine.Length - 1) + '║')
    If ($Successes + $Failures -eq 0) {Write-Host -NoNewline ('║'.PadRight($UIRowLine.Length - 1) + '║'); [Console]::SetCursorPosition(2, [Console]::CursorTop); Write-Host @TextColor "All mods up to date - $TotalStr"}
    If ($Successes -gt 0)             {Write-Host -NoNewline ('║'.PadRight($UIRowLine.Length - 1) + '║'); [Console]::SetCursorPosition(4, [Console]::CursorTop); Write-Host @TextColor "$Successes $S_PluralMod processed successfully - $TotalStr ($DownloadedStr)"}
    If ($Failures -gt 0)              {Write-Host -NoNewline ('║'.PadRight($UIRowLine.Length - 1) + '║'); [Console]::SetCursorPosition(4, [Console]::CursorTop); Write-Host @TextColor "$Failures $F_PluralMod failed to process"}
    If ($Invalids -gt 0)              {Write-Host -NoNewline ('║'.PadRight($UIRowLine.Length - 1) + '║'); [Console]::SetCursorPosition(4, [Console]::CursorTop); Write-Host -ForegroundColor $ColorB "$Invalids $I_PluralMod failed to validate"}
    If ($Failures + $Invalids -gt 0)  {For ([Byte]$n = 0; $n -lt 2; $n++) {Write-Host ('║'.PadRight($UIRowLine.Length - 1) + '║')}; [Console]::SetCursorPosition(2, [Console]::CursorTop - 1); Write-Host @TextColor "Exit and restart the updater to try again"}
    
    #Write-Host "`n"
    Write-Host $UIRowEnd
    Write-Log INFO 'Session completed. Waiting for user input before continuing to OnExit tasks.'

    [Void](Read-KeyPress " Press any key to$(('', " launch $Global:GameNameShort $(('', "+ $($Global:TsseTool.Name) ")[$Global:StartSaveEditor])and")[$Global:StartGame]) exit")
    If ($Successes + $Failures -eq 0 -And $Global:StartGame) {
        If ($Global:GameProcess -NotIn (Get-Process).Name) {
            Start-Process "steam://launch/$Global:GameAppId"
            Write-Log INFO "Started $Global:GameName."
        }
        If ($Global:StartSaveEditor -And $Global:TsseTool.Executable.Exists -And $Global:TsseTool.Name -NotIn (Get-Process).Name) {
            Start-Process $Global:TsseTool.Executable.FullName -WorkingDirectory $Global:TsseTool.RootDirectory.FullName
            Write-Log INFO "Started $($Global:TsseTool.Name)."
        }
    }
    Write-Log INFO 'Exiting session.'

    Unprotect-Variables
    Exit
}

#If (!$InputParam) {
    [String]$Out = $InputParam
    While ($True) {
        [String]$Out = Switch (Sync-Ets2ModRepo $Out) {
            {[String]::IsNullOrWhiteSpace($_)} {& $PSCommandPath; Break}
            {$Null -ne $_} {& $PSCommandPath "$_"; Break}
        }
    }
#}
<#Else {
    Switch (Sync-Ets2ModRepo -Updated $InputParam) {
        {[String]::IsNullOrWhiteSpace($_)}    {& $PSCommandPath; Break}
        {$Null -ne $_} {& $PSCommandPath "$_"; Break}
    }
}#>
